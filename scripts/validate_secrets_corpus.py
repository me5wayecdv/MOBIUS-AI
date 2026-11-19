#!/usr/bin/env python3
"""Bounded corpus validation of the REAL secrets worker path (CI helper).

For each source/hash-verified, authorized public training APK this script
drives the WHOLE pipeline through the real isolated worker, no host-side
parsing and no hand-built payloads:

  upload (real HTTP intake route)
  -> authorization (target_package is an OPERATOR-DECLARED CLI argument,
     the same client-supplied scope field the product takes; nothing is
     parsed from the APK on the host; the stored record's own wording is a
     validation fixture declaration, not a permission grant)
  -> scan (real HTTP route)
  -> POST /recon/jobs (real queue enqueue) -> REAL runner subprocess
     (`python -m mobius.worker.runner`, MOBIUS_WORKER_ONCE=1) executes the
     recon job INSIDE the digest-pinned recon image via the proven OCI
     backend (--network=none, --read-only, --cap-drop=ALL,
     no-new-privileges, pids/memory/cpu limits, per-job timeout)
  -> POST /recon/jobs/{id}/apply (real route) -> SURFACE_READY
  -> POST /secrets-analysis/jobs (real gated enqueue) -> REAL runner
     subprocess executes the secrets job inside the digest-pinned secrets
     image under the same OCI contract (no network)
  -> POST /secrets-analysis/jobs/{id}/apply (real route)
  -> report generate + fetch (real routes)

Artifact binding is asserted against the RUNNER-MEASURED staged_sha256
(runner.py hashes the artifact bytes it actually read), never against
client-supplied metadata.

Verification contracts (all asserted from stored/composed state, never
from report substrings or worker prose):
- Candidate-only allowlist: every applied AND stored secrets verdict must
  equal the exact serialized value "insufficient_evidence"; every finding
  status must equal "manual_review_required". Missing/None/other values
  FAIL the check (allowlist, not blacklist).
- Count consistency: stored apply accounting.transportable == payload
  candidate count; findings_created == transported - placeholder_dropped;
  stored `secrets_analysis_completed` event accounting == apply-response
  accounting (exact dict equality); stored secrets-scoped findings
  (category "hardcoded-secret") count == findings_created; stored verdicts
  count == findings_created. flow_incomplete_candidates is a REQUIRED key
  (absence is a contract violation, never defaulted to 0).
- Report composition: fixed section headers plus the EXACT composed
  transport / accounting / DEX-ledger / flow-incomplete statements rebuilt
  from the apply-response values, and the exact zero-transported
  not-a-no-secrets-result statement when transported == 0.
- Coverage class: truncated / conversion_failed>0 / dex_complete false /
  flow_incomplete>0 mark VALIDATED-WITH-INCOMPLETE-COVERAGE, never a
  generic VALIDATED.

DISCLOSURE CONTRACT (CI logs of a public repo are world-visible). Every
output path is bounded, not just the summary: stdout carries ONLY the
allowlist below; uncaught exceptions are classified by TYPE NAME ONLY (the
exception message is never printed, because messages can embed values);
subprocess stdout/stderr (alembic, the runner) is captured and withheld -
only exit codes are classified. Allowlist per APK: label, pinned sha256,
size, declared target package, per-stage seconds, methods_adapted, dex
completeness/truncation flags, accounting counts, candidates/finding
counts, HTTP status codes, report byte size, coverage class, violation
CLASSES (fixed strings), and on failure a bounded outcome class plus the
job's error_code. NEVER printed: candidate contents, manifest XML, raw
worker payloads, raw worker stdout/stderr, report bodies, exception
messages, tool stderr.

EXIT SEMANTICS (explicit): INCOMPLETE and FAILED-CONTRACT rows fail this
verification job (exit 1). INCOMPLETE is an environment/timeout bound -
NOT detector-finding absence, NOT an accuracy verdict, NOT a defect
refutation. FAILED-CONTRACT means the product diverged from the verified
contract above. VALIDATED-WITH-INCOMPLETE-COVERAGE passes with coverage
limits disclosed in-row. VALIDATED means the pipeline transported
candidate facts only; nothing here proves detection accuracy.

Timeout policy: containers are unnamed `--rm`; this script cannot provably
identify its own container for a targeted stop, so on runner timeout it
STOPS THE SEQUENCE (no next APK) and performs NO container cleanup - the
ephemeral job VM owns teardown. A hung analysis never silently passes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
IMAGE_REF = re.compile(r"^[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}$")

SECRETS_CATEGORY = "hardcoded-secret"
REQUIRED_FINDING_STATUS = "manual_review_required"
REQUIRED_VERDICT = "insufficient_evidence"
ACCOUNTING_KEYS = ("screened_total", "evidence_less", "conversion_failed",
                   "merged", "transported", "placeholder_dropped",
                   "truncated", "transport_complete")
REPORT_SECTIONS = ("## 1. Scope and authorisation",
                   "### Secrets analysis (candidate scan)",
                   "## 9. Code coverage and limitations manifest")
ZERO_TRANSPORT_STATEMENT = (
    "No secrets candidates were transported. This is **not** a no-secrets "
    "result: it says nothing about secrets outside the detector's coverage.")
STOP = "_stop_sequence"


# ---------------------------------------------------------------------------
# Assertion helpers: pure functions over response/stored data so they can be
# exercised by focused local negative checks. Each returns a list of FIXED
# violation-class strings (never data values).
# ---------------------------------------------------------------------------

def check_candidate_only(results) -> list[str]:
    """Allowlist: every applied result must carry exactly the candidate-only
    verdict and status. Missing keys, None and unknown values all fail."""
    violations = []
    if not isinstance(results, list):
        return ["results-not-a-list"]
    for idx, res in enumerate(results):
        if not isinstance(res, dict):
            violations.append("result-not-an-object")
            continue
        if "finding_status" not in res:
            violations.append("finding-status-missing")
        elif res["finding_status"] != REQUIRED_FINDING_STATUS:
            violations.append("finding-status-not-manual-review")
        if "verdict" not in res:
            violations.append("verdict-missing")
        elif res["verdict"] != REQUIRED_VERDICT:
            violations.append("verdict-not-insufficient-evidence")
        if not res.get("finding_id"):
            violations.append("finding-id-missing")
    return violations


def check_count_consistency(candidates_len: int, applied: dict) -> list[str]:
    """Apply-response accounting vs payload candidates and findings created.
    Required keys are required: absence is a violation, never a default."""
    violations = []
    acc = applied.get("accounting")
    if not isinstance(acc, dict):
        return ["accounting-missing"]
    for key in ACCOUNTING_KEYS:
        if key not in acc:
            violations.append(f"accounting-key-missing:{key}")
    if "flow_incomplete_candidates" not in applied:
        violations.append("flow-incomplete-key-missing")
    if violations:
        return violations
    results = applied.get("results")
    if not isinstance(results, list):
        return violations + ["results-not-a-list"]
    if acc["transported"] != candidates_len:
        violations.append("transported-ne-payload-candidates")
    if len(results) != acc["transported"] - acc["placeholder_dropped"]:
        violations.append("findings-ne-transported-minus-placeholder-dropped")
    if not isinstance(applied["flow_incomplete_candidates"], int):
        violations.append("flow-incomplete-not-int")
    return violations


def check_stored_secrets_findings(findings: list, expected_count: int) -> list[str]:
    """Secrets-scoped stored findings: filter by category, then count and
    status must match exactly."""
    violations = []
    scoped = [f for f in findings
              if isinstance(f, dict) and f.get("category") == SECRETS_CATEGORY]
    if len(scoped) != expected_count:
        violations.append("stored-secrets-findings-count-mismatch")
    for item in scoped:
        if item.get("status") != REQUIRED_FINDING_STATUS:
            violations.append("stored-finding-status-not-manual-review")
    return violations


def check_stored_verdicts(verdicts: list, expected_count: int) -> list[str]:
    """Stored verdict rows for the scan's secrets findings: exact allowlist
    value and count."""
    violations = []
    if len(verdicts) != expected_count:
        violations.append("stored-verdicts-count-mismatch")
    for value in verdicts:
        if value != REQUIRED_VERDICT:
            violations.append("stored-verdict-not-insufficient-evidence")
    return violations


def expected_transport_line(acc: dict) -> str:
    if acc.get("truncated"):
        return ("- **Transport:** TRUNCATED by the worker: unreported "
                "candidates may exist; this is not a no-evidence result")
    if acc.get("conversion_failed"):
        return (f"- **Transport:** INCOMPLETE: {acc['conversion_failed']} "
                "candidate(s) with detector evidence could not be converted; "
                "this is not a complete scan")
    return "- **Transport:** complete (payload transport only - see below)"


def expected_accounting_line(acc: dict) -> str:
    return ("- **Accounting:** "
            f"screened {acc['screened_total']} · "
            f"evidence-less {acc['evidence_less']} · "
            f"conversion-failed {acc['conversion_failed']} · "
            f"merged {acc['merged']} · "
            f"transported {acc['transported']} · "
            f"placeholder-dropped {acc['placeholder_dropped']}")


def check_report(report_text: str, acc: dict, flow_incomplete: int,
                 dex_complete: bool) -> list[str]:
    """Fixed sections plus the EXACT composed statements, rebuilt from the
    apply-response accounting (not from the report itself)."""
    violations = []
    for section in REPORT_SECTIONS:
        if section not in report_text:
            violations.append(f"report-section-missing:{section[:24]}")
    if expected_transport_line(acc) not in report_text:
        violations.append("report-transport-statement-mismatch")
    if expected_accounting_line(acc) not in report_text:
        violations.append("report-accounting-statement-mismatch")
    dex_line = ("- **DEX ledger (worker-asserted):** complete (consistent ledger)"
                if dex_complete else
                "- **DEX ledger (worker-asserted):** INCOMPLETE or ambiguous")
    if dex_line not in report_text:
        violations.append("report-dex-statement-mismatch")
    flow_line = (f"- **Flow-incomplete candidates:** {flow_incomplete} "
                 "(absence of evidence not established)")
    if flow_line not in report_text:
        violations.append("report-flow-statement-mismatch")
    if acc.get("transported") == 0 and ZERO_TRANSPORT_STATEMENT not in report_text:
        violations.append("report-zero-transport-statement-missing")
    return violations


# ---------------------------------------------------------------------------

def fail(msg: str) -> None:
    """Hard stop for pre-flight and integrity violations.

    Every call site passes a structural message only (statuses, digests,
    ref shapes, counts, fixed class strings) - never exception text or
    tool output."""
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def run_runner(db_url: str, artifact_root: Path, workspace_root: Path,
               recon_image: str, secrets_image: str, runtime_path: str,
               wall_s: int) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update({
        "MOBIUS_WORKER_DB_URL": db_url,
        "MOBIUS_ARTIFACT_ROOT": str(artifact_root),
        "MOBIUS_WORKSPACE_ROOT": str(workspace_root),
        "MOBIUS_OCI_RUNTIME": runtime_path,
        "MOBIUS_RECON_IMAGE": recon_image,
        "MOBIUS_SECRETS_IMAGE": secrets_image,
        "MOBIUS_WORKER_ONCE": "1",
    })
    # capture_output: worker stdout/stderr NEVER reaches public logs.
    return subprocess.run(
        [sys.executable, "-m", "mobius.worker.runner"],
        env=env, cwd=REPO, capture_output=True, timeout=wall_s)


def sql_rows(db_url: str, statement: str, params: dict) -> list[dict]:
    from sqlalchemy import text
    from mobius.adapters.db import make_engine
    engine = make_engine(db_url)
    with engine.connect() as conn:
        rows = conn.execute(text(statement), params).mappings().all()
    engine.dispose()
    return [dict(r) for r in rows]


def job_state(db_url: str, job_id: str):
    rows = sql_rows(db_url,
                    "SELECT status, result_json, error_code, staged_sha256 "
                    "FROM worker_jobs WHERE id = :i", {"i": job_id})
    return rows[0] if rows else None


def stored_secrets_event_accounting(db_url: str, scan_id: str):
    rows = sql_rows(db_url,
                    "SELECT payload FROM events WHERE investigation_id = :s "
                    "AND type = 'secrets_analysis_completed' "
                    "ORDER BY seq DESC LIMIT 1", {"s": scan_id})
    if not rows:
        return None
    payload = rows[0]["payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return (payload or {}).get("accounting")


def stored_secrets_verdicts(db_url: str, scan_id: str) -> list[str]:
    rows = sql_rows(db_url,
                    "SELECT v.verdict FROM verdicts v "
                    "JOIN findings f ON v.finding_id = f.id "
                    "WHERE f.investigation_id = :s AND f.category = :c",
                    {"s": scan_id, "c": SECRETS_CATEGORY})
    return [r["verdict"] for r in rows]


def require_succeeded(db_url: str, job_id: str, sha: str, label: str,
                      stage: str, row: dict) -> dict | None:
    """Returns result_json on success; on deviation records INCOMPLETE."""
    state = job_state(db_url, job_id)
    if not state or state["status"] != "succeeded":
        row["outcome"] = f"INCOMPLETE: {stage} job not succeeded"
        row["error_code"] = (state or {}).get("error_code")
        return None
    if state["staged_sha256"] != sha:
        # The runner hashes the bytes IT read; a mismatch is a hard stop.
        fail(f"{label}: runner-measured staged_sha256 does not match the "
             f"pinned APK digest at stage {stage}")
    result_json = state["result_json"]
    if isinstance(result_json, str):
        result_json = json.loads(result_json)
    return result_json


def run_one(args, runtime_path: str, label: str, path: Path,
            package: str, apk: bytes, sha: str) -> dict:
    """Drive one APK through the whole containerized path. Returns the
    allowlisted summary row. Raises only through fail() (structural)."""
    row: dict = {"label": label, "sha256": sha, "size": len(apk),
                 "declared_package": package}
    with tempfile.TemporaryDirectory(prefix="mobius-corpus-") as tmp:
        tmp_path = Path(tmp)
        artifact_root = tmp_path / "artifacts"
        workspace_root = tmp_path / "work"
        db_url = f"sqlite+pysqlite:///{tmp_path}/corpus.db"
        env = dict(os.environ, MOBIUS_DB_URL=db_url)
        mig = subprocess.run(["alembic", "upgrade", "head"], cwd=REPO,
                             env=env, capture_output=True, timeout=120)
        if mig.returncode != 0:
            # stderr withheld: migration errors can echo values.
            row["outcome"] = (f"INCOMPLETE: alembic upgrade head exited "
                              f"{mig.returncode} (stderr withheld)")
            return row

        from fastapi.testclient import TestClient
        from mobius.api.app import create_app
        from mobius.api.config import Settings
        from mobius.api.deps import AppContext, set_context

        settings = Settings(db_url=db_url, artifact_root=artifact_root,
                            env="test", secrets_enqueue_enabled=True)
        context = AppContext(settings)
        set_context(context)
        try:
            client = TestClient(create_app())
            r = client.post("/api/v1/applications",
                            files={"file": (path.name, apk,
                                            "application/vnd.android.package-archive")})
            if r.status_code not in (200, 201):
                row["outcome"] = f"INCOMPLETE: intake upload status {r.status_code}"
                return row
            app = r.json()
            if app["sha256"] != sha:
                fail(f"{label}: intake digest mismatch")
            auth = client.post("/api/v1/authorizations", json={
                "apk_sha256": sha, "target_package": package,
                "scope_text": "Static analysis of the supplied public training "
                              "APK only; no execution. Validation fixture "
                              "declaration, not a permission grant.",
                "statement": "Validation fixture declaration, not a permission grant.",
                "max_intensity": 0,
                "expires_at": "2030-01-01T00:00:00Z"})
            if auth.status_code not in (200, 201):
                row["outcome"] = f"INCOMPLETE: authorization status {auth.status_code}"
                return row
            scan = client.post("/api/v1/scans", json={
                "application_id": app["id"],
                "authorization_id": auth.json()["id"],
                "objective": f"bounded corpus validation: {label}",
                "intensity": 0})
            if scan.status_code not in (200, 201):
                row["outcome"] = f"INCOMPLETE: scan create status {scan.status_code}"
                return row
            scan_id = scan.json()["id"]

            # Stage 1: containerized recon through the real queue/runner.
            q = client.post(f"/api/v1/scans/{scan_id}/recon/jobs")
            if q.status_code != 202:
                row["outcome"] = f"INCOMPLETE: recon enqueue status {q.status_code}"
                return row
            recon_job = q.json()["job_id"]
            t0 = time.time()
            try:
                proc = run_runner(db_url, artifact_root, workspace_root,
                                  args.recon_image, args.secrets_image,
                                  runtime_path, args.recon_wall_seconds)
            except subprocess.TimeoutExpired:
                # No provably-owned container to stop: terminate the
                # sequence, no cleanup, no next APK (see module docstring).
                row["outcome"] = ("INCOMPLETE: recon runner wall budget exceeded; "
                                  "sequence stopped, no container cleanup")
                row[STOP] = True
                return row
            row["recon_seconds"] = round(time.time() - t0, 1)
            if proc.returncode != 0:
                row["outcome"] = f"INCOMPLETE: recon runner exited {proc.returncode}"
                return row
            if require_succeeded(db_url, recon_job, sha, label, "recon", row) is None:
                return row
            a = client.post(f"/api/v1/scans/{scan_id}/recon/jobs/{recon_job}/apply")
            row["recon_apply"] = a.status_code
            if a.status_code != 200:
                row["outcome"] = f"INCOMPLETE: recon apply status {a.status_code}"
                return row
            state_after = client.get(f"/api/v1/scans/{scan_id}").json().get("state")
            row["state_after_recon"] = state_after
            if state_after != "SURFACE_READY":
                row["outcome"] = f"INCOMPLETE: state after recon apply is {state_after}"
                return row

            # Stage 2: containerized secrets analysis through the real path.
            q = client.post(f"/api/v1/scans/{scan_id}/secrets-analysis/jobs")
            if q.status_code != 202:
                row["outcome"] = f"INCOMPLETE: secrets enqueue status {q.status_code}"
                return row
            secrets_job = q.json()["job_id"]
            t0 = time.time()
            try:
                proc = run_runner(db_url, artifact_root, workspace_root,
                                  args.recon_image, args.secrets_image,
                                  runtime_path, args.secrets_wall_seconds)
            except subprocess.TimeoutExpired:
                row["outcome"] = ("INCOMPLETE: secrets runner wall budget exceeded; "
                                  "sequence stopped, no container cleanup")
                row[STOP] = True
                return row
            row["analysis_seconds"] = round(time.time() - t0, 1)
            if proc.returncode != 0:
                row["outcome"] = f"INCOMPLETE: secrets runner exited {proc.returncode}"
                return row
            result_json = require_succeeded(db_url, secrets_job, sha, label,
                                            "secrets", row)
            if result_json is None:
                return row
            row["methods_adapted"] = result_json.get("methods_adapted")
            for key in ("screened_total", "evidence_less", "conversion_failed",
                        "merged", "truncated"):
                if key in result_json:
                    row[key] = result_json[key]
            candidates = len(result_json.get("candidates", []))
            row["candidates_transported"] = candidates

            a = client.post(
                f"/api/v1/scans/{scan_id}/secrets-analysis/jobs/{secrets_job}/apply")
            row["apply_status"] = a.status_code
            if a.status_code != 200:
                row["outcome"] = f"INCOMPLETE: secrets apply status {a.status_code}"
                return row
            applied = a.json()
            results = applied.get("results", [])
            acc = applied.get("accounting") or {}
            row["findings_created"] = len(results)
            row["placeholder_screened"] = acc.get("placeholder_dropped")

            violations: list[str] = []
            violations += check_candidate_only(results)
            violations += check_count_consistency(candidates, applied)
            # dex_complete is RECOMPUTED API-side from the ledger
            # (adapters/secrets_payload.py); the payload value is only the
            # worker's claim. Display and report checks use the API value;
            # disagreement is a contract violation.
            if "dex_complete" not in applied:
                violations.append("apply-dex-complete-missing")
            else:
                row["dex_complete"] = applied["dex_complete"]
                if result_json.get("dex_complete") is not None and \
                        bool(result_json.get("dex_complete")) != bool(applied["dex_complete"]):
                    violations.append("worker-dex-claim-ne-api-recompute")

            findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()["items"]
            row["findings_total"] = len(findings)
            violations += check_stored_secrets_findings(findings, len(results))
            violations += check_stored_verdicts(
                stored_secrets_verdicts(db_url, scan_id), len(results))

            stored_acc = stored_secrets_event_accounting(db_url, scan_id)
            if stored_acc is None:
                violations.append("stored-secrets-event-missing")
            elif stored_acc != acc:
                violations.append("stored-accounting-ne-apply-accounting")

            rep = client.post(f"/api/v1/scans/{scan_id}/report")
            row["report_post"] = rep.status_code
            if rep.status_code != 200:
                row["outcome"] = f"INCOMPLETE: report generate status {rep.status_code}"
                return row
            report_text = client.get(f"/api/v1/scans/{scan_id}/report").text
            row["report_bytes"] = len(report_text)
            if isinstance(acc, dict) and all(k in acc for k in ACCOUNTING_KEYS) \
                    and "flow_incomplete_candidates" in applied \
                    and "dex_complete" in applied:
                violations += check_report(
                    report_text, acc, applied["flow_incomplete_candidates"],
                    bool(applied["dex_complete"]))
            else:
                violations.append("report-check-skipped-accounting-incomplete")

            if violations:
                # Fixed class strings only; no values. Product divergence,
                # not an environment bound.
                row["violations"] = sorted(set(violations))
                row["outcome"] = f"FAILED-CONTRACT: {len(set(violations))} assertion class(es) violated"
                return row

            # Reached only when no violations: every accounting key and
            # flow_incomplete_candidates was verified present. Strict key
            # access, no fallbacks.
            coverage_flags = []
            if acc["truncated"]:
                coverage_flags.append("transport_truncated")
            if acc["conversion_failed"]:
                coverage_flags.append("conversion_failed>0")
            if not applied["dex_complete"]:
                coverage_flags.append("dex_incomplete")
            flow_incomplete = applied["flow_incomplete_candidates"]
            if flow_incomplete:
                coverage_flags.append(f"flow_incomplete={flow_incomplete}")
            if not acc["transport_complete"]:
                coverage_flags.append("transport_incomplete")
            if coverage_flags:
                row["coverage"] = "INCOMPLETE: " + ",".join(coverage_flags)
                row["outcome"] = ("VALIDATED-WITH-INCOMPLETE-COVERAGE "
                                  "(pipeline only; candidate facts, no verdict)")
            else:
                row["coverage"] = "complete-as-reported"
                row["outcome"] = "VALIDATED (pipeline only; candidate facts, no verdict)"
            return row
        finally:
            set_context(None)
            context.engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recon-image", required=True,
                        help="loopback-registry name@sha256:<digest> recon ref")
    parser.add_argument("--secrets-image", required=True,
                        help="loopback-registry name@sha256:<digest> secrets ref")
    parser.add_argument("--apk", action="append", required=True,
                        metavar="LABEL=PATH=PACKAGE",
                        help="source/hash-verified public training APK; PACKAGE is "
                             "the operator-declared authorization scope; repeatable")
    parser.add_argument("--recon-wall-seconds", type=int, default=300)
    parser.add_argument("--secrets-wall-seconds", type=int, default=1080,
                        help="wall budget for one secrets runner invocation "
                             "(job limit + margin)")
    args = parser.parse_args()

    for ref_name, ref in (("recon", args.recon_image), ("secrets", args.secrets_image)):
        if not re.fullmatch(IMAGE_REF, ref):
            fail(f"{ref_name} image ref must be digest-pinned (name@sha256:<64 hex>)")
    runtime_path = shutil.which("docker")
    if not runtime_path or not Path(runtime_path).is_absolute() or not Path(runtime_path).is_file():
        fail("docker CLI not found at an absolute path; corpus validation cannot run "
             "(no skip path)")

    print("scope: candidate-only phase-1 transport; no verdicts; no accuracy claim")
    # Runtime limits are DERIVED from the runner's ToolSpec (source of
    # truth), never hardcoded here.
    os.environ.setdefault("MOBIUS_RECON_IMAGE", args.recon_image)
    os.environ.setdefault("MOBIUS_SECRETS_IMAGE", args.secrets_image)
    from mobius.worker.runner import _tool_for
    for kind in ("recon_manifest", "secrets_analysis"):
        _, _, spec = _tool_for(kind, runtime_path)
        lim = spec.limits
        print(f"derived limits[{kind}]: timeout={lim.timeout_seconds}s "
              f"memory={lim.memory_mb}MB (ENFORCED, not measured-peak) "
              f"cpu={lim.cpu_seconds}s max_output={lim.max_output_bytes}B "
              f"network_enabled={lim.network_enabled}")
    outcomes: list[bool] = []
    for spec in args.apk:
        label, _, rest = spec.partition("=")
        apk_path, _, package = rest.partition("=")
        path = Path(apk_path)
        if not label or not path.is_file() or not package:
            fail(f"bad --apk spec (want LABEL=PATH=PACKAGE): {spec}")
        apk = path.read_bytes()
        sha = hashlib.sha256(apk).hexdigest()
        try:
            row = run_one(args, runtime_path, label, path, package, apk, sha)
        except Exception as exc:
            # Exception MESSAGES can embed values: classify by type name only.
            row = {"label": label, "sha256": sha, "size": len(apk),
                   "declared_package": package,
                   "outcome": f"INCOMPLETE: unexpected {type(exc).__name__} "
                              f"(detail withheld from public logs)"}
        stop = bool(row.pop(STOP, False))
        print("CORPUS " + json.dumps(row, sort_keys=True))
        outcomes.append(row.get("outcome", "").startswith("VALIDATED"))
        if stop:
            print("sequence stopped after runner timeout: no further APKs, "
                  "no container cleanup (unnamed --rm; VM teardown owns them)")
            break

    print("exit semantics: INCOMPLETE and FAILED-CONTRACT rows fail this "
          "verification job; INCOMPLETE is an environment/timeout bound, "
          "NOT detector finding absence and NOT an accuracy verdict")
    print("reminder: candidate-only; every finding is MANUAL_REVIEW_REQUIRED")
    return 0 if all(outcomes) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:
        # Last-resort containment: type name only, never the message.
        print(f"FAIL: unexpected {type(exc).__name__} "
              f"(detail withheld from public logs)", file=sys.stderr)
        sys.exit(1)
