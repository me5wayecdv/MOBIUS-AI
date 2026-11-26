#!/usr/bin/env python3
"""Connected journey smoke (verification-gap closure):

  upload -> authorization -> scan -> RECON -> model consent -> REAL model
  hypothesis (free OpenCode route, consent-gated) -> PoC plan referencing the
  REAL persisted hypothesis id (no seeding) -> approvals API -> emulator
  Frida execution -> persisted evidence -> ARCHIVIST report -> read-back.

This attempts a connection between separately verified slices; a pass is instrumentation
plumbing only, not security validation of the model hypothesis. It does not close
the full agent acceptance gap. Historical slices: the model-backed
hypothesis path (REAL_TARGET_VERIFICATION.md) and the dynamic-evidence
journeys that seed a hypothesis (phantom-frida-smoke). Nothing is seeded
here; the plan references the hypothesis the model actually produced.

Honesty rules:
- The per-investigation model consent granted here is a synthetic CI test
  consent inside a throwaway investigation (the upstream-data route itself
  requires separate user-channel authority for each permitted scope). It is labelled as such.
- The plan approval is a synthetic CI test approval through the product
  approvals API - not a real user-approved plan.
- The model leg is not tuned toward any outcome: an invalid, refusing, or
  empty model result fails the model check honestly; the driver never
  retries to force a pass and never edits model output.
- Stdlib only (urllib); the repo gains no dependencies.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
import urllib.error
import uuid

BASE = os.environ.get("MOBIUS_SMOKE_API", "http://127.0.0.1:8791")
APK_PATH = os.environ.get("MOBIUS_SMOKE_APK", "allsafe.apk")
PKG = "infosecadventures.allsafe"
SHA256 = "d6792d6634a033f048f935f1269179d3c27b859c4c34b1e9e5b008a88375efd9"

failures: list[str] = []
CALL_DEADLINE: float | None = None


def check(name: str, ok: bool, detail: str = "") -> None:
    print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""))
    if not ok:
        failures.append(name)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url,code,'redirect refused',headers,fp)


def call(method: str, path: str, body=None, raw=None, headers=None):
    url = BASE + "/api/v1" + path
    data = raw
    hdrs = {"X-Analyst-Id": "ci-connected-journey"}
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    remaining = 300 if CALL_DEADLINE is None else min(10, CALL_DEADLINE-time.monotonic())
    if remaining <= 0: raise TimeoutError('preparation HTTP deadline')
    with urllib.request.build_opener(NoRedirect()).open(req, timeout=remaining) as resp:
        if not 200 <= resp.status < 300:
            raise urllib.error.HTTPError(url,resp.status,"non-success API response",resp.headers,None)
        chunks = []; size = 0
        while True:
            if CALL_DEADLINE is not None:
                left = CALL_DEADLINE-time.monotonic()
                if left <= 0: raise TimeoutError('preparation HTTP body deadline')
                # HTTPResponse.read1 performs at most one underlying read. Reset the
                # socket timeout to the remaining absolute budget before each read.
                resp.fp.raw._sock.settimeout(min(10,left))
            chunk = resp.read1(65536)
            if not chunk: break
            size += len(chunk)
            if size > 2*1024*1024: raise ValueError('API response body over limit')
            chunks.append(chunk)
        payload = b''.join(chunks)
        ctype = resp.headers.get("Content-Type", "")
    if "application/json" in ctype:
        return json.loads(payload)
    return payload


def multipart_upload(path: str, file_path: str):
    boundary = "----mobiusci" + uuid.uuid4().hex
    filename = os.path.basename(file_path)
    with open(file_path, "rb") as fh:
        content = fh.read()
    body = b"\r\n".join([
        f"--{boundary}".encode(),
        f'Content-Disposition: form-data; name="file"; filename="{filename}"'.encode(),
        b"Content-Type: application/vnd.android.package-archive",
        b"",
        content,
        f"--{boundary}--".encode(),
        b"",
    ])
    return call("POST", path, raw=body,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})


def prepare_static_evidence(scan_id: str, *, request=call, clock=time.monotonic, sleep=time.sleep,
                            timeout_seconds: float = 180) -> dict:
    """Use configured isolated workers, not an inline parsing bypass or seeded evidence.

    A missing worker/image, failed job, timeout or manifest-only package stops before any
    model request. Runtime/code evidence must be real persisted product output. The
    finite call timeout is also clamped to the shared preparation deadline by call().
    """
    global CALL_DEADLINE
    old_deadline = CALL_DEADLINE
    deadline = clock() + timeout_seconds
    CALL_DEADLINE = time.monotonic() + timeout_seconds
    try:
        for kind in ('provider-analysis', 'spectre'):
            if clock() >= deadline: raise TimeoutError('static evidence preparation deadline')
            stem = f'/scans/{scan_id}/{kind}/jobs'
            queued = request('POST', stem)
            job_id = queued.get('job_id')
            try:
                if not isinstance(job_id, str) or str(uuid.UUID(job_id)) != job_id: raise ValueError
            except (ValueError, AttributeError):
                raise ValueError('static worker did not return a canonical job identity')
            while True:
                if clock() >= deadline: raise TimeoutError('static evidence preparation deadline')
                status = request('GET', stem+'/'+job_id).get('status')
                if status == 'succeeded': break
                if status not in ('queued', 'running'):
                    raise ValueError('static worker failed or returned an unknown state')
                sleep(min(.5, max(0, deadline-clock())))
            request('POST', stem+'/'+job_id+'/apply')
        package = request('GET', f'/scans/{scan_id}/evidence-package')
        # Paths/sinks justify investigation, NOT exploitability. Their absence is not
        # repaired by telling the model a vulnerability must exist.
        if not package.get('observations') or not package.get('evidence'):
            raise ValueError('no persisted static observations/evidence')
        if not any(package.get(k) for k in ('method_references','sink_references','source_snippets')):
            raise ValueError('manifest-only package: no code evidence for model investigation')
        return package
    finally:
        CALL_DEADLINE = old_deadline


def main() -> int:
    app = multipart_upload("/applications", APK_PATH)
    check("application-uploaded", app.get("sha256") == SHA256, app.get("id", ""))

    auth = call("POST", "/authorizations", {
        "apk_sha256": SHA256,
        "target_package": PKG,
        "scope_text": ("CI connected journey: static intake, one consent-gated free-route "
                       "model hypothesis, then bounded observation-only Frida "
                       "instrumentation on the pinned public Allsafe lab build inside an "
                       "ephemeral emulator. Intensity 2 fixture scope."),
        "statement": "Public intentionally-vulnerable training app used as a CI lab target.",
        "max_intensity": 2,
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600)),
    })
    check("authorization-created", bool(auth.get("id")), auth.get("id", ""))

    scan = call("POST", "/scans", {
        "application_id": app["id"],
        "authorization_id": auth["id"],
        "objective": "CI connected journey: real model hypothesis -> approved bounded PoC -> report.",
        "intensity": 2,
    })
    scan_id = scan.get("id")
    check("scan-created", bool(scan_id), str(scan_id))

    call("POST", f"/scans/{scan_id}/recon")
    detail = call("GET", f"/scans/{scan_id}")
    package = (detail.get("application") or {}).get("package_name")
    check("package-parsed-by-recon", package == PKG, str(package))

    try:
        prepare_static_evidence(scan_id)
    except (ValueError, TimeoutError, OSError) as exc:
        # No raw provider response, APK strings or arbitrary exception text in logs.
        check('static-evidence-ready', False, type(exc).__name__)
        print('SUMMARY failures=' + str(len(failures)))
        return 1
    check('static-evidence-ready', True)

    # Synthetic CI test consent inside this throwaway investigation; the
    # upstream route requires separately grounded authority. Distinct
    # from both the owner's real consent and any real user-approved plan.
    consent = call("PUT", f"/scans/{scan_id}/model-consent", {
        "enabled": True, "provider": "opencode", "auto_veritas": False,
    })
    sharing = consent.get("llm_data_sharing") or {}
    check("model-consent-recorded",
          sharing.get("enabled") is True and sharing.get("provider") == "opencode",
          json.dumps(sharing))

    reply = call("POST", f"/scans/{scan_id}/nexus/hypotheses")
    check("hypotheses-model-mode", reply.get("mode") == "model_gateway",
          f"mode={reply.get('mode')} provider={reply.get('provider')}")
    hyps = reply.get("hypotheses") or []
    check("hypothesis-persisted-by-model", len(hyps) >= 1, f"count={len(hyps)}")
    if not hyps or reply.get("mode") != "model_gateway":
        # Honest stop: without a real model hypothesis there is nothing to
        # connect; do not seed or retry into a pass.
        print("SUMMARY failures=" + str(len(failures)))
        return 1
    hyp_id = hyps[0]["id"]
    # This fixed enumeration plan is an instrumentation transport check only. It
    # does not test the security claim in an arbitrary model-produced hypothesis.
    check('instrumentation-only-not-hypothesis-validation', True)
    prov = reply.get("provenance") or {}
    check("hypothesis-provenance-recorded",
          bool(prov.get("provider")) and bool(prov.get("response_sha256")),
          f"provider={prov.get('provider')} model={reply.get('model_id')}")

    plan = {
        "id": "poc_" + uuid.uuid4().hex.upper()[:26],
        "investigation_id": scan_id,
        "authorization_id": auth["id"],
        "target_sha256": SHA256,
        "target_package": PKG,
        "target_kind": "emulator",
        "hypothesis_ids": [hyp_id],
        "steps": [
            {"action": "assert_emulator_frida_classes", "target_ref": PKG,
             "expected_value": 100},
        ],
        "expected_outcome": ("Observation-only Frida attach enumerates at least 100 loaded "
                             "classes in the lab app process. Instrumentation transport only, "
                             "NOT validation of the model security hypothesis."),
        "safety_class": "non_destructive",
        "requires_approval": True,
        "cleanup_steps": [
            {"action": "stop_emulator_instrumentation", "target_ref": "frida-server"},
        ],
        "max_duration_seconds": 240,
        "max_output_bytes": 8192,
    }

    # Synthetic CI test approval through the product approvals API (the CI
    # job is both requester and approver inside this throwaway
    # investigation). Not a real user-approved plan.
    approval = call("POST", f"/scans/{scan_id}/poc/approvals", {
        "plan": plan,
        "justification": ("CI fixture: verify the connected journey executes the approved "
                          "bounded instrumentation against a real model hypothesis."),
        "risk_summary": ("Ephemeral emulator, public training app, observation-only script, "
                         "instrumentation stopped by cleanup; no external target."),
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 1800)),
    })
    approval_id = approval.get("id")
    check("approval-requested", approval.get("state") == "pending", str(approval.get("state")))

    decision = call("POST", f"/scans/{scan_id}/poc/approvals/{approval_id}/resolve", {
        "decision": "granted",
        "note": "CI fixture approval for the connected journey smoke.",
    })
    check("approval-granted", decision.get("state") == "granted", str(decision.get("state")))

    plan["approval_id"] = approval_id
    result = call("POST", f"/scans/{scan_id}/poc/execute", plan)
    check("poc-execution-passed", result.get("status") == "passed",
          f"status={result.get('status')}")
    output = result.get("output") or {}
    steps = output.get("steps") or []
    actual = steps[0].get("actual_value") if steps else None
    check("frida-classes-actual", isinstance(actual, int) and actual >= 100,
          f"actual={actual}")

    runs = call("GET", f"/scans/{scan_id}/poc/runs")
    items = runs.get("items") or []
    run = next((r for r in items if r.get("id") == result.get("run_id")), None) or {}
    check("run-persisted", run.get("status") == "passed", run.get("status", "missing"))
    check("run-bound-to-model-hypothesis", hyp_id in (run.get("hypothesis_ids") or []),
          str(run.get("hypothesis_ids")))

    report = call("POST", f"/scans/{scan_id}/report")
    check("report-written", bool(report.get("evidence_id")) or bool(report),
          str(report.get("evidence_id", "")))

    text = call("GET", f"/scans/{scan_id}/report")
    body = text.decode("utf-8", "replace") if isinstance(text, bytes) else str(text)
    # The report composes from persisted rows: the model leg shows in the
    # event log and the dynamic evidence in the evidence index. It does not
    # quote hypothesis/run ids, so the checks match what ARCHIVIST writes.
    check("report-shows-model-consent-event", "model_consent_updated" in body,
          f"len={len(body)}")
    check("report-shows-hypotheses-event", "hypotheses_generated" in body)
    check("report-shows-poc-evidence", "poc-result" in body)

    evidence = call("GET", f"/scans/{scan_id}/evidence")
    kinds = {item.get("kind") for item in (evidence.get("items") or [])}
    check("evidence-kinds-persisted",
          {"poc-plan", "poc-result", "poc-log", "report"} <= kinds,
          ",".join(sorted(kinds)))

    print(f"SUMMARY failures={len(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
