#!/usr/bin/env python3
"""PHANTOM instrumentation smoke driver (D-060, approval-gated slice).

Drives an observation-only Frida instrumentation PoC through the running
Mobius API against the pinned public Allsafe lab APK on the CI emulator,
using the REAL plan-approval flow (request -> resolve granted -> execute).
No approval is seeded; the granted approval row is produced by the product
API inside this throwaway CI investigation. This is a pinned-lab fixture
verification, not a user-approved production plan.

Stdlib only. The referenced hypothesis is seeded directly in sqlite as
documented test setup (API hypothesis creation is model-gated; this is a
no-model journey); every step under test, including approval, goes through
the API.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
import urllib.request
import uuid

BASE = os.environ.get("MOBIUS_SMOKE_API", "http://127.0.0.1:8791")
DB_FILE = os.environ["MOBIUS_SMOKE_DB_FILE"]
APK_PATH = os.environ.get("MOBIUS_SMOKE_APK", "allsafe.apk")
PKG = "infosecadventures.allsafe"
SHA256 = "d6792d6634a033f048f935f1269179d3c27b859c4c34b1e9e5b008a88375efd9"

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""))
    if not ok:
        failures.append(name)


def call(method: str, path: str, body=None, raw=None, headers=None):
    url = BASE + "/api/v1" + path
    data = raw
    hdrs = {"X-Analyst-Id": "ci-phantom-frida-smoke"}
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    with urllib.request.urlopen(req, timeout=180) as resp:
        payload = resp.read()
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


def seed_hypothesis(scan_id: str) -> str:
    hyp_id = "hyp_" + uuid.uuid4().hex.upper()[:26]
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute(
            "INSERT INTO hypotheses (id, investigation_id, claim, maswe, derived_from,"
            " required_evidence, satisfied_evidence, status, priority, depth, parent_id,"
            " created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (hyp_id, scan_id,
             "Observation-only instrumentation can enumerate the lab app runtime surface.",
             "[]", "[]", '["runtime_instrumentation"]', "[]", "open", 0.8, 0, None, now),
        )
        conn.commit()
    finally:
        conn.close()
    return hyp_id


def main() -> int:
    app = multipart_upload("/applications", APK_PATH)
    check("application-uploaded", app.get("sha256") == SHA256, app.get("id", ""))

    auth = call("POST", "/authorizations", {
        "apk_sha256": SHA256,
        "target_package": PKG,
        "scope_text": ("CI smoke: static intake plus bounded observation-only Frida "
                       "instrumentation (class enumeration) on the pinned public Allsafe "
                       "lab build inside an ephemeral emulator. Intensity 2 fixture scope."),
        "statement": "Public intentionally-vulnerable training app used as a CI lab target.",
        "max_intensity": 2,
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600)),
    })
    check("authorization-created", bool(auth.get("id")), auth.get("id", ""))

    scan = call("POST", "/scans", {
        "application_id": app["id"],
        "authorization_id": auth["id"],
        "objective": "CI PHANTOM instrumentation smoke: approval-gated observation-only Frida PoC.",
        "intensity": 2,
    })
    scan_id = scan.get("id")
    check("scan-created", bool(scan_id), str(scan_id))

    call("POST", f"/scans/{scan_id}/recon")
    detail = call("GET", f"/scans/{scan_id}")
    package = (detail.get("application") or {}).get("package_name")
    check("package-parsed-by-recon", package == PKG, str(package))

    hyp_id = seed_hypothesis(scan_id)

    plan = {
        # A stable client-supplied id: the approval hash covers the plan id,
        # so the approval request and the execution must carry the same one.
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
                             "classes in the lab app process."),
        "safety_class": "non_destructive",
        "requires_approval": True,
        "cleanup_steps": [
            {"action": "stop_emulator_instrumentation", "target_ref": "frida-server"},
        ],
        "max_duration_seconds": 240,
        "max_output_bytes": 8192,
    }

    # Real approval flow through the product API (fixture scope: the CI job is
    # both requester and approver inside this throwaway investigation).
    approval = call("POST", f"/scans/{scan_id}/poc/approvals", {
        "plan": plan,
        "justification": ("CI fixture: verify the approval-gated instrumentation path "
                          "executes observation-only enumeration on the pinned lab app."),
        "risk_summary": ("Ephemeral emulator, public training app, observation-only script, "
                         "instrumentation stopped by cleanup; no external target."),
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 1800)),
    })
    approval_id = approval.get("id")
    check("approval-requested", approval.get("state") == "pending", str(approval.get("state")))

    decision = call("POST", f"/scans/{scan_id}/poc/approvals/{approval_id}/resolve", {
        "decision": "granted",
        "note": "CI fixture approval for the bounded instrumentation smoke.",
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
    check("approval-bound-to-run", run.get("approval_id") == approval_id,
          str(run.get("approval_id")))
    cleanup_steps = (run.get("cleanup") or {}).get("steps") or []
    check("instrumentation-cleanup-recorded",
          bool(cleanup_steps) and cleanup_steps[0].get("status") == "completed",
          json.dumps(cleanup_steps)[:140])
    versions = " ".join(run.get("tool_versions") or [])
    check("phantom-frida-version-recorded", "phantom-frida/" in versions, versions)

    evidence = call("GET", f"/scans/{scan_id}/evidence")
    kinds = {item.get("kind") for item in (evidence.get("items") or [])}
    check("evidence-kinds-persisted",
          {"poc-plan", "poc-result", "poc-log"} <= kinds, ",".join(sorted(kinds)))

    print(f"SUMMARY failures={len(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
