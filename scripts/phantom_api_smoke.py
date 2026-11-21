#!/usr/bin/env python3
"""PHANTOM API smoke driver (D-060 integration slice).

Drives a real read_only emulator PoC journey through the running Mobius API
against the pinned public Allsafe lab APK installed on the CI emulator:

  upload APK -> authorization -> scan -> PoC execute (emulator probes via
  adb through the PHANTOM adapter) -> persisted run + evidence read-back.

Stdlib only (urllib + sqlite3), so the repo gains no dependencies.

One honesty note: the PoC plan must reference an existing hypothesis, and
hypothesis creation through the API is model-gated (NEXUS consent flow).
This no-model CI journey seeds exactly one hypothesis row directly in the
sqlite database as test setup; every step under test goes through the API.
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
AUTHORITY = "infosecadventures.allsafe.dataprovider"

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""))
    if not ok:
        failures.append(name)


def call(method: str, path: str, body=None, raw=None, headers=None):
    url = BASE + "/api/v1" + path
    data = raw
    hdrs = {"X-Analyst-Id": "ci-phantom-smoke"}
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    with urllib.request.urlopen(req, timeout=120) as resp:
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
             "Exported unprotected provider rows are readable at runtime without a permission.",
             "[]", "[]", '["runtime_rows"]', "[]", "open", 0.8, 0, None, now),
        )
        conn.commit()
    finally:
        conn.close()
    return hyp_id


def main() -> int:
    app = multipart_upload("/applications", APK_PATH)
    check("application-uploaded", app.get("sha256") == SHA256, app.get("id", ""))
    # package_name is intentionally unpopulated at intake; RECON parses it.

    auth = call("POST", "/authorizations", {
        "apk_sha256": SHA256,
        "target_package": PKG,
        "scope_text": ("CI smoke: static intake plus bounded read-only emulator probes "
                       "(package presence, provider row count) on the pinned public "
                       "Allsafe lab build inside an ephemeral emulator."),
        "statement": "Public intentionally-vulnerable training app used as a CI lab target.",
        "max_intensity": 0,
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600)),
    })
    check("authorization-created", bool(auth.get("id")), auth.get("id", ""))

    scan = call("POST", "/scans", {
        "application_id": app["id"],
        "authorization_id": auth["id"],
        "objective": "CI PHANTOM API smoke: execute read-only emulator PoC and persist evidence.",
        "intensity": 0,
    })
    scan_id = scan.get("id")
    check("scan-created", bool(scan_id), str(scan_id))

    recon = call("POST", f"/scans/{scan_id}/recon")
    check("recon-ran", isinstance(recon, dict) and len(recon) > 0)
    detail = call("GET", f"/scans/{scan_id}")
    package = (detail.get("application") or {}).get("package_name")
    check("package-parsed-by-recon", package == PKG, str(package))

    hyp_id = seed_hypothesis(scan_id)

    plan = {
        "investigation_id": scan_id,
        "authorization_id": auth["id"],
        "target_sha256": SHA256,
        "target_package": PKG,
        "target_kind": "emulator",
        "hypothesis_ids": [hyp_id],
        "steps": [
            {"action": "assert_emulator_package_present", "target_ref": PKG,
             "expected_value": True},
            {"action": "assert_emulator_provider_rows",
             "target_ref": f"{AUTHORITY}/note", "expected_value": 4},
        ],
        "expected_outcome": ("Runtime read-only probes confirm the seeded notes are readable "
                             "without a permission on the emulator."),
        "safety_class": "read_only",
        "max_duration_seconds": 120,
        "max_output_bytes": 8192,
    }
    result = call("POST", f"/scans/{scan_id}/poc/execute", plan)
    check("poc-execution-passed", result.get("status") == "passed",
          f"status={result.get('status')}")
    output = result.get("output") or {}
    steps = output.get("steps") or []
    if len(steps) == 2:
        check("provider-rows-actual", steps[1].get("actual_value") == 4,
              f"actual={steps[1].get('actual_value')}")
    else:
        check("provider-rows-actual", False, f"steps={len(steps)}")
    check("poc-evidence-ids", len(result.get("evidence_ids") or []) >= 3,
          str(len(result.get("evidence_ids") or [])))
    check("simulation-flag-honest", output.get("simulation_only") is False)

    runs = call("GET", f"/scans/{scan_id}/poc/runs")
    items = runs.get("items") or []
    run = next((r for r in items if r.get("id") == result.get("run_id")), None)
    check("run-persisted", run is not None and run.get("status") == "passed",
          (run or {}).get("status", "missing"))
    versions = " ".join((run or {}).get("tool_versions") or [])
    check("phantom-version-recorded", "phantom-adb/" in versions, versions)

    evidence = call("GET", f"/scans/{scan_id}/evidence")
    kinds = {item.get("kind") for item in (evidence.get("items") or [])}
    check("evidence-kinds-persisted",
          {"poc-plan", "poc-result", "poc-log"} <= kinds, ",".join(sorted(kinds)))

    print(f"SUMMARY failures={len(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
