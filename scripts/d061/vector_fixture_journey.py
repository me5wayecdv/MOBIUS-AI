#!/usr/bin/env python3
"""D-061 fixture journey: the substitute-target slice through the real
Mobius authorization/execution path, inside the contained namespace.

upload -> authorization -> scan -> RECON -> PoC plan (VECTOR fixture
capture) -> synthetic CI approval -> execution -> persisted evidence ->
ARCHIVIST report -> read-back. No model leg: this slice needs no upstream
provider at all. No hypothesis seeding, no approval bypass: the approval is
the product approvals API, requested and granted by the CI job inside this
throwaway investigation, exactly like the connected journey smoke.

Scope honesty: the fixture is a substitute target. A pass proves the named
machinery (proxy capture, safe-GET request replay, TLS trust gates) works;
it proves nothing about Allsafe or any real target.
"""
import json
import os
import sys
import time
import uuid
import urllib.request

BASE = os.environ.get("MOBIUS_SMOKE_API", "http://127.0.0.1:8791")
APK_PATH = os.environ["MOBIUS_VECTOR_TRUSTED_APK"]
PKG = "local.mobius.d061lab"
RECEIPTS = os.environ["MOBIUS_VECTOR_RECEIPTS"]

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(("PASS" if ok else "FAIL") + f" {name}" + (f" ({detail})" if detail else ""))
    if not ok:
        failures.append(name)


def call(method: str, path: str, body=None, raw=None, headers=None):
    url = BASE + path
    data = raw
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    with urllib.request.urlopen(req, timeout=300) as resp:
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


def sha256_of(path: str) -> str:
    import hashlib
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def receipt_counts() -> dict:
    counts: dict[str, int] = {}
    try:
        with open(RECEIPTS, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if entry.get("status") == 200 and entry.get("req"):
                    counts[entry["req"]] = counts.get(entry["req"], 0) + 1
    except FileNotFoundError:
        pass
    return counts


def main() -> int:
    sha = sha256_of(APK_PATH)

    app = multipart_upload("/applications", APK_PATH)
    check("application-uploaded", app.get("sha256") == sha, app.get("id", ""))

    auth = call("POST", "/authorizations", {
        "apk_sha256": sha,
        "target_package": PKG,
        "scope_text": ("CI D-061 fixture slice: substitute lab target inside a "
                       "no-uplink contained namespace. Proxy capture, safe-GET "
                       "request replay, and TLS trust gates against a loopback "
                       "mock origin. No external endpoint exists or is "
                       "reachable. Intensity 2 fixture scope."),
        "statement": "Purpose-built lab fixture inside a contained namespace; substitute target.",
        "max_intensity": 2,
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600)),
    })
    check("authorization-created", bool(auth.get("id")), auth.get("id", ""))

    scan = call("POST", "/scans", {
        "application_id": app["id"],
        "authorization_id": auth["id"],
        "objective": "CI D-061 fixture: contained capture machinery against a substitute target.",
        "intensity": 2,
    })
    scan_id = scan.get("id")
    check("scan-created", bool(scan_id), str(scan_id))

    call("POST", f"/scans/{scan_id}/recon")
    detail = call("GET", f"/scans/{scan_id}")
    package = (detail.get("application") or {}).get("package_name")
    check("package-parsed-by-recon", package == PKG, str(package))

    plan = {
        "id": "poc_" + uuid.uuid4().hex.upper()[:26],
        "investigation_id": scan_id,
        "authorization_id": auth["id"],
        "target_sha256": sha,
        "target_package": PKG,
        "target_kind": "emulator",
        "hypothesis_ids": [],
        "steps": [
            {"action": "run_vector_fixture_capture", "target_ref": PKG},
        ],
        "expected_outcome": ("Fixture capture machinery passes all gates: proxied positive "
                             "GET, wrong-hostname rejection, untrusted-CA rejection, "
                             "safe-GET request replay with a second backend receipt."),
        "safety_class": "non_destructive",
        "requires_approval": True,
        "cleanup_steps": [],
        "max_duration_seconds": 600,
        "max_output_bytes": 16384,
    }

    approval = call("POST", f"/scans/{scan_id}/poc/approvals", {
        "plan": plan,
        "justification": ("CI fixture: exercise the contained capture machinery through the "
                          "real execution path against the substitute lab fixture."),
        "risk_summary": ("No-uplink namespace, loopback-only proxy and mock origin, per-run "
                         "test CA, GET-only; no external endpoint exists."),
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 1800)),
    })
    approval_id = approval.get("id")
    check("approval-requested", approval.get("state") == "pending", str(approval.get("state")))

    decision = call("POST", f"/scans/{scan_id}/poc/approvals/{approval_id}/resolve", {
        "decision": "granted",
        "note": "CI fixture approval for the D-061 contained capture slice.",
    })
    check("approval-granted", decision.get("state") == "granted", str(decision.get("state")))

    plan["approval_id"] = approval_id
    result = call("POST", f"/scans/{scan_id}/poc/execute", plan)
    check("poc-execution-passed", result.get("status") == "passed",
          f"status={result.get('status')}")
    output = result.get("output") or {}
    steps = output.get("steps") or []
    actual = steps[0].get("actual_value") if steps else {}
    check("gate-positive", isinstance(actual, dict) and actual.get("positive_ok") is True,
          str(actual))
    check("gate-wronghost-rejected", isinstance(actual, dict) and actual.get("wronghost_rejected") is True)
    check("gate-untrusted-rejected", isinstance(actual, dict) and actual.get("untrusted_rejected") is True)
    check("gate-request-replay", isinstance(actual, dict)
          and actual.get("request_replay_second_receipt") is True)

    counts = receipt_counts()
    check("backend-positive-second-receipt", counts.get("positive", 0) >= 2,
          f"positive_receipts={counts.get('positive', 0)}")

    report = call("POST", f"/scans/{scan_id}/report")
    check("report-written", bool(report.get("evidence_id")) or bool(report),
          str(report.get("evidence_id", "")))
    text = call("GET", f"/scans/{scan_id}/report")
    body = text.decode("utf-8", "replace") if isinstance(text, bytes) else str(text)
    check("report-shows-poc-evidence", "poc-result" in body, f"len={len(body)}")

    evidence = call("GET", f"/scans/{scan_id}/evidence")
    kinds = {item.get("kind") for item in (evidence.get("items") or [])}
    check("evidence-kinds-persisted",
          {"poc-plan", "poc-result", "poc-log", "report"} <= kinds,
          ",".join(sorted(kinds)))

    print(f"SUMMARY failures={len(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
