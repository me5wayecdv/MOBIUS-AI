"""End-to-end apply of validated secrets-analysis worker payloads.

Mirrors the provider worker apply tests: hand-built payloads let each test
tamper with exactly one field. Most job rows are inserted directly as
``succeeded`` so each apply test controls its payload exactly. The enqueue
route exists but is DISABLED BY DEFAULT (503 unless the settings gate is
explicitly enabled); while no digest-pinned worker image is published, an
enabled route yields a claimed-and-terminally-failed job, never analysis.
"""

from __future__ import annotations

import json
from uuid import uuid4

from mobius.adapters.events import utcnow
from mobius.adapters.models import ApplicationRow, WorkerJobRow

from conftest import make_apk


def _upload(client, data=None, name="app.apk"):
    return client.post(
        "/api/v1/applications",
        files={"file": (name, data or make_apk(), "application/vnd.android.package-archive")},
    )


def _authorize(client, sha, **kw):
    body = {
        "apk_sha256": sha,
        "target_package": "com.example",
        "scope_text": "Static analysis of the supplied artefact only; no execution.",
        "statement": "I am authorised to analyse this build.",
        "max_intensity": 2,
        "expires_at": "2030-01-01T00:00:00Z",
    }
    body.update(kw)
    return client.post("/api/v1/authorizations", json=body)


def _scan(client, app_id, auth_id, **kw):
    body = {
        "application_id": app_id,
        "authorization_id": auth_id,
        "objective": "Determine whether hardcoded secrets reach a security sink.",
        "intensity": 0,
    }
    body.update(kw)
    return client.post("/api/v1/scans", json=body)


def _surface_ready_scan(client):
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()
    assert client.post(f"/api/v1/scans/{scan['id']}/recon").status_code == 200
    return app, scan


def _enable_enqueue(ctx):
    """Flip the explicit enqueue gate ON for this test (default is OFF)."""
    import dataclasses
    ctx.settings = dataclasses.replace(ctx.settings, secrets_enqueue_enabled=True)


# make_apk writes a 40-byte classes.dex; the ledger cross-check compares
# (name, size) only, so hand-built ledger rows must match those bytes.
LEDGER_PARSED = [{"entry": "classes.dex", "status": "parsed",
                  "size_bytes": 40, "methods": 1}]
LEDGER_FAILED = [{"entry": "classes.dex", "status": "failed-parse",
                  "size_bytes": 40, "methods": 0}]


def _direct_evidence(**overrides):
    item = {
        "kind": "key-material-argument",
        "container_class": "com.example.Foo",
        "container_method": "check",
        "container_descriptor": "()V",
        "sink_class": "javax.crypto.spec.SecretKeySpec",
        "sink_method": "<init>",
        "sink_descriptor": "([BLjava/lang/String;)V",
        "sink_offset": 12,
        "arg_position": 1,
    }
    item.update(overrides)
    return item


def _derived_evidence():
    return {
        "kind": "key-material-argument-derived",
        "container_class": "com.example.Foo",
        "container_method": "check",
        "container_descriptor": "()V",
        "sink_class": "javax.crypto.spec.SecretKeySpec",
        "sink_method": "<init>",
        "sink_descriptor": "([BLjava/lang/String;)V",
        "sink_offset": 12,
        "arg_position": 1,
        "transform_class": "com.example.Foo",
        "transform_method": "decode",
        "transform_descriptor": "(Ljava/lang/String;)[B",
        "transform_offset": 3,
    }


def _candidate(offset=4, evidence=None, screening="not-placeholder",
               flow_complete=False):
    return {
        "method_class": "com.example.Foo",
        "method_name": "check",
        "method_descriptor": "()V",
        "literal_offset": offset,
        "placeholder_screening": screening,
        "flow_complete": flow_complete,
        "evidence": evidence if evidence is not None else [_direct_evidence()],
    }


def _payload(sha, package="com.example", candidates=None, counts=None,
             truncated=False, ledger=None, methods=1):
    cands = [_candidate()] if candidates is None else candidates
    body = {
        "schema_version": 1,
        "artifact_sha256": sha,
        "package_name": package,
        "methods_adapted": methods,
        "truncated": truncated,
        "dex_coverage": ledger if ledger is not None else LEDGER_PARSED,
        "candidates": cands,
        "counts": counts or {"screened_total": len(cands), "evidence_less": 0},
    }
    return body


def _secrets_job(ctx, scan, payload):
    """Insert a succeeded secrets-analysis job row directly (no enqueue
    route exists by design)."""
    with ctx.session() as session:
        from mobius.services.errors import NotFound
        scan_row = session.get(__import__("mobius.adapters.models", fromlist=["InvestigationRow"]).InvestigationRow, scan["id"])
        app_row = session.get(ApplicationRow, scan_row.application_id)
        job = WorkerJobRow(
            id=str(uuid4()),
            investigation_id=scan["id"],
            kind="secrets_analysis",
            artifact_key=app_row.artifact_key,
            status="succeeded",
            attempts=1,
            worker_id="secrets-worker-test",
            result_json=payload,
            staged_sha256=payload["artifact_sha256"],
            created_at=utcnow(),
            finished_at=utcnow(),
        )
        session.add(job)
        session.commit()
        return job.id


def _apply(client, scan, job_id):
    return client.post(f"/api/v1/scans/{scan['id']}/secrets-analysis/jobs/{job_id}/apply")


def _finding_rows(ctx, scan):
    """Stored finding rows: the findings list endpoint carries no
    description, so description-level contract assertions read the rows."""
    from mobius.adapters.models import FindingRow
    with ctx.session() as session:
        rows = (session.query(FindingRow)
                .filter(FindingRow.investigation_id == scan["id"])
                .order_by(FindingRow.created_at.asc()).all())
        return [{c.name: getattr(r, c.name) for c in r.__table__.columns}
                for r in rows]


def _events(client, scan, event_type):
    items = client.get(f"/api/v1/scans/{scan['id']}/events").json()["items"]
    return [e for e in items if e["type"] == event_type]


def _completed(client, scan):
    completed = _events(client, scan, "secrets_analysis_completed")
    assert len(completed) == 1
    return completed[0]["payload"]


def test_apply_lands_candidates_as_manual_review_never_confirmed(client, ctx):
    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload(app["sha256"]))

    applied = _apply(client, scan, job_id)
    assert applied.status_code == 200, applied.text
    body = applied.json()
    assert body["package_name"] == "com.example"
    assert len(body["results"]) == 1
    outcome = body["results"][0]
    # Candidate-only invariant through the real ValidationService.
    assert outcome["verdict"] == "insufficient_evidence"
    assert outcome["finding_status"] == "manual_review_required"
    assert "format_and_entropy_ok" not in outcome["attributes"]
    assert outcome["attributes"]["located"] is True
    assert outcome["attributes"]["flow_incomplete"] is True

    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["category"] == "hardcoded-secret"
    # Conservative severity and capped confidence, not the gate's HIGH hint.
    assert finding["severity"] == "medium"
    # exact: 3 of 4 clauses settled -> 0.38, capped at 0.3
    assert finding["confidence"] == 0.3
    assert "(manual review)" in finding["title"]
    rows = _finding_rows(ctx, scan)
    assert "INCOMPLETE (absence not established)" in rows[0]["description"]
    assert "worker-reported direct key-material route" in rows[0]["description"]

    # The report is composed from the same findings.
    assert client.post(f"/api/v1/scans/{scan['id']}/report").status_code == 200
    report = client.get(f"/api/v1/scans/{scan['id']}/report")
    assert report.status_code == 200
    assert "Hardcoded-secret candidate" in report.text

    summary = _completed(client, scan)
    assert summary["accounting"]["transported"] == 1
    assert summary["accounting"]["transport_complete"] is True
    assert summary["flow_incomplete_candidates"] == 1
    assert summary["detector_coverage_limits"]


def test_apply_derived_candidate_keeps_may_depend_basis(client, ctx):
    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload(
        app["sha256"], candidates=[_candidate(evidence=[_derived_evidence()])]))

    applied = _apply(client, scan, job_id)
    assert applied.status_code == 200, applied.text
    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"]
    assert len(findings) == 1
    assert findings[0]["status"] == "manual_review_required"
    # Derived-only tier: LOW with a lower confidence cap than direct
    # key-material evidence; the unmodelled transform stays explicit.
    assert findings[0]["severity"] == "low"
    # exact: 3 of 4 settled -> 0.38, capped at 0.2
    assert findings[0]["confidence"] == 0.2
    rows = _finding_rows(ctx, scan)
    assert "MAY-depend derived route" in rows[0]["description"]
    assert "unmodelled" in rows[0]["description"]


def test_apply_placeholder_candidate_dropped_counted_never_a_finding(client, ctx):
    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload(
        app["sha256"], candidates=[_candidate(screening="placeholder")]))

    applied = _apply(client, scan, job_id)
    assert applied.status_code == 200, applied.text
    assert applied.json()["results"] == []
    assert client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"] == []
    summary = _completed(client, scan)
    assert summary["accounting"]["placeholder_dropped"] == 1


def test_apply_empty_failed_transport_is_scan_level_incomplete(client, ctx):
    # Zero candidates, evidence existed but none converted: the scan-level
    # incompleteness persists without any candidate description to carry it.
    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload(
        app["sha256"], candidates=[],
        counts={"screened_total": 3, "evidence_less": 0,
                "conversion_failed": 3}))

    applied = _apply(client, scan, job_id)
    assert applied.status_code == 200, applied.text
    assert client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"] == []
    summary = _completed(client, scan)
    assert summary["accounting"]["conversion_failed"] == 3
    assert summary["accounting"]["transport_complete"] is False


def test_apply_empty_clean_is_complete_transport_but_not_no_secrets(client, ctx):
    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload(
        app["sha256"], candidates=[],
        counts={"screened_total": 5, "evidence_less": 5}))

    applied = _apply(client, scan, job_id)
    assert applied.status_code == 200, applied.text
    summary = _completed(client, scan)
    assert summary["accounting"]["transport_complete"] is True
    # Emptiness is never relabelled: coverage limits travel with the summary.
    assert any("not a no-secrets" in line
               for line in summary["detector_coverage_limits"])
    assert any("never a scan-complete" in line
               for line in summary["detector_coverage_limits"])


def test_apply_truncated_payload_is_incomplete_transport(client, ctx):
    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload(
        app["sha256"], candidates=[], truncated=True,
        counts={"screened_total": 5, "evidence_less": 4}))

    applied = _apply(client, scan, job_id)
    assert applied.status_code == 200, applied.text
    summary = _completed(client, scan)
    assert summary["accounting"]["truncated"] is True
    assert summary["accounting"]["transport_complete"] is False


def test_apply_incomplete_dex_labels_worker_asserted_gap(client, ctx):
    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload(
        app["sha256"], ledger=LEDGER_FAILED, methods=0))

    applied = _apply(client, scan, job_id)
    assert applied.status_code == 200, applied.text
    assert applied.json()["dex_complete"] is False
    rows = _finding_rows(ctx, scan)
    assert "worker-asserted INCOMPLETE or ambiguous" in rows[0]["description"]
    assert _completed(client, scan)["dex_complete"] is False


def test_apply_rejects_derived_evidence_on_incomplete_dex(client, ctx):
    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload(
        app["sha256"], candidates=[_candidate(evidence=[_derived_evidence()])],
        ledger=LEDGER_FAILED, methods=0))

    applied = _apply(client, scan, job_id)
    assert applied.status_code == 422
    assert client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"] == []


def test_apply_rejects_tampered_artifact_digest(client, ctx):
    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload("0" * 64))

    applied = _apply(client, scan, job_id)
    assert applied.status_code == 422
    status = client.get(f"/api/v1/scans/{scan['id']}/secrets-analysis/jobs/{job_id}")
    assert status.json()["status"] == "rejected"
    assert client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"] == []


def test_apply_rejects_package_contradicting_recon(client, ctx):
    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload(app["sha256"], package="com.other.app"))

    applied = _apply(client, scan, job_id)
    assert applied.status_code == 422
    assert "recon" in applied.text
    assert client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"] == []


def test_apply_rejects_ledger_contradicting_zip_metadata(client, ctx):
    app, scan = _surface_ready_scan(client)
    bad_ledger = [{"entry": "classes.dex", "status": "parsed",
                   "size_bytes": 999, "methods": 1}]
    job_id = _secrets_job(ctx, scan, _payload(app["sha256"], ledger=bad_ledger))

    applied = _apply(client, scan, job_id)
    assert applied.status_code == 422
    assert "zip metadata" in applied.text
    assert client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"] == []


def test_apply_twice_is_a_conflict_and_never_duplicates(client, ctx):
    # Sequential duplicate only: the atomic claim_apply row-lock is the
    # shared mechanism against a true concurrent race and is NOT separately
    # tested here.
    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload(app["sha256"]))

    assert _apply(client, scan, job_id).status_code == 200
    duplicate = _apply(client, scan, job_id)
    assert duplicate.status_code == 409
    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"]
    assert len(findings) == 1
    assert client.get(
        f"/api/v1/scans/{scan['id']}/secrets-analysis/jobs/{job_id}"
    ).json()["applied"] is True


def test_apply_stores_only_structural_strings_from_unusual_names(client, ctx):
    # Scope: NOT a leak proof - the schema is what excludes literals and
    # worker prose (there is no field for them). This checks the other
    # direction: identifiers that are unusual but schema-legal pass through
    # validation and are stored VERBATIM as structural strings, so the
    # rendering path cannot be surprised by odd-but-legal names.
    weird = "a.A0_._b"
    app, scan = _surface_ready_scan(client)
    job_payload = _payload(
        app["sha256"], candidates=[_candidate(evidence=[_direct_evidence(
            container_class=weird, container_method="_x9",
            container_descriptor="()V")])])
    job_id = _secrets_job(ctx, scan, job_payload)
    assert _apply(client, scan, job_id).status_code == 200

    rows = _finding_rows(ctx, scan)
    assert weird in rows[0]["description"]  # stored as a structural string
    # ... and verbatim in the stored evidence document (read back bytes).
    from mobius.services.evidence import EvidenceService
    with ctx.session() as session:
        svc = EvidenceService(session, ctx.store)
        docs = [svc.read_bytes(e.id).decode() for e in svc.list_for(scan["id"])]
    assert any(weird in doc for doc in docs)
    assert any("worker-reported; not independently verified" in doc
               for doc in docs)


def test_apply_route_rejects_schema_violating_payloads(client, ctx):
    # Route-level rejection: payloads outside the schema never reach
    # storage; the job is terminally rejected with the reason retained.
    app, scan = _surface_ready_scan(client)

    bad_sink = _payload(app["sha256"], candidates=[_candidate(
        evidence=[_direct_evidence(sink_class="android.os.Exec")])])
    job_id = _secrets_job(ctx, scan, bad_sink)
    resp = _apply(client, scan, job_id)
    assert resp.status_code == 422
    assert client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"] == []

    extra_field = _payload(app["sha256"])
    extra_field["candidates"][0]["literal_sha256"] = "0" * 64  # no such field
    job_id = _secrets_job(ctx, scan, extra_field)
    resp = _apply(client, scan, job_id)
    assert resp.status_code == 422
    assert client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"] == []


def test_apply_tiers_comparison_only_evidence_lowest(client, ctx):
    # Comparison-suspect evidence alone is a review signal with no key-role
    # evidence: INFO tier, confidence capped at 0.2, still manual review.
    comparison = {
        "kind": "access-comparison-suspect",
        "container_class": "com.example.Foo",
        "container_method": "check",
        "container_descriptor": "()V",
        "sink_class": "java.lang.String",
        "sink_method": "equals",
        "sink_descriptor": "(Ljava/lang/Object;)Z",
        "sink_offset": 4,
    }
    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload(
        app["sha256"], candidates=[_candidate(evidence=[comparison])]))
    assert _apply(client, scan, job_id).status_code == 200

    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"]
    assert findings[0]["severity"] == "info"
    # exact: 2 of 4 settled -> 0.25, capped at 0.2. The cap equals the
    # derived tier's; SEVERITY is what distinguishes the two bases.
    assert findings[0]["confidence"] == 0.2
    assert findings[0]["status"] == "manual_review_required"
    rows = _finding_rows(ctx, scan)
    assert "comparison-suspect" in rows[0]["description"]
    assert "not key-role evidence" in rows[0]["description"]


def _report_text(client, scan):
    assert client.post(f"/api/v1/scans/{scan['id']}/report").status_code == 200
    resp = client.get(f"/api/v1/scans/{scan['id']}/report")
    assert resp.status_code == 200
    return resp.text


def test_report_renders_secrets_summary_for_empty_clean(client, ctx):
    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload(
        app["sha256"], candidates=[],
        counts={"screened_total": 5, "evidence_less": 5}))
    assert _apply(client, scan, job_id).status_code == 200

    text = _report_text(client, scan)
    assert "Secrets analysis (candidate scan)" in text
    assert "transported 0" in text
    assert "not** a no-secrets result" in text
    assert "never a scan-complete, safe or no-secrets label" in text
    # Constructor references render as code spans: a bare "<init>" would be
    # swallowed as an unknown HTML tag by Markdown renderers.
    assert "`SecretKeySpec.<init>`" in text
    assert "`PBEKeySpec.<init>`" in text
    assert "`KeyStore.load`" in text


def test_report_renders_secrets_summary_for_empty_failed(client, ctx):
    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload(
        app["sha256"], candidates=[],
        counts={"screened_total": 3, "evidence_less": 0,
                "conversion_failed": 3}))
    assert _apply(client, scan, job_id).status_code == 200

    text = _report_text(client, scan)
    assert "Secrets analysis (candidate scan)" in text
    assert "INCOMPLETE: 3 candidate(s)" in text
    assert "not** a no-secrets result" in text


def test_report_renders_secrets_summary_for_truncated(client, ctx):
    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload(
        app["sha256"], candidates=[], truncated=True,
        counts={"screened_total": 5, "evidence_less": 4}))
    assert _apply(client, scan, job_id).status_code == 200

    text = _report_text(client, scan)
    assert "TRUNCATED by the worker" in text
    assert "not** a no-secrets result" in text


def test_report_has_no_secrets_section_without_a_run(client, ctx):
    app, scan = _surface_ready_scan(client)
    text = _report_text(client, scan)
    assert "Secrets analysis (candidate scan)" not in text


def test_apply_malformed_archive_metadata_fails_closed(client, ctx, monkeypatch):
    # Scope: this proves HANDLER behavior only. zipfile.ZipFile is mocked to
    # raise, so it does not exercise real malformed bytes. A truly malformed
    # stored archive is near-unreachable in production: any post-intake byte
    # swap fails the fresh-rehash digest anchor BEFORE the zip open, which is
    # itself covered by the tampered-digest path. What is proven here: if the
    # cross-check ever meets an unreadable archive, the route rejects cleanly
    # (terminal job, bounded reason, no 500, no findings).
    import zipfile

    def _boom(*args, **kwargs):
        raise zipfile.BadZipFile("not a zip")

    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload(app["sha256"]))

    # Patch only around the apply call: building the APK needs zipfile too.
    monkeypatch.setattr(zipfile, "ZipFile", _boom)
    applied = _apply(client, scan, job_id)
    monkeypatch.undo()
    assert applied.status_code == 422
    assert "not a readable zip archive" in applied.text
    status = client.get(f"/api/v1/scans/{scan['id']}/secrets-analysis/jobs/{job_id}")
    assert status.json()["status"] == "rejected"
    assert client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"] == []


def test_enqueue_secrets_analysis_job_queues_and_reports_status(client, ctx):
    _enable_enqueue(ctx)
    app, scan = _surface_ready_scan(client)
    queued = client.post(f"/api/v1/scans/{scan['id']}/secrets-analysis/jobs")
    assert queued.status_code == 202
    body = queued.json()
    assert body["kind"] == "secrets_analysis"
    assert body["status"] == "queued"

    status = client.get(
        f"/api/v1/scans/{scan['id']}/secrets-analysis/jobs/{body['job_id']}")
    assert status.status_code == 200
    assert status.json()["status"] == "queued"


def test_enqueue_secrets_analysis_job_refuses_duplicate(client, ctx):
    _enable_enqueue(ctx)
    app, scan = _surface_ready_scan(client)
    assert client.post(
        f"/api/v1/scans/{scan['id']}/secrets-analysis/jobs").status_code == 202
    duplicate = client.post(f"/api/v1/scans/{scan['id']}/secrets-analysis/jobs")
    assert duplicate.status_code == 409


def test_enqueue_secrets_analysis_job_refuses_after_apply(client, ctx):
    _enable_enqueue(ctx)
    app, scan = _surface_ready_scan(client)
    job_id = _secrets_job(ctx, scan, _payload(
        app["sha256"], candidates=[],
        counts={"screened_total": 1, "evidence_less": 1}))
    assert _apply(client, scan, job_id).status_code == 200

    resp = client.post(f"/api/v1/scans/{scan['id']}/secrets-analysis/jobs")
    assert resp.status_code == 409
    assert "already applied" in resp.json()["detail"]


def test_enqueue_secrets_analysis_job_is_disabled_by_default(client, ctx):
    """Gate OFF (the default): bounded 503 BEFORE any job row is created."""
    app, scan = _surface_ready_scan(client)
    resp = client.post(f"/api/v1/scans/{scan['id']}/secrets-analysis/jobs")
    assert resp.status_code == 503
    assert "disabled" in resp.json()["detail"]

    check = ctx.session()
    try:
        from sqlalchemy import func, select
        rows = check.execute(
            select(func.count()).select_from(WorkerJobRow).where(
                WorkerJobRow.investigation_id == scan["id"],
                WorkerJobRow.kind == "secrets_analysis",
            )
        ).scalar_one()
        assert rows == 0
    finally:
        check.close()
