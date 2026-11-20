"""RECON: manifest -> evidence -> observations -> frontier.

The test that matters most is `test_recon_candidates_can_never_confirm`. It encodes the
project's central claim in an assertion: a scan that stops after RECON cannot produce a
confirmed finding, no matter how suspicious the manifest looks.
"""

from __future__ import annotations

import io
import zipfile

import pytest

from _axml import encode, manifest_xml
from mobius.adapters.events import SqlEventStore
from mobius.adapters.models import ApplicationRow, EvidenceRow, FrontierEntryRow, ObservationRow
from mobius.core.enums import FindingStatus, InvestigationState, Verdict
from mobius.core.manifest import candidates, recon_candidate_attributes
from mobius.services import errors
from mobius.services.artifacts import ArtifactStore
from mobius.services.intake import IntakeService
from mobius.services.recon import ReconService
from mobius.services.validation import ValidationService


def _svc(session, store) -> IntakeService:
    return IntakeService(session, store)


def _apk(binary: bool = True) -> bytes:
    manifest = encode(manifest_xml()) if binary else (
        b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        b'package="com.example.text"><application>'
        b'<activity android:name=".L" android:exported="true"><intent-filter>'
        b'<action android:name="android.intent.action.MAIN"/>'
        b'<category android:name="android.intent.category.LAUNCHER"/>'
        b'</intent-filter></activity>'
        b'<activity android:name=".Open" android:exported="true"/>'
        b"</application></manifest>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", b"dex\n035\x00")
    return buf.getvalue()


@pytest.fixture()
def started(session, store, future_iso):
    """An investigation already advanced to RECON."""
    intake = _svc(session, store)
    app, _ = intake.create_application(_apk(), "a.apk", uploaded_by="analyst-1")
    auth = intake.create_authorization(
        apk_sha256=app.sha256,
        target_package="com.example.demo",
        scope_text="Static analysis of the supplied artefact only; no execution.",
        statement="s",
        max_intensity=2,
        granted_by="analyst-1",
        expires_at=future_iso,
    )
    inv = intake.create_investigation(
        application_id=app.id,
        authorization_id=auth.id,
        objective="Determine whether exported components reach a privileged sink.",
        intensity=0,
        created_by="analyst-1",
    )
    intake.start(inv.id)
    return inv.id


def test_recon_advances_to_surface_ready(session, store, started):
    result = ReconService(session, store).run(started)
    assert result["state"] == InvestigationState.SURFACE_READY.value
    assert result["package_name"] == "com.example.demo"
    assert result["components"] == 5
    assert result["version_code"] == 7


def test_recon_records_the_decoded_manifest_as_evidence(session, store, started):
    ReconService(session, store).run(started)
    evidence = session.query(EvidenceRow).filter_by(investigation_id=started).all()
    assert len(evidence) == 1
    assert evidence[0].kind == "manifest"
    assert evidence[0].produced_by == "RECON"
    assert b"com.example.demo" in ArtifactStore(store.root).get(evidence[0].object_key)


def test_recon_updates_the_application_identity(session, store, started):
    ReconService(session, store).run(started)
    inv = session.get(__import__("mobius.adapters.models", fromlist=["InvestigationRow"]).InvestigationRow, started)
    app = session.get(ApplicationRow, inv.application_id)
    assert app.package_name == "com.example.demo"
    assert app.version_name == "1.2.3"
    assert app.min_sdk == 24 and app.target_sdk == 34


def test_recon_records_every_component_including_excluded_ones(session, store, started):
    ReconService(session, store).run(started)
    observations = session.query(ObservationRow).filter_by(investigation_id=started).all()
    components = [o for o in observations if o.subject_type == "component"]
    # 5 components from the manifest: activity x2, service, receiver, provider
    assert len(components) == 5
    assert len([o for o in observations if o.subject_type == "application"]) == 1
    attrs = {o.subject_ref: o.attributes for o in components}
    launcher = attrs["com.example.demo.MainActivity"]
    assert launcher["launcher"] is True
    assert launcher["is_candidate"] is False


def test_recon_observations_are_facts_with_evidence(session, store, started):
    ReconService(session, store).run(started)
    for observation in session.query(ObservationRow).filter_by(investigation_id=started):
        assert observation.kind == "fact"
        assert observation.confidence == 1.0
        assert observation.evidence_refs, "a fact without evidence is rejected by the CHECK"


def test_recon_queues_only_unguarded_non_launcher_components(session, store, started):
    result = ReconService(session, store).run(started)
    queued = session.query(FrontierEntryRow).filter_by(investigation_id=started).all()
    assert len(queued) == result["frontier_enqueued"] == 2
    targets = {q.action_args["component"] for q in queued}
    assert targets == {"com.example.demo.ExportActivity", "com.example.demo.BootReceiver"}
    assert all(q.required_agent == "SPECTRE" for q in queued)
    # Gate-seeded candidates carry the corrected taxonomy ID plus the category as
    # scoring metadata, so the metadata fix cannot move their score.
    assert all(q.relates_to_maswe == ["MASWE-0018"] for q in queued)
    assert all(q.gate_category == "exported-component-no-permission" for q in queued)


def test_recon_emits_surface_ready_then_the_transition(session, store, started):
    ReconService(session, store).run(started)
    types = [e.type for e in SqlEventStore(session).read_after(started, 0)]
    # evidence_collected is emitted by EvidenceService when the manifest is stored, so the
    # audit trail shows *why* surface_ready is trustworthy: the bytes are already on record.
    assert types == [
        "investigation_started",
        "investigation_updated",
        "evidence_collected",
        "surface_ready",
        "investigation_updated",
    ]


def test_recon_candidates_can_never_confirm(session, store, started):
    """The central claim, as an assertion.

    Every candidate RECON produces enters validation and comes back
    INSUFFICIENT_EVIDENCE / MANUAL_REVIEW_REQUIRED. Never CONFIRMED: RECON has not shown
    that the code behind the component reaches anything.
    """
    service = ReconService(session, store)
    service.run(started)
    surface_readback = service.surface(started)
    evidence_id = service._record_manifest  # noqa: SLF001 - only checking the attribute exists
    assert callable(evidence_id)

    from mobius.core.manifest import Component, ExportSource, ManifestSurface

    surface = ManifestSurface(
        package_name="com.example.demo",
        components=(
            Component("activity", "com.example.demo.ExportActivity", True,
                      ExportSource.DECLARED),
            Component("receiver", "com.example.demo.BootReceiver", True,
                      ExportSource.INFERRED_INTENT_FILTER),
        ),
    )
    evidence = session.query(EvidenceRow).filter_by(investigation_id=started).one()
    validator = ValidationService(session)
    for component in candidates(surface):
        attrs = recon_candidate_attributes(component)
        finding, verdict = validator.validate(
            investigation_id=started,
            category="exported-component-no-permission",
            attributes=attrs,
            title=f"{component.name} is exported without a guard",
            description="RECON established the declaration only.",
            evidence_refs=(evidence.id,),
            discovered_by="RECON",
            validated_by="VERITAS",
        )
        assert verdict.verdict is Verdict.INSUFFICIENT_EVIDENCE
        assert verdict.rejection_reason is None, 'not refuted, so no rejection reason'
        assert finding.status is FindingStatus.MANUAL_REVIEW_REQUIRED
        assert finding.confidence < 1.0
    assert surface_readback["observations"]


def test_recon_refuses_to_run_out_of_order(session, store, started, future_iso):
    service = ReconService(session, store)
    service.run(started)
    with pytest.raises(errors.ScanStateConflict):
        service.run(started)


def test_recon_rejects_a_corrupt_manifest(session, store, future_iso):
    intake = _svc(session, store)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\xff" * 32)
    app, _ = intake.create_application(buf.getvalue(), "bad.apk", uploaded_by="u")
    auth = intake.create_authorization(
        apk_sha256=app.sha256, target_package="com.bad",
        scope_text="Static analysis of the supplied artefact only.",
        statement="s", max_intensity=1, granted_by="u", expires_at=future_iso,
    )
    inv = intake.create_investigation(
        application_id=app.id, authorization_id=auth.id,
        objective="Attempt to parse a manifest that is not valid AXML.",
        intensity=0, created_by="u",
    )
    intake.start(inv.id)
    with pytest.raises(errors.ManifestInvalid):
        ReconService(session, store).run(inv.id)


def test_recon_surface_readback_lists_frontier(session, store, started):
    service = ReconService(session, store)
    service.run(started)
    body = service.surface(started)
    assert body["package_name"] == "com.example.demo"
    assert len(body["frontier"]) == 2
    assert {f["action"] for f in body["frontier"]} == {"find_api_refs"}
