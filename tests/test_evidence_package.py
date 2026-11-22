from __future__ import annotations

from datetime import datetime, timedelta, timezone

from mobius.adapters.models import ObservationRow
from mobius.core.enums import EvidenceKind, Fidelity, ObservationKind
from mobius.core.ids import IdPrefix, new_id
from mobius.services.evidence import EvidenceService
from mobius.services.evidence_package import EvidencePackageBuilder
from mobius.services.intake import IntakeService
from conftest import make_apk


def _investigation(session, store, future_iso):
    intake = IntakeService(session, store)
    app, _ = intake.create_application(
        make_apk(), "fixture.apk", uploaded_by="analyst-1"
    )
    auth = intake.create_authorization(
        apk_sha256=app.sha256,
        target_package="com.example",
        scope_text="Static analysis only",
        statement="I own this APK",
        max_intensity=0,
        granted_by="analyst-1",
        expires_at=future_iso,
    )
    scan = intake.create_investigation(
        application_id=app.id,
        authorization_id=auth.id,
        objective="Inspect exported component",
        intensity=0,
        created_by="analyst-1",
    )
    return scan.id


def _seed_context(session, store, scan_id, component, *, statement="Call path reaches file sink"):
    evidence = EvidenceService(session, store).record(
        investigation_id=scan_id,
        kind=EvidenceKind.MANIFEST,
        content=b'{"manifest":"fixture","package":"com.example"}',
        summary="Manifest component inventory",
        produced_by="RECON",
    )
    observation = ObservationRow(
        id=new_id(IdPrefix.OBSERVATION),
        investigation_id=scan_id,
        agent="SPECTRE",
        kind=ObservationKind.INFERENCE.value,
        fidelity=Fidelity.DECOMPILED.value,
        subject_type="component",
        subject_ref=component,
        statement=statement,
        attributes={
            "reachability": "reached-unguarded",
            "path": ["Lcom/example/Entry;->onCreate()V", "Ljava/io/FileOutputStream;-><init>()V"],
            "sink": "Ljava/io/FileOutputStream;-><init>()V",
            "guards": ["Lcom/example/Auth;->check()Z"],
            "index_truncated": False,
            "exhaustive": True,
        },
        maswe=["MASWE-0001"],
        confidence=0.8,
        evidence_refs=[evidence.id],
        created_at="2026-11-16T00:00:00Z",
    )
    session.add(observation)
    session.flush()
    return evidence, observation


def test_evidence_package_includes_method_path_sink_guard_and_provenance(
    session, store, future_iso
):
    scan = _investigation(session, store, future_iso)
    evidence, observation = _seed_context(session, store, scan, "com.example.Entry")

    package = EvidencePackageBuilder(session).build(scan, component="com.example.Entry")
    data = package.as_dict()

    assert data["component"] == "com.example.Entry"
    assert [item["id"] for item in data["observations"]] == [observation.id]
    assert data["method_references"] == [
        "Lcom/example/Entry;->onCreate()V",
        "Ljava/io/FileOutputStream;-><init>()V",
    ]
    assert data["sink_references"] == ["Ljava/io/FileOutputStream;-><init>()V"]
    assert data["guard_references"] == ["Lcom/example/Auth;->check()Z"]
    assert data["evidence"][0]["id"] == evidence.id
    assert data["evidence"][0]["sha256"] == evidence.sha256
    assert "No persisted verified JADX source excerpts" in data["limitations"][0]


def test_evidence_package_is_investigation_scoped_and_component_filtered(
    session, store, future_iso
):
    first = _investigation(session, store, future_iso)
    second = _investigation(session, store, future_iso)
    _, own = _seed_context(session, store, first, "com.example.Own")
    _seed_context(session, store, second, "com.example.Other")

    package = EvidencePackageBuilder(session).build(first, component="com.example.Own")

    assert [item["id"] for item in package.observations] == [own.id]
    assert all(item["subject_ref"] != "com.example.Other" for item in package.observations)


def test_evidence_package_limits_are_explicit_and_mark_truncation(
    session, store, future_iso
):
    scan = _investigation(session, store, future_iso)
    _seed_context(session, store, scan, "com.example.Entry")
    _seed_context(session, store, scan, "com.example.Entry", statement="Second observation")

    package = EvidencePackageBuilder(session, max_observations=1).build(scan)

    assert len(package.observations) == 1
    assert package.truncated is True
    assert any("limits were reached" in item for item in package.limitations)


def test_evidence_package_api_enforces_scan_owner(client, ctx):
    response = client.get("/api/v1/scans/not-a-real-scan/evidence-package")
    assert response.status_code == 404


def test_explicit_method_refs_clipping_is_disclosed_not_a_caller_path(session,store,future_iso):
    scan=_investigation(session,store,future_iso)
    _,obs=_seed_context(session,store,scan,'com.example.Entry')
    obs.attributes={'path':[], 'method_references':['C.first','C.second'],
                    'sink_references':['SQLiteDatabase.query'], 'guards':[],
                    'operation':'read', 'operation_coverage_complete':False,
                    'flow_complete':False, 'package_dex_complete':True}
    session.flush()
    p=EvidencePackageBuilder(session,max_methods=1).build(scan).as_dict()
    assert p['truncated'] is True
    assert len(p['method_references'])==1
    a=p['observations'][0]['attributes']
    assert a['path']==[] and a['references_clipped'] is True
    assert a['operation']=='read'
    assert a['operation_coverage_complete'] is False and a['flow_complete'] is False
    assert a['package_dex_complete'] is True
    assert any('omitted' in s for s in p['limitations'])


def test_aggregate_method_reference_clipping_sets_package_truncated(session,store,future_iso):
    scan=_investigation(session,store,future_iso)
    _,a=_seed_context(session,store,scan,'com.example.One')
    _,b=_seed_context(session,store,scan,'com.example.Two')
    a.attributes={'path':[],'method_references':['C.first']}
    b.attributes={'path':[],'method_references':['C.second']}
    session.flush()
    p=EvidencePackageBuilder(session,max_methods=1).build(scan).as_dict()
    assert p['truncated'] is True and len(p['method_references'])==1
    assert all(o['attributes']['references_clipped'] is False for o in p['observations'])
