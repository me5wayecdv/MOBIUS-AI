from __future__ import annotations

from mobius.adapters.models import ObservationRow
from mobius.core.enums import EvidenceKind, Fidelity, ObservationKind
from mobius.core.ids import IdPrefix, new_id
from mobius.services.evidence import EvidenceService
from conftest import make_apk


def _create_scan(client):
    upload = client.post(
        "/api/v1/applications",
        files={"file": ("graph-api.apk", make_apk(), "application/vnd.android.package-archive")},
    )
    assert upload.status_code == 201, upload.text
    app = upload.json()
    auth = client.post("/api/v1/authorizations", json={
        "apk_sha256": app["sha256"], "target_package": "com.example",
        "scope_text": "Static analysis of the team-owned fixture APK only.",
        "statement": "I own this APK and authorize static analysis.",
        "max_intensity": 0, "expires_at": "2099-01-01T00:00:00Z",
    })
    assert auth.status_code == 201, auth.text
    scan = client.post("/api/v1/scans", json={
        "application_id": app["id"], "authorization_id": auth.json()["id"],
        "objective": "Build the persisted evidence graph for the fixture APK.",
        "intensity": 0,
    })
    assert scan.status_code == 201, scan.text
    return scan.json()


def test_graph_api_rebuilds_and_returns_evidence_provenance(client, ctx):
    scan = _create_scan(client)
    with ctx.session() as session:
        evidence = EvidenceService(session, ctx.store).record(
            investigation_id=scan["id"], kind=EvidenceKind.MANIFEST,
            content=b"graph-api-evidence", summary="Manifest proof", produced_by="RECON",
        )
        session.add(ObservationRow(
            id=new_id(IdPrefix.OBSERVATION), investigation_id=scan["id"], agent="RECON",
            kind=ObservationKind.FACT.value, fidelity=Fidelity.BINARY_XML.value,
            subject_type="component", subject_ref="com.example.Entry",
            statement="Activity is exported", attributes={"exported": True, "permission": None},
            maswe=[], confidence=1.0, evidence_refs=[evidence.id],
            created_at="2026-11-18T00:00:00Z",
        ))
        session.commit()
    rebuilt = client.post(f"/api/v1/scans/{scan['id']}/graph/rebuild")
    assert rebuilt.status_code == 200, rebuilt.text
    assert rebuilt.json()["nodes"] >= 2
    response = client.get(f"/api/v1/scans/{scan['id']}/graph")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["investigation_id"] == scan["id"]
    component = next(n for n in body["nodes"] if n["data"]["node_type"] == "component")
    assert component["data"]["evidence_refs"] == [evidence.id]
    assert isinstance(body["edges"], list)
    assert isinstance(body["candidate_paths"], list)


def test_graph_api_enforces_investigation_owner(client):
    scan = _create_scan(client)
    response = client.get(
        f"/api/v1/scans/{scan['id']}/graph",
        headers={"X-Analyst-Id": "different-analyst"},
    )
    assert response.status_code == 404


def test_react_flow_graph_page_is_served(client):
    response = client.get("/ui/graph")
    assert response.status_code == 200, response.text
    assert "MOBIUS" in response.text
    assert 'id="root"' in response.text
