from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from mobius.adapters.models import (\n    GraphEdgeEvidenceRow, GraphEdgeRow, GraphNodeEvidenceRow, ObservationRow,\n)
from mobius.core.enums import AssertionLevel, EvidenceKind, Fidelity, ObservationKind
from mobius.core.ids import IdPrefix, new_id
from mobius.core.schemas import GraphEdge, GraphNode
from mobius.services.evidence import EvidenceService
from mobius.services.graph import GraphIntegrityError, GraphPersistenceService
from mobius.services.intake import IntakeService
from conftest import make_apk


def _investigation(session, store, future_iso):
    intake = IntakeService(session, store)
    app, _ = intake.create_application(make_apk(), "graph-fixture.apk", uploaded_by="analyst-1")
    auth = intake.create_authorization(
        apk_sha256=app.sha256,
        target_package="com.example",
        scope_text="Static analysis only",
        statement="I own this APK",
        max_intensity=0,
        granted_by="analyst-1",
        expires_at=future_iso,
    )
    return intake.create_investigation(
        application_id=app.id,
        authorization_id=auth.id,
        objective="Persist evidence graph",
        intensity=0,
        created_by="analyst-1",
    ).id


def _evidence(session, scan_id, payload):
    return EvidenceService(session, _StoreStub()).record(
        investigation_id=scan_id,
        kind=EvidenceKind.MANIFEST,
        content=payload,
        summary="Manifest evidence",
        produced_by="RECON",
    )


class _StoreStub:
    def __init__(self):
        self.data = {}

    def put(self, content, sha):
        key = f"evidence/{sha}"
        self.data[key] = content
        return key, len(content)

    def get(self, key):
        return self.data[key]


def test_graph_edge_uses_its_own_id_prefix_and_hypothesis_requires_rationale():
    edge = GraphEdge(
        investigation_id="scn_01J8ZQ3K7Y0000000000000000",
        source_id="gph_01J8ZQ3K7Y0000000000000000",
        target_id="gph_01J8ZQ3K7Y0000000000000001",
        relation="calls",
        assertion=AssertionLevel.OBSERVED,
    )
    assert edge.id.startswith("ged_")
    with pytest.raises(ValidationError, match="rationale"):
        GraphEdge(
            investigation_id="scn_01J8ZQ3K7Y0000000000000000",
            source_id="gph_01J8ZQ3K7Y0000000000000000",
            target_id="gph_01J8ZQ3K7Y0000000000000001",
            relation="may_call",
            assertion=AssertionLevel.HYPOTHESIS,
        )


def test_rebuild_persists_provenance_and_is_idempotent(session, store, future_iso):
    scan_id = _investigation(session, store, future_iso)
    evidence = EvidenceService(session, store).record(
        investigation_id=scan_id,
        kind=EvidenceKind.MANIFEST,
        content=b"graph-manifest-fixture",
        summary="Exported component manifest",
        produced_by="RECON",
    )
    observation = ObservationRow(
        id=new_id(IdPrefix.OBSERVATION),
        investigation_id=scan_id,
        agent="RECON",
        kind=ObservationKind.FACT.value,
        fidelity=Fidelity.MANIFEST.value,
        subject_type="component",
        subject_ref="com.example.Entry",
        statement="Component is exported",
        attributes={"exported": True},
        maswe=[],
        confidence=1.0,
        evidence_refs=[evidence.id],
        created_at="2026-11-18T00:00:00Z",
    )
    session.add(observation)
    session.flush()

    service = GraphPersistenceService(session)
    first = service.rebuild(scan_id)
    first_node_ids = {node.ref: node.id for node in first.nodes}
    first_edge_ids = {edge.id for edge in first.edges}
    second = service.rebuild(scan_id)

    assert len(first.nodes) == 2
    assert len(first.edges) == 1
    assert {node.ref: node.id for node in second.nodes} == first_node_ids
    assert {edge.id for edge in second.edges} == first_edge_ids
    observation_node = next(n for n in second.nodes if n.node_type == "observation")
    evidence_node = next(n for n in second.nodes if n.node_type == "evidence")
    assert observation_node.evidence_refs == (evidence.id,)
    assert second.edges[0].source_id == observation_node.id
    assert second.edges[0].target_id == evidence_node.id
    assert second.edges[0].relation == "supported_by"
    assert second.edges[0].evidence_refs == (evidence.id,)


def test_graph_service_rejects_evidence_from_another_investigation(
    session, store, future_iso
):
    first = _investigation(session, store, future_iso)
    second = _investigation(session, store, future_iso)
    foreign = EvidenceService(session, store).record(
        investigation_id=second,
        kind=EvidenceKind.MANIFEST,
        content=b"foreign-evidence",
        summary="Foreign evidence",
        produced_by="RECON",
    )
    node = GraphNode(
        investigation_id=first,
        node_type="component",
        label="Entry",
        ref="com.example.Entry",
        assertion=AssertionLevel.OBSERVED,
        evidence_refs=(foreign.id,),
    )
    with pytest.raises(GraphIntegrityError, match="another investigation"):
        GraphPersistenceService(session).add_node(node)


def test_graph_service_rejects_edge_endpoint_from_another_investigation(
    session, store, future_iso
):
    first = _investigation(session, store, future_iso)
    second = _investigation(session, store, future_iso)
    service = GraphPersistenceService(session)
    local = service.add_node(GraphNode(
        investigation_id=first, node_type="component", label="Local",
        ref="local", assertion=AssertionLevel.OBSERVED,
    ))
    foreign = service.add_node(GraphNode(
        investigation_id=second, node_type="component", label="Foreign",
        ref="foreign", assertion=AssertionLevel.OBSERVED,
    ))
    with pytest.raises(GraphIntegrityError, match="endpoints"):
        service.add_edge(GraphEdge(
            investigation_id=first, source_id=local.id, target_id=foreign.id,
            relation="calls", assertion=AssertionLevel.OBSERVED,
        ))


def test_database_composite_foreign_key_blocks_cross_investigation_edge(session, store, future_iso):
    first = _investigation(session, store, future_iso)
    second = _investigation(session, store, future_iso)
    service = GraphPersistenceService(session)
    local = service.add_node(GraphNode(
        investigation_id=first, node_type="component", label="Local",
        ref="local-db", assertion=AssertionLevel.OBSERVED,
    ))
    foreign = service.add_node(GraphNode(
        investigation_id=second, node_type="component", label="Foreign",
        ref="foreign-db", assertion=AssertionLevel.OBSERVED,
    ))
    invalid = GraphEdgeRow(
        id=new_id(IdPrefix.GRAPH_EDGE),
        investigation_id=first,
        source_id=local.id,
        target_id=foreign.id,
        relation="calls",
        assertion=AssertionLevel.OBSERVED.value,
        rationale=None,
        created_at="2026-11-18T00:00:00Z",
    )
    session.add(invalid)
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_database_composite_foreign_keys_block_cross_investigation_evidence_links(
    session, store, future_iso
):
    first = _investigation(session, store, future_iso)
    second = _investigation(session, store, future_iso)
    foreign = EvidenceService(session, store).record(
        investigation_id=second,
        kind=EvidenceKind.MANIFEST,
        content=b"foreign-association-evidence",
        summary="Foreign evidence",
        produced_by="RECON",
    )
    service = GraphPersistenceService(session)
    node = service.add_node(GraphNode(
        investigation_id=first, node_type="component", label="Local",
        ref="node-local", assertion=AssertionLevel.OBSERVED,
    ))
    session.commit()
    with pytest.raises(IntegrityError):
        session.add(GraphNodeEvidenceRow(
            investigation_id=first, node_id=node.id, evidence_id=foreign.id
        ))
        session.flush()
    session.rollback()

    # Recreate the graph node after rollback and exercise the edge-evidence composite FK.
    service = GraphPersistenceService(session)
    node_a = service.add_node(GraphNode(
        investigation_id=first, node_type="component", label="A",
        ref="edge-a", assertion=AssertionLevel.OBSERVED,
    ))
    node_b = service.add_node(GraphNode(
        investigation_id=first, node_type="component", label="B",
        ref="edge-b", assertion=AssertionLevel.OBSERVED,
    ))
    edge = service.add_edge(GraphEdge(
        investigation_id=first, source_id=node_a.id, target_id=node_b.id,
        relation="calls", assertion=AssertionLevel.OBSERVED,
    ))
    with pytest.raises(IntegrityError):
        session.add(GraphEdgeEvidenceRow(
            investigation_id=first, edge_id=edge.id, evidence_id=foreign.id
        ))
        session.flush()
    session.rollback()


def test_graph_is_empty_for_investigation_without_persisted_source_rows(
    session, store, future_iso
):
    scan_id = _investigation(session, store, future_iso)
    graph = GraphPersistenceService(session).rebuild(scan_id)
    assert graph.investigation_id == scan_id
    assert graph.nodes == ()
    assert graph.edges == ()
