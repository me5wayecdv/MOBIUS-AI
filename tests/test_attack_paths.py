from __future__ import annotations

from mobius.core.enums import AssertionLevel, EvidenceKind
from mobius.core.schemas import GraphEdge, GraphNode
from mobius.services.evidence import EvidenceService
from mobius.services.graph import GraphPersistenceService
from mobius.services.attack_paths import CandidateAttackPathService
from mobius.services.intake import IntakeService
from conftest import make_apk


def _investigation(session, store, future_iso):
    intake = IntakeService(session, store)
    app, _ = intake.create_application(make_apk(), "path-fixture.apk", uploaded_by="analyst-1")
    auth = intake.create_authorization(
        apk_sha256=app.sha256, target_package="com.example",
        scope_text="Static analysis only", statement="I own this APK",
        max_intensity=0, granted_by="analyst-1", expires_at=future_iso,
    )
    return intake.create_investigation(
        application_id=app.id, authorization_id=auth.id,
        objective="Build candidate attack path", intensity=0, created_by="analyst-1",
    ).id


def _seed_path(session, store, scan_id, *, with_source=False, with_guard=False, with_permission=False):
    evidence = EvidenceService(session, store).record(
        investigation_id=scan_id, kind=EvidenceKind.DEX_STRING,
        content=b"attack-path-evidence", summary="Static call graph evidence", produced_by="SPECTRE",
    )
    persistence = GraphPersistenceService(session)
    component = persistence.add_node(GraphNode(
        investigation_id=scan_id, node_type="component", label="com.example.Entry",
        ref="com.example.Entry", assertion=AssertionLevel.OBSERVED,
        attributes={"exported": True}, evidence_refs=(evidence.id,),
    ))
    method_a = persistence.add_node(GraphNode(
        investigation_id=scan_id, node_type="method", label="Entry.onCreate",
        ref="Lcom/example/Entry;->onCreate()V", assertion=AssertionLevel.HYPOTHESIS,
        evidence_refs=(evidence.id,),
    ))
    method_b = persistence.add_node(GraphNode(
        investigation_id=scan_id, node_type="method", label="Helper.load",
        ref="Lcom/example/Helper;->load()V", assertion=AssertionLevel.HYPOTHESIS,
        evidence_refs=(evidence.id,),
    ))
    sink = persistence.add_node(GraphNode(
        investigation_id=scan_id, node_type="sink", label="WebView.loadUrl",
        ref="android.webkit.WebView#loadUrl", assertion=AssertionLevel.OBSERVED,
        evidence_refs=(evidence.id,),
    ))
    persistence.add_edge(GraphEdge(
        investigation_id=scan_id, source_id=component.id, target_id=method_a.id,
        relation="enters_method", assertion=AssertionLevel.HYPOTHESIS,
        rationale="Manifest component maps to this entry method.", evidence_refs=(evidence.id,),
    ))
    persistence.add_edge(GraphEdge(
        investigation_id=scan_id, source_id=method_a.id, target_id=method_b.id,
        relation="calls", assertion=AssertionLevel.HYPOTHESIS,
        rationale="Bytecode call graph contains this direct call.", evidence_refs=(evidence.id,),
    ))
    persistence.add_edge(GraphEdge(
        investigation_id=scan_id, source_id=method_b.id, target_id=sink.id,
        relation="reaches_sink", assertion=AssertionLevel.HYPOTHESIS,
        rationale="Static path reaches a catalogued sink.", evidence_refs=(evidence.id,),
    ))
    if with_source:
        source = persistence.add_node(GraphNode(
            investigation_id=scan_id, node_type="data_source", label="Intent extra",
            ref="android.intent.extra.TEXT", assertion=AssertionLevel.OBSERVED,
            evidence_refs=(evidence.id,),
        ))
        persistence.add_edge(GraphEdge(
            investigation_id=scan_id, source_id=source.id, target_id=method_a.id,
            relation="flows_to", assertion=AssertionLevel.OBSERVED, evidence_refs=(evidence.id,),
        ))
    if with_guard:
        guard = persistence.add_node(GraphNode(
            investigation_id=scan_id, node_type="guard", label="Permission check",
            ref="checkCallingPermission", assertion=AssertionLevel.OBSERVED,
            evidence_refs=(evidence.id,),
        ))
        persistence.add_edge(GraphEdge(
            investigation_id=scan_id, source_id=component.id, target_id=guard.id,
            relation="guard_on_path", assertion=AssertionLevel.HYPOTHESIS,
            rationale="Static analysis observed a guard reference.", evidence_refs=(evidence.id,),
        ))
    if with_permission:
        permission = persistence.add_node(GraphNode(
            investigation_id=scan_id, node_type="permission", label="READ_SMS",
            ref="android.permission.READ_SMS", assertion=AssertionLevel.OBSERVED,
            evidence_refs=(evidence.id,),
        ))
        persistence.add_edge(GraphEdge(
            investigation_id=scan_id, source_id=component.id, target_id=permission.id,
            relation="requires_permission", assertion=AssertionLevel.OBSERVED,
            evidence_refs=(evidence.id,),
        ))
    return evidence, component, method_a, method_b, sink


def test_builds_candidate_with_prerequisites_and_missing_proof_and_is_idempotent(
    session, store, future_iso
):
    scan = _investigation(session, store, future_iso)
    evidence, component, method_a, method_b, sink = _seed_path(
        session, store, scan, with_guard=True,
    )
    service = CandidateAttackPathService(session)
    first = service.build(scan)
    second = service.build(scan)

    assert len(first.candidates) == 1
    path = first.candidates[0]
    assert path.node_ids == (component.id, method_a.id, method_b.id, sink.id)
    assert path.edge_ids
    prereqs = {item.key: item.status for item in path.prerequisites}
    assert prereqs["exported_component"] == "satisfied"
    assert prereqs["static_call_path"] == "satisfied"
    assert prereqs["sink_reference"] == "satisfied"
    assert prereqs["data_source_observed"] == "missing"
    assert prereqs["taint_propagation"] == "missing"
    assert prereqs["guard_semantics"] == "unknown"
    assert prereqs["runtime_reproduction"] == "missing"
    assert any("attacker-controlled data source" in item for item in path.missing_proof)
    assert any("taint propagation" in item for item in path.missing_proof)
    assert any("guard correctness" in item for item in path.missing_proof)
    assert any("negative control" in item for item in path.missing_proof)

    graph = GraphPersistenceService(session).get_graph(scan)
    path_node = next(node for node in graph.nodes if node.id == path.graph_node_id)
    assert path_node.assertion is AssertionLevel.HYPOTHESIS
    assert path_node.attributes["not_an_exploitability_verdict"] is True
    assert len([edge for edge in graph.edges if edge.relation == "includes_step"]) == 4
    assert second.candidates[0].graph_node_id == path.graph_node_id
    assert second.graph_nodes == first.graph_nodes
    assert second.graph_edges == first.graph_edges
    assert all(edge.assertion is not AssertionLevel.CONFIRMED for edge in graph.edges)


def test_source_observation_is_partial_not_proof_of_taint(session, store, future_iso):
    scan = _investigation(session, store, future_iso)
    _seed_path(session, store, scan, with_source=True, with_permission=True)
    result = CandidateAttackPathService(session).build(scan)
    path = result.candidates[0]
    prereqs = {item.key: item.status for item in path.prerequisites}
    assert prereqs["data_source_observed"] == "partial"
    assert prereqs["permission_enforcement"] == "unknown"
    assert prereqs["taint_propagation"] == "missing"
    assert any("Prove source-to-sink taint propagation" in item for item in path.missing_proof)


def test_no_candidate_is_created_without_a_sink_reachability_edge(session, store, future_iso):
    scan = _investigation(session, store, future_iso)
    evidence, component, method_a, method_b, sink = _seed_path(session, store, scan)
    # The test uses a fresh investigation with a component but no complete route to a sink.
    other = _investigation(session, store, future_iso)
    other_evidence = EvidenceService(session, store).record(
        investigation_id=other, kind=EvidenceKind.DEX_STRING,
        content=b"other-attack-path-evidence", summary="Other static evidence", produced_by="SPECTRE",
    )
    persistence = GraphPersistenceService(session)
    component2 = persistence.add_node(GraphNode(
        investigation_id=other, node_type="component", label="Exported",
        ref="com.example.Other", assertion=AssertionLevel.OBSERVED,
        attributes={"exported": True}, evidence_refs=(other_evidence.id,),
    ))
    result = CandidateAttackPathService(session).build(other)
    assert result.candidates == ()
