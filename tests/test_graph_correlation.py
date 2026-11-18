from __future__ import annotations

from mobius.adapters.models import ObservationRow
from mobius.core.enums import EvidenceKind, Fidelity, ObservationKind
from mobius.services.evidence import EvidenceService
from mobius.services.graph import GraphPersistenceService
from mobius.services.graph_correlation import GraphCorrelationService
from mobius.services.intake import IntakeService
from conftest import make_apk


def _investigation(session, store, future_iso):
    intake = IntakeService(session, store)
    app, _ = intake.create_application(make_apk(), "correlation-fixture.apk", uploaded_by="analyst-1")
    auth = intake.create_authorization(
        apk_sha256=app.sha256, target_package="com.example",
        scope_text="Static analysis only", statement="I own this APK",
        max_intensity=0, granted_by="analyst-1", expires_at=future_iso,
    )
    return intake.create_investigation(
        application_id=app.id, authorization_id=auth.id,
        objective="Correlate persisted evidence", intensity=0, created_by="analyst-1",
    ).id


def _evidence(session, store, scan_id, content):
    return EvidenceService(session, store).record(
        investigation_id=scan_id, kind=EvidenceKind.DEX_STRING, content=content,
        summary="Bytecode evidence", produced_by="SPECTRE",
    )


def _observation(session, scan_id, evidence_id, *, agent, kind, subject_type, subject_ref, attrs, statement):
    from mobius.core.ids import IdPrefix, new_id
    row = ObservationRow(
        id=new_id(IdPrefix.OBSERVATION), investigation_id=scan_id, agent=agent,
        kind=kind, fidelity=Fidelity.DECOMPILED.value, subject_type=subject_type,
        subject_ref=subject_ref, statement=statement, attributes=attrs, maswe=[],
        confidence=1.0 if kind == ObservationKind.FACT.value else 0.8,
        evidence_refs=[evidence_id], created_at="2026-11-18T00:00:00Z",
    )
    session.add(row)
    session.flush()
    return row


def test_correlates_direct_relations_with_evidence_and_is_idempotent(session, store, future_iso):
    scan = _investigation(session, store, future_iso)
    evidence = _evidence(session, store, scan, b"correlation-evidence")
    component = "com.example.Entry"
    method_a = "Lcom/example/Entry;->onCreate()V"
    method_b = "Lcom/example/Helper;->load()V"
    caller = "Lcom/example/Caller;->dispatch()V"
    sink = "android.webkit.WebView#loadUrl"
    guard = "android.content.Context#checkCallingPermission"
    permission = "android.permission.READ_SMS"

    _observation(
        session, scan, evidence.id, agent="RECON", kind=ObservationKind.FACT.value,
        subject_type="component", subject_ref=component,
        attrs={"kind": "activity", "exported": True, "permission": permission},
        statement="Exported activity requires READ_SMS",
    )
    _observation(
        session, scan, evidence.id, agent="SPECTRE", kind=ObservationKind.INFERENCE.value,
        subject_type="component", subject_ref=component,
        attrs={"path": [method_a, method_b], "sink": sink, "guards": [guard],
               "reachability": "reached-guarded"},
        statement="Static path reaches WebView loadUrl with a guard on path",
    )
    _observation(
        session, scan, evidence.id, agent="SPECTRE", kind=ObservationKind.FACT.value,
        subject_type="method", subject_ref=method_b,
        attrs={"target_method": method_b, "target_present": True,
               "callers": [caller], "exhaustive": True},
        statement="Indexed one direct caller for load method",
    )
    _observation(
        session, scan, evidence.id, agent="SPECTRE", kind=ObservationKind.FACT.value,
        subject_type="data_source", subject_ref="android.intent.extra.TEXT",
        attrs={"method_ref": method_a, "source_kind": "intent_extra"},
        statement="Intent extra text is an input source",
    )

    service = GraphCorrelationService(session)
    first = service.correlate(scan)
    graph1 = GraphPersistenceService(session).get_graph(scan)
    ids1 = {(n.node_type, n.ref): n.id for n in graph1.nodes}
    edges1 = {(e.source_id, e.target_id, e.relation): e.id for e in graph1.edges}
    second = service.correlate(scan)
    graph2 = GraphPersistenceService(session).get_graph(scan)
    nodes = {(n.node_type, n.ref): n for n in graph2.nodes}
    edges = {(e.source_id, e.target_id, e.relation): e for e in graph2.edges}

    for key in (
        ("component", component), ("permission", permission), ("method", method_a),
        ("method", method_b), ("method", caller), ("sink", sink), ("guard", guard),
        ("data_source", "android.intent.extra.TEXT"),
    ):
        assert key in nodes
    comp = nodes[("component", component)]
    perm = nodes[("permission", permission)]
    assert (comp.id, perm.id, "requires_permission") in edges
    caller_node, target_node = nodes[("method", caller)], nodes[("method", method_b)]
    assert edges[(caller_node.id, target_node.id, "calls")].assertion.value == "observed"
    source_node, entry_node = nodes[("data_source", "android.intent.extra.TEXT")], nodes[("method", method_a)]
    assert edges[(source_node.id, entry_node.id, "flows_to")].evidence_refs == (evidence.id,)
    inferred = edges[(nodes[("method", method_a)].id, nodes[("method", method_b)].id, "calls")]
    assert inferred.assertion.value == "hypothesis" and inferred.rationale
    reaches = [edge for edge in graph2.edges if edge.relation == "reaches_sink"]
    assert len(reaches) == 1 and reaches[0].assertion.value == "hypothesis"
    assert all(edge.evidence_refs == (evidence.id,) for edge in graph2.edges)
    assert {(n.node_type, n.ref): n.id for n in graph2.nodes} == ids1
    assert {(e.source_id, e.target_id, e.relation): e.id for e in graph2.edges} == edges1
    assert first.data_source_observations == 1
    assert second.graph_nodes == first.graph_nodes
    assert second.graph_edges == first.graph_edges
    assert not any(e.relation in {"attack_chain", "candidate_path"} for e in graph2.edges)


def test_no_data_source_node_is_invented_without_source_observation(session, store, future_iso):
    scan = _investigation(session, store, future_iso)
    evidence = _evidence(session, store, scan, b"no-source-evidence")
    _observation(
        session, scan, evidence.id, agent="RECON", kind=ObservationKind.FACT.value,
        subject_type="component", subject_ref="com.example.Entry",
        attrs={"exported": True, "permission": None},
        statement="Entry component is exported",
    )
    result = GraphCorrelationService(session).correlate(scan)
    graph = GraphPersistenceService(session).get_graph(scan)
    assert not any(node.node_type == "data_source" for node in graph.nodes)
    assert result.data_source_observations == 0
    assert any("No persisted data-source observations" in item for item in result.limitations)
