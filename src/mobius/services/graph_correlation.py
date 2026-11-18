"""Deterministic direct evidence correlation for D-031; no attack-chain reasoning."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.models import (
    GraphEdgeEvidenceRow, GraphEdgeRow, GraphNodeEvidenceRow, GraphNodeRow, ObservationRow,
)
from ..core.enums import AssertionLevel
from ..core.schemas import GraphEdge, GraphNode
from .graph import GraphPersistenceService


@dataclass(frozen=True, slots=True)
class CorrelationSummary:
    investigation_id: str
    nodes_touched: int
    edges_touched: int
    graph_nodes: int
    graph_edges: int
    data_source_observations: int
    limitations: tuple[str, ...]


class GraphCorrelationService:
    """Create typed direct relations only from explicit persisted observation records."""

    _RANK = {
        AssertionLevel.REJECTED: 0,
        AssertionLevel.HYPOTHESIS: 1,
        AssertionLevel.OBSERVED: 2,
        AssertionLevel.CONFIRMED: 3,
    }

    def __init__(self, session: Session) -> None:
        self.session = session
        self.persistence = GraphPersistenceService(session)

    def correlate(self, investigation_id: str) -> CorrelationSummary:
        self.persistence.rebuild(investigation_id)
        nodes_touched: set[tuple[str, str]] = set()
        edges_touched: set[tuple[str, str, str]] = set()
        rows = list(self.session.execute(
            select(ObservationRow)
            .where(ObservationRow.investigation_id == investigation_id)
            .order_by(ObservationRow.created_at, ObservationRow.id)
        ).scalars())
        source_count = 0

        for row in rows:
            attrs = row.attributes or {}
            evidence = tuple(sorted(set(row.evidence_refs or [])))
            assertion = (
                AssertionLevel.OBSERVED
                if row.kind == "fact"
                else AssertionLevel.HYPOTHESIS
            )
            rationale = None if assertion is AssertionLevel.OBSERVED else row.statement

            if row.subject_type == "component" and row.subject_ref:
                component = self._node(
                    investigation_id, "component", row.subject_ref, row.subject_ref,
                    assertion, self._scalar_attrs(attrs), evidence,
                )
                nodes_touched.add(("component", row.subject_ref))
                permission = attrs.get("permission")
                if isinstance(permission, str) and permission.strip():
                    target = self._node(
                        investigation_id, "permission", permission, permission,
                        AssertionLevel.OBSERVED, {}, evidence,
                    )
                    nodes_touched.add(("permission", permission))
                    self._edge(
                        investigation_id, component.id, target.id, "requires_permission",
                        assertion, rationale, evidence,
                    )
                    edges_touched.add((component.id, target.id, "requires_permission"))

                methods: list[GraphNode] = []
                for method_ref in self._strings(attrs.get("path")):
                    method = self._node(
                        investigation_id, "method", method_ref, method_ref, assertion,
                        {"origin_observation": row.id}, evidence,
                    )
                    methods.append(method)
                    nodes_touched.add(("method", method_ref))
                if methods:
                    self._edge(
                        investigation_id, component.id, methods[0].id, "enters_method",
                        assertion, rationale, evidence,
                    )
                    edges_touched.add((component.id, methods[0].id, "enters_method"))
                    for source, target in zip(methods, methods[1:]):
                        self._edge(
                            investigation_id, source.id, target.id, "calls",
                            assertion, rationale, evidence,
                        )
                        edges_touched.add((source.id, target.id, "calls"))

                sink_ref = attrs.get("sink")
                if isinstance(sink_ref, str) and sink_ref.strip():
                    sink = self._node(
                        investigation_id, "sink", sink_ref, sink_ref,
                        AssertionLevel.OBSERVED, {}, evidence,
                    )
                    nodes_touched.add(("sink", sink_ref))
                    source_node = methods[-1] if methods else component
                    self._edge(
                        investigation_id, source_node.id, sink.id, "reaches_sink",
                        assertion, rationale, evidence,
                    )
                    edges_touched.add((source_node.id, sink.id, "reaches_sink"))

                for guard_ref in self._strings(attrs.get("guards")):
                    guard = self._node(
                        investigation_id, "guard", guard_ref, guard_ref,
                        AssertionLevel.OBSERVED, {}, evidence,
                    )
                    nodes_touched.add(("guard", guard_ref))
                    self._edge(
                        investigation_id, component.id, guard.id, "guard_on_path",
                        assertion, rationale, evidence,
                    )
                    edges_touched.add((component.id, guard.id, "guard_on_path"))

            elif row.subject_type == "method" and row.subject_ref:
                target_ref = attrs.get("target_method")
                if not isinstance(target_ref, str) or not target_ref.strip():
                    target_ref = row.subject_ref
                target = self._node(
                    investigation_id, "method", target_ref, target_ref, assertion,
                    {"origin_observation": row.id}, evidence,
                )
                nodes_touched.add(("method", target_ref))
                if attrs.get("target_present") is True:
                    for caller_ref in self._strings(attrs.get("callers")):
                        caller = self._node(
                            investigation_id, "method", caller_ref, caller_ref,
                            AssertionLevel.OBSERVED, {"origin_observation": row.id}, evidence,
                        )
                        nodes_touched.add(("method", caller_ref))
                        self._edge(
                            investigation_id, caller.id, target.id, "calls",
                            AssertionLevel.OBSERVED, None, evidence,
                        )
                        edges_touched.add((caller.id, target.id, "calls"))

            elif row.subject_type in ("data_source", "source") and row.subject_ref:
                source_count += 1
                source = self._node(
                    investigation_id, "data_source", row.subject_ref, row.statement,
                    assertion, self._scalar_attrs(attrs), evidence,
                )
                nodes_touched.add(("data_source", row.subject_ref))
                method_ref = attrs.get("method_ref")
                if isinstance(method_ref, str) and method_ref.strip():
                    method = self._node(
                        investigation_id, "method", method_ref, method_ref, assertion,
                        {"origin_observation": row.id}, evidence,
                    )
                    nodes_touched.add(("method", method_ref))
                    self._edge(
                        investigation_id, source.id, method.id, "flows_to",
                        assertion, rationale, evidence,
                    )
                    edges_touched.add((source.id, method.id, "flows_to"))

        self.session.flush()
        graph = self.persistence.get_graph(investigation_id)
        limitations = [
            "Direct evidence relations only; no candidate attack-chain reasoning or exploitability conclusion (D-032)."
        ]
        if source_count == 0:
            limitations.append(
                "No persisted data-source observations exist. No source node was invented; "
                "source-to-method relations require explicit source observations from D-014/D-015."
            )
        return CorrelationSummary(
            investigation_id=investigation_id,
            nodes_touched=len(nodes_touched),
            edges_touched=len(edges_touched),
            graph_nodes=len(graph.nodes),
            graph_edges=len(graph.edges),
            data_source_observations=source_count,
            limitations=tuple(limitations),
        )

    def _node(
        self, investigation_id: str, node_type: str, ref: str, label: str,
        assertion: AssertionLevel, attrs: dict[str, Any], evidence: tuple[str, ...],
    ) -> GraphNode:
        row = self.session.execute(
            select(GraphNodeRow).where(
                GraphNodeRow.investigation_id == investigation_id,
                GraphNodeRow.node_type == node_type,
                GraphNodeRow.ref == ref,
            )
        ).scalar_one_or_none()
        if row is None:
            node = GraphNode(
                investigation_id=investigation_id, node_type=node_type, label=label[:1000],
                ref=ref, assertion=assertion, attributes=attrs, evidence_refs=evidence,
            )
        else:
            old_refs = set(self.session.execute(
                select(GraphNodeEvidenceRow.evidence_id).where(
                    GraphNodeEvidenceRow.investigation_id == investigation_id,
                    GraphNodeEvidenceRow.node_id == row.id,
                )
            ).scalars())
            strongest = max(
                (AssertionLevel(row.assertion), assertion), key=lambda item: self._RANK[item]
            )
            node = GraphNode(
                id=row.id, investigation_id=investigation_id, node_type=node_type,
                label=label[:1000], ref=ref, assertion=strongest,
                attributes={**(row.attributes or {}), **attrs},
                evidence_refs=tuple(sorted(old_refs | set(evidence))),
            )
        return self.persistence.add_node(node)

    def _edge(
        self, investigation_id: str, source_id: str, target_id: str, relation: str,
        assertion: AssertionLevel, rationale: str | None, evidence: tuple[str, ...],
    ) -> GraphEdge:
        row = self.session.execute(
            select(GraphEdgeRow).where(
                GraphEdgeRow.investigation_id == investigation_id,
                GraphEdgeRow.source_id == source_id,
                GraphEdgeRow.target_id == target_id,
                GraphEdgeRow.relation == relation,
            )
        ).scalar_one_or_none()
        if row is None:
            edge = GraphEdge(
                investigation_id=investigation_id, source_id=source_id, target_id=target_id,
                relation=relation, assertion=assertion, rationale=rationale,
                evidence_refs=evidence,
            )
        else:
            old_refs = set(self.session.execute(
                select(GraphEdgeEvidenceRow.evidence_id).where(
                    GraphEdgeEvidenceRow.investigation_id == investigation_id,
                    GraphEdgeEvidenceRow.edge_id == row.id,
                )
            ).scalars())
            strongest = max(
                (AssertionLevel(row.assertion), assertion), key=lambda item: self._RANK[item]
            )
            edge = GraphEdge(
                id=row.id, investigation_id=investigation_id, source_id=source_id,
                target_id=target_id, relation=relation, assertion=strongest,
                rationale=rationale or row.rationale,
                evidence_refs=tuple(sorted(old_refs | set(evidence))),
            )
        return self.persistence.add_edge(edge)

    @staticmethod
    def _strings(value: Any) -> tuple[str, ...]:
        if not isinstance(value, (list, tuple)):
            return ()
        return tuple(sorted({item.strip() for item in value if isinstance(item, str) and item.strip()}))

    @staticmethod
    def _scalar_attrs(attrs: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value for key, value in attrs.items()
            if isinstance(value, (str, int, float, bool)) or value is None
        }
