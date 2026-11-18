"""Investigation-scoped graph persistence and idempotent evidence projection.

D-030 deliberately stops at storage and reconstruction. It does not correlate application
entities, infer paths, or reason about exploitability; those belong to D-031/D-032.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.events import utcnow
from ..adapters.models import (
    EvidenceRow,
    FindingRow,
    GraphEdgeEvidenceRow,
    GraphEdgeRow,
    GraphNodeEvidenceRow,
    GraphNodeRow,
    InvestigationRow,
    ObservationRow,
)
from ..core.enums import AssertionLevel
from ..core.schemas import GraphEdge, GraphNode


class GraphIntegrityError(ValueError):
    """Raised when graph references cross investigation boundaries or are missing."""


@dataclass(frozen=True, slots=True)
class PersistedGraph:
    investigation_id: str
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]


class GraphPersistenceService:
    """Persist graph records and rebuild a provenance-only projection from stored rows."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def _require_investigation(self, investigation_id: str) -> None:
        if self.session.get(InvestigationRow, investigation_id) is None:
            raise GraphIntegrityError(f"unknown investigation {investigation_id}")

    def _validate_evidence(self, investigation_id: str, evidence_refs: tuple[str, ...]) -> None:
        refs = set(evidence_refs)
        if not refs:
            return
        found = set(self.session.execute(
            select(EvidenceRow.id).where(
                EvidenceRow.investigation_id == investigation_id,
                EvidenceRow.id.in_(refs),
            )
        ).scalars())
        missing = refs - found
        if missing:
            raise GraphIntegrityError(
                f"evidence is missing or belongs to another investigation: {sorted(missing)}"
            )

    def add_node(self, node: GraphNode) -> GraphNode:
        self._require_investigation(node.investigation_id)
        self._validate_evidence(node.investigation_id, node.evidence_refs)
        row = self.session.get(GraphNodeRow, node.id)
        if row is None:
            row = GraphNodeRow(
                id=node.id,
                investigation_id=node.investigation_id,
                node_type=node.node_type,
                label=node.label,
                ref=node.ref,
                assertion=node.assertion.value,
                attributes=node.attributes,
                created_at=utcnow(),
            )
            self.session.add(row)
        elif row.investigation_id != node.investigation_id:
            raise GraphIntegrityError("graph node ID is already owned by another investigation")
        else:
            row.node_type = node.node_type
            row.label = node.label
            row.ref = node.ref
            row.assertion = node.assertion.value
            row.attributes = node.attributes
        for evidence_id in sorted(set(node.evidence_refs)):
            link = self.session.get(
                GraphNodeEvidenceRow,
                (node.investigation_id, node.id, evidence_id),
            )
            if link is None:
                self.session.add(GraphNodeEvidenceRow(
                    investigation_id=node.investigation_id,
                    node_id=node.id,
                    evidence_id=evidence_id,
                ))
        self.session.flush()
        return node

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        self._require_investigation(edge.investigation_id)
        endpoints = self.session.execute(
            select(GraphNodeRow.id).where(
                GraphNodeRow.investigation_id == edge.investigation_id,
                GraphNodeRow.id.in_([edge.source_id, edge.target_id]),
            )
        ).scalars()
        if set(endpoints) != {edge.source_id, edge.target_id}:
            raise GraphIntegrityError("both graph edge endpoints must belong to its investigation")
        self._validate_evidence(edge.investigation_id, edge.evidence_refs)
        row = self.session.execute(
            select(GraphEdgeRow).where(
                GraphEdgeRow.investigation_id == edge.investigation_id,
                GraphEdgeRow.source_id == edge.source_id,
                GraphEdgeRow.target_id == edge.target_id,
                GraphEdgeRow.relation == edge.relation,
            )
        ).scalar_one_or_none()
        if row is None:
            row = GraphEdgeRow(
                id=edge.id,
                investigation_id=edge.investigation_id,
                source_id=edge.source_id,
                target_id=edge.target_id,
                relation=edge.relation,
                assertion=edge.assertion.value,
                rationale=edge.rationale,
                created_at=utcnow(),
            )
            self.session.add(row)
        else:
            row.assertion = edge.assertion.value
            row.rationale = edge.rationale
        for evidence_id in sorted(set(edge.evidence_refs)):
            link = self.session.get(
                GraphEdgeEvidenceRow,
                (edge.investigation_id, row.id, evidence_id),
            )
            if link is None:
                self.session.add(GraphEdgeEvidenceRow(
                    investigation_id=edge.investigation_id,
                    edge_id=row.id,
                    evidence_id=evidence_id,
                ))
        self.session.flush()
        return GraphEdge(
            id=row.id,
            investigation_id=row.investigation_id,
            source_id=row.source_id,
            target_id=row.target_id,
            relation=row.relation,
            assertion=AssertionLevel(row.assertion),
            rationale=row.rationale,
            evidence_refs=tuple(sorted(set(edge.evidence_refs))),
        )

    def get_graph(self, investigation_id: str) -> PersistedGraph:
        self._require_investigation(investigation_id)
        node_rows = list(self.session.execute(
            select(GraphNodeRow)
            .where(GraphNodeRow.investigation_id == investigation_id)
            .order_by(GraphNodeRow.created_at, GraphNodeRow.id)
        ).scalars())
        edge_rows = list(self.session.execute(
            select(GraphEdgeRow)
            .where(GraphEdgeRow.investigation_id == investigation_id)
            .order_by(GraphEdgeRow.created_at, GraphEdgeRow.id)
        ).scalars())
        node_refs: dict[str, list[str]] = {}
        for link in self.session.execute(
            select(GraphNodeEvidenceRow).where(
                GraphNodeEvidenceRow.investigation_id == investigation_id
            )
        ).scalars():
            node_refs.setdefault(link.node_id, []).append(link.evidence_id)
        edge_refs: dict[str, list[str]] = {}
        for link in self.session.execute(
            select(GraphEdgeEvidenceRow).where(
                GraphEdgeEvidenceRow.investigation_id == investigation_id
            )
        ).scalars():
            edge_refs.setdefault(link.edge_id, []).append(link.evidence_id)
        nodes = tuple(GraphNode(
            id=row.id,
            investigation_id=row.investigation_id,
            node_type=row.node_type,
            label=row.label,
            ref=row.ref,
            assertion=AssertionLevel(row.assertion),
            attributes=row.attributes or {},
            evidence_refs=tuple(sorted(node_refs.get(row.id, []))),
        ) for row in node_rows)
        edges = tuple(GraphEdge(
            id=row.id,
            investigation_id=row.investigation_id,
            source_id=row.source_id,
            target_id=row.target_id,
            relation=row.relation,
            assertion=AssertionLevel(row.assertion),
            rationale=row.rationale,
            evidence_refs=tuple(sorted(edge_refs.get(row.id, []))),
        ) for row in edge_rows)
        return PersistedGraph(investigation_id, nodes, edges)

    def rebuild(self, investigation_id: str) -> PersistedGraph:
        """Add/update a provenance graph from persisted observations, findings and evidence.

        Stable (type, ref) node identities and unique edge keys make repeated rebuilds
        idempotent. The operation is additive and never deletes graph or source records.
        """
        self._require_investigation(investigation_id)
        evidence_rows = list(self.session.execute(
            select(EvidenceRow)
            .where(EvidenceRow.investigation_id == investigation_id)
            .order_by(EvidenceRow.id)
        ).scalars())
        observations = list(self.session.execute(
            select(ObservationRow)
            .where(ObservationRow.investigation_id == investigation_id)
            .order_by(ObservationRow.id)
        ).scalars())
        findings = list(self.session.execute(
            select(FindingRow)
            .where(FindingRow.investigation_id == investigation_id)
            .order_by(FindingRow.id)
        ).scalars())

        evidence_ids = {row.id for row in evidence_rows}
        for row in evidence_rows:
            self._upsert_projection_node(
                investigation_id, "evidence", row.id, row.summary[:500],
                AssertionLevel.OBSERVED, {"kind": row.kind, "sha256": row.sha256},
                (),
            )
        for row in observations:
            refs = tuple(sorted(set(row.evidence_refs or [])))
            missing = set(refs) - evidence_ids
            if missing:
                raise GraphIntegrityError(
                    f"observation {row.id} references missing evidence: {sorted(missing)}"
                )
            node = self._upsert_projection_node(
                investigation_id, "observation", row.id, row.statement[:500],
                AssertionLevel.OBSERVED if row.kind == "fact" else AssertionLevel.HYPOTHESIS,
                {"agent": row.agent, "kind": row.kind, "fidelity": row.fidelity,
                 "subject_type": row.subject_type, "subject_ref": row.subject_ref,
                 "confidence": row.confidence},
                refs,
            )
            for evidence_id in refs:
                evidence_node = self._find_projection_node(investigation_id, "evidence", evidence_id)
                self._upsert_projection_edge(
                    investigation_id, node.id, evidence_node.id, "supported_by",
                    AssertionLevel.OBSERVED, None, (evidence_id,),
                )
        for row in findings:
            refs = tuple(sorted(set(row.evidence_refs or [])))
            missing = set(refs) - evidence_ids
            if missing:
                raise GraphIntegrityError(
                    f"finding {row.id} references missing evidence: {sorted(missing)}"
                )
            node = self._upsert_projection_node(
                investigation_id, "finding", row.id, row.title[:500],
                AssertionLevel.CONFIRMED if row.status == "confirmed" else AssertionLevel.HYPOTHESIS,
                {"category": row.category, "status": row.status, "severity": row.severity,
                 "confidence": row.confidence, "component_ref": row.component_ref},
                refs,
            )
            for evidence_id in refs:
                evidence_node = self._find_projection_node(investigation_id, "evidence", evidence_id)
                self._upsert_projection_edge(
                    investigation_id, node.id, evidence_node.id, "supported_by",
                    AssertionLevel.OBSERVED, None, (evidence_id,),
                )
        self.session.flush()
        return self.get_graph(investigation_id)

    def _find_projection_node(
        self, investigation_id: str, node_type: str, ref: str
    ) -> GraphNodeRow:
        row = self.session.execute(
            select(GraphNodeRow).where(
                GraphNodeRow.investigation_id == investigation_id,
                GraphNodeRow.node_type == node_type,
                GraphNodeRow.ref == ref,
            )
        ).scalar_one_or_none()
        if row is None:
            raise GraphIntegrityError(f"projection node {node_type}:{ref} was not created")
        return row

    def _upsert_projection_node(
        self, investigation_id: str, node_type: str, ref: str, label: str,
        assertion: AssertionLevel, attributes: dict, evidence_refs: tuple[str, ...],
    ) -> GraphNodeRow:
        row = self.session.execute(
            select(GraphNodeRow).where(
                GraphNodeRow.investigation_id == investigation_id,
                GraphNodeRow.node_type == node_type,
                GraphNodeRow.ref == ref,
            )
        ).scalar_one_or_none()
        if row is None:
            row = GraphNodeRow(
                id=GraphNode(investigation_id=investigation_id, node_type=node_type,
                             label=label, ref=ref, assertion=assertion).id,
                investigation_id=investigation_id, node_type=node_type, label=label,
                ref=ref, assertion=assertion.value, attributes=attributes, created_at=utcnow(),
            )
            self.session.add(row)
            self.session.flush()
        else:
            row.label = label
            row.assertion = assertion.value
            row.attributes = attributes
        for evidence_id in evidence_refs:
            key = (investigation_id, row.id, evidence_id)
            if self.session.get(GraphNodeEvidenceRow, key) is None:
                self.session.add(GraphNodeEvidenceRow(
                    investigation_id=investigation_id, node_id=row.id, evidence_id=evidence_id
                ))
        return row

    def _upsert_projection_edge(
        self, investigation_id: str, source_id: str, target_id: str, relation: str,
        assertion: AssertionLevel, rationale: str | None, evidence_refs: tuple[str, ...],
    ) -> GraphEdgeRow:
        row = self.session.execute(
            select(GraphEdgeRow).where(
                GraphEdgeRow.investigation_id == investigation_id,
                GraphEdgeRow.source_id == source_id,
                GraphEdgeRow.target_id == target_id,
                GraphEdgeRow.relation == relation,
            )
        ).scalar_one_or_none()
        if row is None:
            row = GraphEdgeRow(
                id=GraphEdge(investigation_id=investigation_id, source_id=source_id,
                             target_id=target_id, relation=relation, assertion=assertion).id,
                investigation_id=investigation_id, source_id=source_id, target_id=target_id,
                relation=relation, assertion=assertion.value, rationale=rationale,
                created_at=utcnow(),
            )
            self.session.add(row)
            self.session.flush()
        else:
            row.assertion = assertion.value
            row.rationale = rationale
        for evidence_id in evidence_refs:
            key = (investigation_id, row.id, evidence_id)
            if self.session.get(GraphEdgeEvidenceRow, key) is None:
                self.session.add(GraphEdgeEvidenceRow(
                    investigation_id=investigation_id, edge_id=row.id, evidence_id=evidence_id
                ))
        return row
