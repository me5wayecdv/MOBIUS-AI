"""Conservative candidate attack-path construction for D-032.

Paths are hypotheses assembled from direct D-031 graph relations. This module does not
confirm findings, execute tests, or claim exploitability. Every candidate carries explicit
prerequisites and missing proof.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.models import GraphNodeRow
from ..core.enums import AssertionLevel
from ..core.schemas import GraphEdge, GraphNode
from .graph import GraphPersistenceService


@dataclass(frozen=True, slots=True)
class PathPrerequisite:
    key: str
    status: str
    detail: str
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CandidateAttackPath:
    id: str
    investigation_id: str
    component_node_id: str
    sink_node_id: str
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    prerequisites: tuple[PathPrerequisite, ...]
    missing_proof: tuple[str, ...]
    graph_node_id: str


@dataclass(frozen=True, slots=True)
class AttackPathBuildResult:
    investigation_id: str
    candidates: tuple[CandidateAttackPath, ...]
    graph_nodes: int
    graph_edges: int
    limitations: tuple[str, ...]


class CandidateAttackPathService:
    """Build bounded shortest candidate paths from component entry to sink nodes."""

    def __init__(
        self, session: Session, *, max_depth: int = 16, max_paths: int = 50
    ) -> None:
        if max_depth < 1 or max_paths < 1:
            raise ValueError("path limits must be positive")
        self.session = session
        self.persistence = GraphPersistenceService(session)
        self.max_depth = max_depth
        self.max_paths = max_paths

    def build(self, investigation_id: str) -> AttackPathBuildResult:
        graph = self.persistence.get_graph(investigation_id)
        nodes = {node.id: node for node in graph.nodes}
        outgoing: dict[str, list[GraphEdge]] = {}
        for edge in graph.edges:
            if edge.assertion is AssertionLevel.REJECTED:
                continue
            outgoing.setdefault(edge.source_id, []).append(edge)
        for edges in outgoing.values():
            edges.sort(key=lambda item: (item.relation, item.target_id, item.id))

        candidates: list[CandidateAttackPath] = []
        for component in sorted(
            (node for node in graph.nodes if node.node_type == "component"),
            key=lambda item: (item.ref or "", item.id),
        ):
            # A candidate attack path starts at an externally reachable component. If the
            # manifest has not established export, do not manufacture an external entry.
            if (component.attributes or {}).get("exported") is not True:
                continue
            entries = [
                edge for edge in outgoing.get(component.id, ())
                if edge.relation == "enters_method"
                and nodes.get(edge.target_id) is not None
                and nodes[edge.target_id].node_type == "method"
            ]
            best_by_sink: dict[str, tuple[list[str], list[GraphEdge]]] = {}
            for entry in entries:
                queue: list[tuple[str, list[str], list[GraphEdge]]] = [
                    (entry.target_id, [component.id, entry.target_id], [entry])
                ]
                while queue:
                    current, path_nodes, path_edges = queue.pop(0)
                    if len(path_edges) > self.max_depth:
                        continue
                    for edge in outgoing.get(current, ()):
                        target = nodes.get(edge.target_id)
                        if edge.relation == "reaches_sink" and target and target.node_type == "sink":
                            candidate_nodes = path_nodes + [target.id]
                            candidate_edges = path_edges + [edge]
                            previous = best_by_sink.get(target.id)
                            candidate_key = (len(candidate_edges), tuple(e.id for e in candidate_edges))
                            previous_key = (
                                (len(previous[1]), tuple(e.id for e in previous[1]))
                                if previous else None
                            )
                            if previous is None or candidate_key < previous_key:
                                best_by_sink[target.id] = (candidate_nodes, candidate_edges)
                        elif (
                            edge.relation == "calls"
                            and target is not None
                            and target.node_type == "method"
                            and target.id not in path_nodes
                            and len(path_edges) < self.max_depth
                        ):
                            queue.append((
                                target.id, path_nodes + [target.id], path_edges + [edge]
                            ))
            for sink_id, (path_nodes, path_edges) in sorted(best_by_sink.items()):
                candidates.append(self._persist_candidate(
                    investigation_id, component, sink_id, path_nodes, path_edges,
                    graph.nodes, graph.edges,
                ))
                if len(candidates) >= self.max_paths:
                    break
            if len(candidates) >= self.max_paths:
                break

        self.session.flush()
        updated = self.persistence.get_graph(investigation_id)
        limitations = (
            "A candidate path is a hypothesis, not a confirmed vulnerability or exploitability verdict.",
            "Static call reachability does not establish attacker-controlled taint flow, guard correctness, or runtime execution.",
            "Safe PoC execution and a negative control are separate required proof steps.",
        )
        return AttackPathBuildResult(
            investigation_id=investigation_id,
            candidates=tuple(candidates),
            graph_nodes=len(updated.nodes),
            graph_edges=len(updated.edges),
            limitations=limitations,
        )

    def _persist_candidate(
        self,
        investigation_id: str,
        component: GraphNode,
        sink_id: str,
        path_nodes: list[str],
        path_edges: list[GraphEdge],
        all_nodes: tuple[GraphNode, ...],
        all_edges: tuple[GraphEdge, ...],
    ) -> CandidateAttackPath:
        node_by_id = {node.id: node for node in all_nodes}
        sink = node_by_id[sink_id]
        path_methods = set(path_nodes) & {
            node.id for node in all_nodes if node.node_type == "method"
        }
        source_edges = [
            edge for edge in all_edges
            if edge.relation == "flows_to" and edge.target_id in path_methods
            and node_by_id.get(edge.source_id) is not None
            and node_by_id[edge.source_id].node_type == "data_source"
        ]
        guard_edges = [
            edge for edge in all_edges
            if edge.relation == "guard_on_path" and edge.source_id == component.id
        ]
        permission_edges = [
            edge for edge in all_edges
            if edge.relation == "requires_permission" and edge.source_id == component.id
        ]
        evidence_refs = tuple(sorted({
            ref for edge in path_edges for ref in edge.evidence_refs
        } | {
            ref for edge in source_edges + guard_edges + permission_edges
            for ref in edge.evidence_refs
        }))

        prerequisites: list[PathPrerequisite] = [
            PathPrerequisite(
                "exported_component", "satisfied",
                "RECON evidence marks the entry component as exported.",
                tuple(sorted(set(component.evidence_refs))),
            ),
            PathPrerequisite(
                "static_call_path", "satisfied",
                "Persisted graph contains an entry-method edge and a connected method path.",
                evidence_refs,
            ),
            PathPrerequisite(
                "sink_reference", "satisfied",
                f"Persisted graph links the path to sink {sink.ref or sink.label}.",
                evidence_refs,
            ),
        ]
        missing: list[str] = []
        if source_edges:
            prerequisites.append(PathPrerequisite(
                "data_source_observed", "partial",
                "A persisted data-source observation links to a method on this path; "
                "attacker control and propagation are not established.",
                tuple(sorted({ref for edge in source_edges for ref in edge.evidence_refs})),
            ))
        else:
            prerequisites.append(PathPrerequisite(
                "data_source_observed", "missing",
                "No persisted data-source edge enters a method on this candidate path.",
            ))
            missing.append("Identify an attacker-controlled data source and link it to this path.")
        prerequisites.append(PathPrerequisite(
            "taint_propagation", "missing",
            "No bounded CFG/data-flow analysis proves that source data reaches the sink.",
        ))
        missing.append("Prove source-to-sink taint propagation with guard ordering considered.")
        if guard_edges:
            prerequisites.append(PathPrerequisite(
                "guard_semantics", "unknown",
                "A guard is recorded on the component path; its correctness, order and enforcement are unverified.",
                tuple(sorted({ref for edge in guard_edges for ref in edge.evidence_refs})),
            ))
            missing.append("Validate guard correctness, ordering and enforcement; do not assume a guard is effective.")
        elif permission_edges:
            prerequisites.append(PathPrerequisite(
                "permission_enforcement", "unknown",
                "A manifest permission is declared, but runtime enforcement and call-site coverage are unverified.",
                tuple(sorted({ref for edge in permission_edges for ref in edge.evidence_refs})),
            ))
            missing.append("Verify the declared permission is enforced on every relevant path.")
        else:
            prerequisites.append(PathPrerequisite(
                "permission_boundary", "observed_absent",
                "No manifest permission relation is recorded for this component.",
                tuple(sorted(set(component.evidence_refs))),
            ))
        prerequisites.append(PathPrerequisite(
            "runtime_reproduction", "missing",
            "No safe PoC execution and negative control are attached to this candidate.",
        ))
        missing.append("Reproduce safely in the controlled lab and run a negative control.")

        fingerprint_source = "|".join(
            [investigation_id, component.id, sink_id, *[edge.id for edge in path_edges]]
        )
        fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()
        path_ref = f"d032:{fingerprint}"
        existing = self.session.execute(
            select(GraphNodeRow).where(
                GraphNodeRow.investigation_id == investigation_id,
                GraphNodeRow.node_type == "candidate_path",
                GraphNodeRow.ref == path_ref,
            )
        ).scalar_one_or_none()
        path_fields = {
            "investigation_id": investigation_id,
            "node_type": "candidate_path",
            "label": f"Candidate path: {component.label} → {sink.label}"[:1000],
            "ref": path_ref,
            "assertion": AssertionLevel.HYPOTHESIS,
            "attributes": {
                "status": "candidate",
                "component_node_id": component.id,
                "sink_node_id": sink_id,
                "ordered_node_ids": path_nodes,
                "ordered_edge_ids": [edge.id for edge in path_edges],
                "prerequisites": [
                    {"key": item.key, "status": item.status, "detail": item.detail}
                    for item in prerequisites
                ],
                "missing_proof": missing,
                "not_an_exploitability_verdict": True,
            },
            "evidence_refs": evidence_refs,
        }
        if existing is not None:
            path_fields["id"] = existing.id
        path_node = GraphNode(**path_fields)
        persisted_path = self.persistence.add_node(path_node)
        for index, node_id in enumerate(path_nodes):
            step_evidence = tuple(sorted({
                ref for edge in path_edges
                if edge.source_id == node_id or edge.target_id == node_id
                for ref in edge.evidence_refs
            }))
            self.persistence.add_edge(GraphEdge(
                investigation_id=investigation_id,
                source_id=persisted_path.id,
                target_id=node_id,
                relation="includes_step",
                assertion=AssertionLevel.HYPOTHESIS,
                rationale=f"Ordered candidate-path step {index + 1}; this is not proof of exploitability.",
                evidence_refs=step_evidence,
            ))
        return CandidateAttackPath(
            id=fingerprint,
            investigation_id=investigation_id,
            component_node_id=component.id,
            sink_node_id=sink_id,
            node_ids=tuple(path_nodes),
            edge_ids=tuple(edge.id for edge in path_edges),
            prerequisites=tuple(prerequisites),
            missing_proof=tuple(missing),
            graph_node_id=persisted_path.id,
        )
