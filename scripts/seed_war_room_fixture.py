"""Seed a deterministic, explicitly synthetic War Room fixture for CI browser tests."""
from __future__ import annotations

import json
import sys

from sqlalchemy import select

from mobius.adapters.events import SqlEventStore, utcnow
from mobius.adapters.models import DecisionRow, EvidenceRow, HypothesisRow, InvestigationRow, ObservationRow
from mobius.api.config import Settings
from mobius.api.deps import AppContext
from mobius.core.enums import Fidelity, ObservationKind
from mobius.core.ids import IdPrefix, new_id


def main(scan_id: str) -> None:
    context = AppContext(Settings.from_env(), create_schema=False)
    session = context.session()
    try:
        scan = session.get(InvestigationRow, scan_id)
        if scan is None:
            raise SystemExit(f"unknown investigation: {scan_id}")
        evidence = session.execute(
            select(EvidenceRow).where(EvidenceRow.investigation_id == scan_id)
            .order_by(EvidenceRow.created_at.desc())
        ).scalars().first()
        if evidence is None:
            raise SystemExit("seed requires at least one persisted evidence record")
        observation_id = new_id(IdPrefix.OBSERVATION)
        observation = ObservationRow(
            id=observation_id, investigation_id=scan_id, agent="FIXTURE",
            kind=ObservationKind.FACT.value, fidelity=Fidelity.BINARY_XML.value,
            subject_type="component", subject_ref="com.example.lab.MainActivity",
            statement="Synthetic fixture observation: exported activity declaration is represented for UI and graph integration tests.",
            attributes={"exported": True, "fixture_only": True, "permission": None},
            maswe=["MASWE-0029"], confidence=1.0, evidence_refs=[evidence.id],
            created_at=utcnow(),
        )
        session.add(observation)
        session.flush()
        hypothesis_id = new_id(IdPrefix.HYPOTHESIS)
        hypothesis = HypothesisRow(
            id=hypothesis_id, investigation_id=scan_id,
            claim="Fixture-only hypothesis: exported activity may expose an unguarded entry point.",
            maswe=["MASWE-0029"], derived_from=[observation_id],
            required_evidence=["exported", "permission", "caller_check_absent", "sink_reachable"],
            satisfied_evidence=["exported", "permission"], status="open",
            priority=0.75, depth=0, parent_id=None, created_at=utcnow(),
        )
        session.add(hypothesis)
        decisions = [
            DecisionRow(
                id=new_id(IdPrefix.DECISION), investigation_id=scan_id,
                agent="NEXUS", action="enumerate_entrypoints",
                action_args={"package": "com.example.lab"},
                considered_evidence=[evidence.id],
                alternatives=[{"action": "stop", "reason": "scope"}],
                expected_outcome="Entry points are enumerated from the persisted manifest.",
                uncertainty=None, prompt_version="v1",
                model_id=None, provider=None, created_at=utcnow(),
            ),
            DecisionRow(
                id=new_id(IdPrefix.DECISION), investigation_id=scan_id,
                agent="VERITAS", action="review_finding",
                action_args={"finding_id": "fnd_fixture", "producer_model_id": "fixture-producer",
                             "producer_model_verified": False, "advisory_only": True},
                considered_evidence=[evidence.id],
                alternatives=[],
                expected_outcome="Independently challenge the finding using only persisted evidence; never alter the deterministic verdict.",
                uncertainty="Fixture review summary: evidence supports the gate verdict.",
                prompt_version="veritas-independent-review-v1",
                model_id="fixture-reviewer", provider="mock", model_role="reasoning",
                requested_model="fixture-reviewer",
                system_prompt_sha256="a" * 64, input_sha256="b" * 64,
                schema_sha256="c" * 64, response_sha256="d" * 64,
                schema_name="VeritasReviewReply",
                output_json={"disposition": "no_material_challenge",
                             "summary": "Fixture review summary.",
                             "challenges": []},
                input_tokens=30, output_tokens=20, latency_ms=42,
                temperature=0.0, max_tokens=1200, created_at=utcnow(),
            ),
        ]
        for decision in decisions:
            session.add(decision)
        SqlEventStore(session).emit(
            scan_id, "fixture_hypothesis_seeded",
            {"hypothesis_id": hypothesis_id, "observation_id": observation_id,
             "evidence_id": evidence.id, "fixture_only": True},
            actor="FIXTURE",
        )
        session.commit()
        print(json.dumps({"hypothesis_id": hypothesis_id, "observation_id": observation_id,
                          "evidence_id": evidence.id}))
    finally:
        session.close()
        context.engine.dispose()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: seed_war_room_fixture.py <investigation_id>")
    main(sys.argv[1])
