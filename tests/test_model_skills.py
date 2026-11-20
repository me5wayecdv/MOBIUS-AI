"""Domain skills are actually injected into the stage prompts, with version bumps.

These tests pin the CONDITIONING, not model quality: a prompt change is not a
measured improvement until the acceptance harness measures a real model with it.
"""
from __future__ import annotations

from mobius.services import nexus_hypotheses, veritas
from mobius.services.model_skills import (
    NEXUS_HYPOTHESIS_SKILLS,
    SKILLS_VERSION,
    VERITAS_REVIEW_SKILLS,
)


def test_veritas_prompt_carries_the_review_skills():
    assert veritas.PROMPT_VERSION == "veritas-independent-review-v2"
    assert VERITAS_REVIEW_SKILLS in veritas._SYSTEM_PROMPT
    assert SKILLS_VERSION in veritas._SYSTEM_PROMPT
    # the catalogue families the build can evidence anchor the review guidance
    for token in ("MASWE-0029", "MASWE-0049", "exported-component-no-permission"):
        assert token in veritas._SYSTEM_PROMPT


def test_nexus_prompt_carries_the_hypothesis_skills():
    assert nexus_hypotheses.PROMPT_VERSION == "nexus-hypothesis-generation-v2"
    assert NEXUS_HYPOTHESIS_SKILLS in nexus_hypotheses._SYSTEM_PROMPT
    assert SKILLS_VERSION in nexus_hypotheses._SYSTEM_PROMPT


def test_both_prompts_carry_the_citation_discipline():
    """The measured 2026-11-19 failure mode (fabricated/wrong-kind citations)
    is addressed verbatim in both stage prompts."""
    for prompt in (veritas._SYSTEM_PROMPT, nexus_hypotheses._SYSTEM_PROMPT):
        assert "fabricated or wrong-kind citations" in prompt
        assert "Copy them" in prompt
        assert "may-flow evidence" in prompt


def test_skills_stay_bounded_for_token_budget():
    """Prompt bytes count toward the budget reservation ceiling; skills must not
    balloon the prompt (system + schema + payload share the reservation)."""
    assert len(VERITAS_REVIEW_SKILLS.encode("utf-8")) < 4096
    assert len(NEXUS_HYPOTHESIS_SKILLS.encode("utf-8")) < 4096
