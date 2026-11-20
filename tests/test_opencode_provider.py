"""Unit tests for the eval-only OpenCode CLI adapter (no CLI, no network)."""

from __future__ import annotations

import json

from mobius.services.model_provider import _model_tag, parse_ndjson_events


def _text_event(text: str) -> str:
    return json.dumps({"type": "text", "part": {"type": "text", "text": text}})


def _finish_event(input_tokens: int, output_tokens: int) -> str:
    return json.dumps({
        "type": "step_finish",
        "part": {"type": "step-finish",
                 "tokens": {"input": input_tokens, "output": output_tokens}},
    })


def test_model_tag_adds_provider_prefix():
    assert _model_tag("deepseek-v4.1-flash-free") == "opencode/deepseek-v4.1-flash-free"
    assert _model_tag("opencode/big-pickle") == "opencode/big-pickle"


def test_parse_concatenates_text_parts_and_sums_tokens():
    stdout = "\n".join([
        json.dumps({"type": "step_start", "part": {"type": "step-start"}}),
        _text_event('{"a":'),
        _text_event(" 1}"),
        _finish_event(100, 5),
        _finish_event(40, 3),
    ])
    content, input_tokens, output_tokens = parse_ndjson_events(stdout)
    assert content == '{"a": 1}'
    assert input_tokens == 140
    assert output_tokens == 8


def test_parse_ignores_non_json_lines_and_missing_tokens():
    stdout = "garbage line\n" + _text_event("hi")
    content, input_tokens, output_tokens = parse_ndjson_events(stdout)
    assert content == "hi"
    assert input_tokens is None
    assert output_tokens is None


GOOD = '{"disposition":"insufficient_evidence","summary":"only one observation supplied","challenges":[]}'


def test_normalization_accepts_exact_fenced_and_prose_wrapped_single_object():
    from mobius.services.model_provider import normalize_structured_reply
    from mobius.services.veritas import VeritasReviewReply

    norm = normalize_structured_reply('  ' + GOOD + '\n', VeritasReviewReply)
    assert norm.status == "valid" and norm.method == "exact"

    fenced = normalize_structured_reply('```json\n' + GOOD + '\n```', VeritasReviewReply)
    assert fenced.status == "valid" and fenced.method == "fenced"

    wrapped = normalize_structured_reply('Here is my review:\n' + GOOD + '\nEnd of review.', VeritasReviewReply)
    assert wrapped.status == "valid" and wrapped.method == "extracted"
    assert wrapped.data.disposition == "insufficient_evidence"


def test_normalization_collapses_identical_duplicate_payloads():
    from mobius.services.model_provider import normalize_structured_reply
    from mobius.services.veritas import VeritasReviewReply

    norm = normalize_structured_reply(GOOD + '\n' + GOOD, VeritasReviewReply)
    assert norm.status == "valid" and norm.method == "extracted_duplicate"


def test_normalization_refuses_conflicting_or_absent_payloads():
    from mobius.services.model_provider import normalize_structured_reply
    from mobius.services.veritas import VeritasReviewReply

    conflicting = (
        '{"disposition":"challenge","summary":"a long enough summary here","challenges":[]}'
        '\n{"disposition":"no_material_challenge","summary":"a contradictory second verdict","challenges":[]}'
    )
    norm = normalize_structured_reply(conflicting, VeritasReviewReply)
    assert norm.status == "unconvertible" and norm.reason == "multiple_conflicting_payloads"

    for bad in ('plain prose with no json at all', '{"disposition":"challenge"'):
        norm = normalize_structured_reply(bad, VeritasReviewReply)
        assert norm.status == "unconvertible" and norm.reason == "no_json_payload", (bad, norm.reason)


def test_normalization_drops_undeclared_fields_and_records_them():
    from mobius.services.model_provider import normalize_structured_reply
    from mobius.services.veritas import VeritasReviewReply

    reply = (
        '{"disposition":"challenge","summary":"evidence does not establish the claimed flow",'
        '"challenges":[{"challenge_type":"unsupported_claim","title":"decorative",'
        '"statement":"the supplied evidence does not show the component is exported",'
        '"evidence_refs":["ev1"],"requested_proof":"persisted manifest evidence"}]}'
    )
    norm = normalize_structured_reply(reply, VeritasReviewReply)
    assert norm.status == "valid"
    assert norm.dropped_fields == ("challenges.0.title",)


def test_normalization_never_invents_missing_required_fields():
    from mobius.services.model_provider import normalize_structured_reply
    from mobius.services.veritas import VeritasReviewReply

    norm = normalize_structured_reply('{"disposition":"insufficient_evidence","challenges":[]}', VeritasReviewReply)
    assert norm.status == "unconvertible"
    assert norm.reason and norm.reason.startswith("schema_violation:summary")


def test_compose_prompt_measures_json_escaping_growth_at_real_scale():
    """Regression for the Allsafe failure: the composed wire envelope grows with
    payload escaping (newlines/quotes) and exceeds the legacy fixed-margin
    estimate; the reservation must measure the composed bytes."""
    from mobius.services.model_provider import OpenCodeCliProvider

    system = "Return JSON only."
    user = 'private void f() {\n    Log.d("k", "v");\n}\n' * 700  # ~28KB multiline
    schema = {"type": "object", "properties": {"x": {"type": "string"}}}

    composed = OpenCodeCliProvider.compose_prompt(
        system_prompt=system, user_payload={"input": user}, response_schema=schema
    )
    envelope = len(composed.encode("utf-8"))
    legacy_estimate = (
        len(system.encode("utf-8"))
        + len(user.encode("utf-8"))
        + len(json.dumps(schema, separators=(",", ":")).encode("utf-8"))
        + 1024
    )
    assert envelope > legacy_estimate
    assert json.dumps({"input": user}) in composed


def test_complete_json_populates_provider_reported_usage(monkeypatch, tmp_path):
    """The adapter keeps conservative accounting units and the CLI's real
    token report as distinct fields on the result."""
    import subprocess as sp
    from mobius.services.model_provider import OpenCodeCliProvider

    ndjson = "\n".join([
        _text_event('{"a": 1}'),
        _finish_event(13000, 200),
        _finish_event(463, 33),
    ])

    def fake_run(args, **kwargs):
        return sp.CompletedProcess(args, 0, stdout=ndjson, stderr="")

    monkeypatch.setattr(sp, "run", fake_run)
    provider = OpenCodeCliProvider(binary="/bin/true")
    result = provider.complete_json(
        model="deepseek-v4.1-flash-free", system_prompt="sys",
        user_payload={"input": "payload with\nnewlines"},
        response_schema={"type": "object"}, max_tokens=2048,
    )
    # Accounting units: composed-envelope bytes and CLI output sum.
    assert result.prompt_tokens == len(
        provider.compose_prompt(
            system_prompt="sys", user_payload={"input": "payload with\nnewlines"},
            response_schema={"type": "object"},
        ).encode("utf-8")
    )
    assert result.completion_tokens == 233
    # Provider-reported real usage, distinctly named.
    assert result.provider_prompt_tokens == 13463
    assert result.provider_completion_tokens == 233
