"""Unit tests for the eval-only OpenCode CLI adapter (no CLI, no network)."""

from __future__ import annotations

import json

from mobius.tools.opencode_provider import _model_tag, parse_ndjson_events


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
