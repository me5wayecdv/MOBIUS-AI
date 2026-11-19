"""Real-DEX controls for the bounded data-flow analysis (D-015).

FlowTest.dex is hand-assembled in memory by fixtures/dex/build_flow_dex.py (no compiler
dependency). Its decoding was cross-checked with an independent decompiler
(JADX) and with valid Adler32/SHA-1 header fields. The results remain
may-flow only, intra-procedural, and say nothing about attacker control.
"""
import importlib.util
import pathlib

import pytest

from mobius.adapters.dex import index_dex

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "dex"


def _flow_dex() -> bytes:
    spec = importlib.util.spec_from_file_location(
        "build_flow_dex", FIXTURES / "build_flow_dex.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build()


@pytest.fixture(scope="module")
def flows():
    index = index_dex(_flow_dex())
    return index, {finding.method.name: finding for finding in index.data_flows}


def test_straight_line_intent_extra_reaches_webview_with_real_offsets(flows):
    _, by_method = flows
    flow = by_method["positive"]
    assert (flow.source_id, flow.sink_id) == (
        "intent-string-extra",
        "webview-load",
    )
    assert (flow.source_offset, flow.sink_offset) == (4, 12)
    assert flow.assertion == "may-flow"


def test_branch_join_keeps_may_flow_with_offsets_across_blocks(flows):
    _, by_method = flows
    flow = by_method["branching"]
    assert (flow.source_offset, flow.sink_offset) == (8, 16)
    assert flow.assertion == "may-flow"
    assert flow.guard_outcome_verified is False


def test_negative_controls_report_no_finding(flows):
    _, by_method = flows
    assert "negative" not in by_method
    assert "negative_branch" not in by_method


def test_real_dex_flow_run_is_complete_and_bounded(flows):
    index, by_method = flows
    assert set(by_method) == {"positive", "branching"}
    assert index.data_flow_complete is True
    assert index.data_flow_truncated_methods == 0
    assert index.data_flow_limitations == ()


def test_real_cfg_branch_has_two_successors_and_a_join():
    from androguard.core.dex import DEX
    from mobius.adapters.dex import _build_method_flow

    vm = DEX(_flow_dex())
    method = next(
        method
        for cls in vm.get_classes()
        for method in cls.get_methods()
        if method.get_name() == "branching"
    )
    flow = _build_method_flow(vm, method)
    starts = [block.start for block in flow.blocks]
    assert starts == [0, 8, 16]
    by_start = {block.start: block for block in flow.blocks}
    assert by_start[0].successors == (8, 16)
    assert by_start[8].successors == (16,)
    assert by_start[16].successors == ()
