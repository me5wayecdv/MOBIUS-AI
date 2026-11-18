from mobius.core.dataflow import (
    FlowBlock,
    FlowInstruction,
    MethodFlow,
    analyse_method,
)
from mobius.core.reachability import MethodRef

INTENT = "Landroid/content/Intent;"
WEBVIEW = "Landroid/webkit/WebView;"
CONTEXT = "Landroid/content/Context;"


def M(name="onCreate"):
    return MethodRef("com.example.Entry", name, "()V")


def source(offset=0, dest=2):
    return FlowInstruction(
        offset, "invoke-virtual", registers=(0, 1),
        invoke_class=INTENT, invoke_method="getStringExtra",
    )


def move_result(offset=4, dest=2):
    return FlowInstruction(offset, "move-result-object", registers=(dest,), dest=dest)


def sink(offset=6, value_register=2):
    return FlowInstruction(
        offset, "invoke-virtual", registers=(3, value_register),
        invoke_class=WEBVIEW, invoke_method="loadUrl",
    )


def test_tracks_intent_extra_through_move_to_webview_sink():
    flow = MethodFlow(M(), (
        FlowBlock(0, (source(), move_result(), sink()), ()),
    ), 0)

    result = analyse_method(flow)

    assert result.status == "flow-found"
    assert result.complete is True
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.source_id == "intent-string-extra"
    assert finding.sink_id == "webview-load"
    assert finding.source_offset == 0
    assert finding.sink_offset == 6
    assert finding.assertion == "may-flow"
    assert finding.guard_outcome_verified is False


def test_tracks_taint_across_cfg_blocks_and_move():
    flow = MethodFlow(M(), (
        FlowBlock(0, (source(), move_result()), (10,)),
        FlowBlock(10, (
            FlowInstruction(10, "move-object", registers=(4, 2), dest=4, uses=(2,)),
            sink(14, 4),
        ), ()),
    ), 0)

    result = analyse_method(flow)

    assert result.status == "flow-found"
    assert result.findings[0].sink_offset == 14


def test_guard_order_is_reported_but_never_proves_guard_outcome():
    guard = FlowInstruction(
        0, "invoke-virtual", registers=(0, 1),
        invoke_class=CONTEXT, invoke_method="checkCallingPermission",
    )
    flow = MethodFlow(M(), (
        FlowBlock(0, (guard, source(4), move_result(8), sink(10)), ()),
    ), 0)

    result = analyse_method(flow)
    finding = result.findings[0]
    assert finding.guard_ids_before == ("check-calling-permission",)
    assert finding.guard_dominates_sink is True
    assert finding.guard_outcome_verified is False


def test_guard_after_sink_is_not_reported_as_pre_sink_guard():
    flow = MethodFlow(M(), (
        FlowBlock(0, (
            source(), move_result(), sink(),
            FlowInstruction(10, "invoke-virtual", registers=(0, 1),
                            invoke_class=CONTEXT, invoke_method="checkCallingPermission"),
        ), ()),
    ), 0)

    finding = analyse_method(flow).findings[0]
    assert finding.guard_ids_before == ()
    assert finding.guard_ids_after == ("check-calling-permission",)
    assert finding.guard_dominates_sink is False


def test_no_flow_is_only_complete_inside_the_supported_method_scope():
    flow = MethodFlow(M(), (
        FlowBlock(0, (
            FlowInstruction(0, "const-string", registers=(2,), dest=2),
            sink(4, 2),
        ), ()),
    ), 0)

    result = analyse_method(flow)
    assert result.status == "no-flow"
    assert result.complete is True


def test_tainted_value_through_unsupported_operation_is_incomplete_not_negative():
    flow = MethodFlow(M(), (
        FlowBlock(0, (
            source(), move_result(),
            FlowInstruction(6, "iget-object", registers=(4, 2), dest=4, uses=(2,), unsupported=True),
            sink(10, 4),
        ), ()),
    ), 0)

    result = analyse_method(flow)
    assert result.status == "incomplete"
    assert result.complete is False
    assert result.findings == ()
    assert any("unsupported opcode" in item for item in result.limitations)


def test_block_budget_exhaustion_is_truncated():
    blocks = tuple(FlowBlock(i * 2, (), ((i + 1) * 2,) if i < 4 else ()) for i in range(5))
    result = analyse_method(MethodFlow(M(), blocks, 0), max_blocks=3)
    assert result.status == "truncated"
    assert result.complete is False


def test_unresolved_cfg_edge_is_incomplete():
    flow = MethodFlow(M(), (FlowBlock(0, (), (99,)),), 0)
    result = analyse_method(flow)
    assert result.status == "incomplete"
    assert result.complete is False



def test_tracks_intent_uri_through_to_string_to_webview_sink():
    flow = MethodFlow(M(), (
        FlowBlock(0, (
            FlowInstruction(
                0, "invoke-virtual", registers=(0,),
                invoke_class=INTENT, invoke_method="getData",
            ),
            FlowInstruction(4, "move-result-object", registers=(2,), dest=2),
            FlowInstruction(
                6, "invoke-virtual", registers=(2,),
                invoke_class="Landroid/net/Uri;", invoke_method="toString",
            ),
            FlowInstruction(10, "move-result-object", registers=(4,), dest=4),
            sink(12, 4),
        ), ()),
    ), 0)

    result = analyse_method(flow)

    assert result.status == "flow-found"
    assert result.findings[0].source_id == "intent-data"
    assert result.findings[0].sink_id == "webview-load"



def test_taint_reaches_sink_after_cfg_join_from_source_predecessor():
    flow = MethodFlow(M(), (
        FlowBlock(0, (), (10, 20)),
        FlowBlock(10, (source(), move_result()), (30,)),
        FlowBlock(20, (), (30,)),
        FlowBlock(30, (sink(30, 2),), ()),
    ), 0)

    result = analyse_method(flow)

    assert result.status == "flow-found"
    assert result.findings[0].sink_offset == 30


def test_taint_does_not_cross_between_unconnected_cfg_branches():
    flow = MethodFlow(M(), (
        FlowBlock(0, (), (10, 20)),
        FlowBlock(10, (source(), move_result()), ()),
        FlowBlock(20, (sink(20, 2),), ()),
    ), 0)

    result = analyse_method(flow)

    assert result.status == "no-flow"
    assert result.findings == ()
    assert result.complete is True



def test_exception_edge_coverage_gap_cannot_be_reported_as_no_flow():
    flow = MethodFlow(M(), (
        FlowBlock(0, (FlowInstruction(0, "const-string", registers=(2,), dest=2),), ()),
    ), 0, complete=False)

    result = analyse_method(flow)

    assert result.status == "incomplete"
    assert result.complete is False
    assert any("exception edges" in item for item in result.limitations)



def test_string_builder_receiver_taint_survives_subsequent_clean_append():
    flow = MethodFlow(M(), (
        FlowBlock(0, (
            source(),
            move_result(),
            FlowInstruction(6, "invoke-virtual", registers=(3, 2),
                            invoke_class="Ljava/lang/StringBuilder;", invoke_method="append"),
            FlowInstruction(10, "move-result-object", registers=(4,), dest=4),
            FlowInstruction(12, "const-string", registers=(5,), dest=5),
            FlowInstruction(14, "invoke-virtual", registers=(4, 5),
                            invoke_class="Ljava/lang/StringBuilder;", invoke_method="append"),
            FlowInstruction(18, "move-result-object", registers=(6,), dest=6),
            FlowInstruction(20, "invoke-virtual", registers=(6,),
                            invoke_class="Ljava/lang/StringBuilder;", invoke_method="toString"),
            FlowInstruction(24, "move-result-object", registers=(7,), dest=7),
            sink(26, 7),
        ), ()),
    ), 0)

    result = analyse_method(flow)

    assert result.status == "flow-found"
    assert result.findings[0].sink_offset == 26
