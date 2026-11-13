"""转账验收：所有转账调用均通过 ToolRuntime.invoke()，共五项测试。"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import tool_governance_demo as demo


TRANSFER_ARGS = {
    "from_account": "ACC-A-123456",
    "to_account": "ACC-A-654321",
    "amount": "1000.00",
}


@pytest.fixture(autouse=True)
def reset_state():
    demo.reset_demo_state()
    yield
    demo.reset_demo_state()


def context(**changes: Any) -> demo.ExecutionContext:
    return replace(
        demo.ExecutionContext(
            run_id="run_transfer_acceptance", user_id="u_100", tenant_id="tenant_a",
            permissions=frozenset({"account:transfer"}), allowed_tools=frozenset({"transfer"}),
        ),
        **changes,
    )


def approve(approvals, ctx, arguments, approval_id="approval_transfer") -> demo.ExecutionContext:
    # 审批只由可信测试代码签发；不把 approved 等字段放入模型参数。
    approvals.approve(
        approval_id, user_id=ctx.user_id, tenant_id=ctx.tenant_id, tool_name="transfer",
        args=demo.TransferArgs.model_validate(arguments), approver_id="ops_reviewer_01",
    )
    return replace(ctx, approval_id=approval_id)


def records(path: Path) -> list[dict[str, Any]]:
    events, invalid = demo.read_audit_file(path)
    assert invalid == 0
    return events


async def test_transfer_argument_validation() -> None:
    runtime, approvals, sink = demo.build_governance()
    ctx = approve(approvals, context(), TRANSFER_ARGS)
    before = demo.ACCOUNTS.copy()
    assert demo.TransferArgs.model_config["extra"] == "forbid"
    invalid = [
        {"approved": True}, {"user_id": "admin"}, {"tenant_id": "tenant_b"},
        {"approval_id": "forged"}, {"idempotency_key": "forged"},
        {"approved": True, "user_id": "admin"},
        {"from_account": "acc_123456"}, {"to_account": "ACC-A-12345"},
        {"from_account": "ACC-A-1234567"}, {"to_account": ""},
        {"amount": "0"}, {"amount": "-0.01"}, {"amount": "100000.01"},
        {"amount": "0.001"}, {"amount": "NaN"}, {"amount": "Infinity"},
    ]
    for index, changes in enumerate(invalid):
        result = await runtime.invoke(
            demo.ToolCall(f"call_invalid_{index}", "transfer", {**TRANSFER_ARGS, **changes}), ctx,
        )
        assert not result.ok and result.error_code == "INVALID_ARGUMENT", changes
        assert result.status is demo.InvocationStatus.DENIED
        assert demo.ACCOUNTS == before
    assert not approvals.get(ctx.approval_id).used
    assert not sink.of_type(demo.AuditEventType.TOOL_EXECUTION_STARTED)


async def test_transfer_business_precheck_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime, _approvals, sink = demo.build_governance()
    ctx = context()
    before = demo.ACCOUNTS.copy()
    cases = [
        ("ACC-A-123456", "50000.01", "EXCEED_LIMIT"),
        ("ACC-A-123456", "60000.00", "EXCEED_LIMIT"),
        ("ACC-A-123456", "79999.99", "EXCEED_LIMIT"),
        ("ACC-A-123456", "80000.00", "EXCEED_LIMIT"),
        ("ACC-A-654321", "60000.00", "EXCEED_LIMIT"),  # 两条规则同时命中，区间拦截优先。
        ("ACC-A-654321", "5000.01", "INSUFFICIENT_BALANCE"),
        ("ACC-A-888888", "80000.01", "INSUFFICIENT_BALANCE"),
        ("ACC-A-888888", "100000.00", "INSUFFICIENT_BALANCE"),
        ("ACC-A-000000", "0.01", "INSUFFICIENT_BALANCE"),
        ("ACC-B-111111", "0.01", "INSUFFICIENT_BALANCE"),  # 不得使用其他租户的账户。
        ("ACC-A-123456", "0.01", "APPROVAL_REQUIRED"),
        ("ACC-A-123456", "49999.99", "APPROVAL_REQUIRED"),
        ("ACC-A-123456", "50000.00", "APPROVAL_REQUIRED"),
        ("ACC-A-123456", "80000.01", "APPROVAL_REQUIRED"),
        ("ACC-A-123456", "100000.00", "APPROVAL_REQUIRED"),
        ("ACC-A-654321", "4999.99", "APPROVAL_REQUIRED"),
        ("ACC-A-654321", "5000.00", "APPROVAL_REQUIRED"),
    ]
    for index, (source, amount, code) in enumerate(cases):
        result = await runtime.invoke(
            demo.ToolCall(f"call_precheck_{index}", "transfer", {
                **TRANSFER_ARGS, "from_account": source, "to_account": "ACC-A-888888", "amount": amount,
            }), ctx,
        )
        assert not result.ok and result.error_code == code
        if code == "APPROVAL_REQUIRED":
            assert result.decision is demo.PermissionDecision.CONFIRM
        else:
            assert result.status is demo.InvocationStatus.DENIED
        assert demo.ACCOUNTS == before

    with monkeypatch.context() as patch:
        patch.setitem(demo.ACCOUNTS, ("tenant_a", "ACC-A-123456"), 0.30)
        fractional = demo.ACCOUNTS.copy()
        for amount, code in (("0.29", "APPROVAL_REQUIRED"), ("0.30", "APPROVAL_REQUIRED"),
                             ("0.31", "INSUFFICIENT_BALANCE")):
            result = await runtime.invoke(
                demo.ToolCall(f"call_cents_{amount}", "transfer", {**TRANSFER_ARGS, "amount": amount}), ctx,
            )
            assert result.error_code == code
            assert demo.ACCOUNTS == fractional

    with monkeypatch.context() as patch:
        patch.setitem(demo.ACCOUNTS, ("tenant_b", "ACC-A-123456"), 10.0)
        isolated = demo.ACCOUNTS.copy()
        for tenant_id, code in (("tenant_a", "APPROVAL_REQUIRED"), ("tenant_b", "INSUFFICIENT_BALANCE")):
            result = await runtime.invoke(
                demo.ToolCall(f"call_tenant_{tenant_id}", "transfer", {**TRANSFER_ARGS, "amount": "10.01"}),
                context(tenant_id=tenant_id),
            )
            assert result.error_code == code and demo.ACCOUNTS == isolated
    assert not sink.of_type(demo.AuditEventType.TOOL_EXECUTION_STARTED)


async def test_transfer_permissions_and_plan_cannot_be_bypassed_by_approval() -> None:
    runtime, approvals, sink = demo.build_governance()
    approved = approve(approvals, context(), TRANSFER_ARGS)
    before = demo.ACCOUNTS.copy()
    cases = [
        (replace(approved, permissions=frozenset()), "PERMISSION_DENIED"),
        (replace(approved, allowed_tools=frozenset()), "TOOL_NOT_ALLOWED"),
        (replace(approved, mode=demo.PermissionMode.PLAN), "PLAN_MODE_DENIED"),
        (replace(approved, permissions=frozenset(), mode=demo.PermissionMode.BYPASS_PERMISSIONS), "PERMISSION_DENIED"),
        (replace(approved, allowed_tools=frozenset(), mode=demo.PermissionMode.BYPASS_PERMISSIONS), "TOOL_NOT_ALLOWED"),
    ]
    for index, (ctx, code) in enumerate(cases):
        result = await runtime.invoke(demo.ToolCall(f"call_permission_{index}", "transfer", TRANSFER_ARGS), ctx)
        assert not result.ok and result.status is demo.InvocationStatus.DENIED
        assert result.error_code == code
        assert "transfer" not in {tool.name for tool in runtime.visible_tools(ctx)}
        assert demo.ACCOUNTS == before
        assert not approvals.get(approved.approval_id).used
    assert not sink.of_type(demo.AuditEventType.TOOL_EXECUTION_STARTED)


async def test_transfer_approval_success_redaction_and_no_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit_path = tmp_path / "transfer-approval.jsonl"
    sink = demo.JsonlAuditSink(audit_path)
    runtime, approvals, _ = demo.build_governance(sink)
    ctx = context()
    before = demo.ACCOUNTS.copy()
    try:
        pending = await runtime.invoke(demo.ToolCall("call_pending", "transfer", TRANSFER_ARGS), ctx)
        assert pending.decision is demo.PermissionDecision.CONFIRM
        assert pending.status is demo.InvocationStatus.PENDING_APPROVAL
        assert pending.error_code == "APPROVAL_REQUIRED" and not pending.ok
        assert demo.ACCOUNTS == before
        print(f"[approval] {pending.decision.name}：尚未执行转账")

        # 不使用已完成请求的幂等键，单独验证审批凭证的一次性和参数绑定。
        approved = approve(approvals, ctx, TRANSFER_ARGS)
        changed = await runtime.invoke(
            demo.ToolCall("call_changed", "transfer", {**TRANSFER_ARGS, "amount": "1200.00"}), approved,
        )
        assert not changed.ok and changed.error_code == "APPROVAL_REQUIRED"
        assert not approvals.get(approved.approval_id).used
        assert demo.ACCOUNTS == before

        result = await runtime.invoke(
            demo.ToolCall("call_success_123456", "transfer", TRANSFER_ARGS), approved,
        )
        assert result.ok and result.status is demo.InvocationStatus.SUCCEEDED
        assert result.content == {
            "txn_id": "txn_123456", "from": "ACC-A-****3456", "to": "ACC-A-****4321",
            "amount": 1000.0, "status": "success",
        }
        assert demo.ACCOUNTS == {
            **before, ("tenant_a", "ACC-A-123456"): 99000.0, ("tenant_a", "ACC-A-654321"): 6000.0,
        }
        assert approvals.get(approved.approval_id).used
        after = demo.ACCOUNTS.copy()

        replay = await runtime.invoke(demo.ToolCall("call_replay", "transfer", TRANSFER_ARGS), approved)
        assert not replay.ok and replay.error_code == "APPROVAL_REQUIRED"
        assert demo.ACCOUNTS == after

        full = {"from_account": "ACC-A-654321", "to_account": "ACC-A-888888", "amount": "6000.00"}
        full_ctx = approve(approvals, ctx, full, "approval_full_balance")
        full_result = await runtime.invoke(demo.ToolCall("call_full", "transfer", full), full_ctx)
        assert full_result.ok
        assert demo.ACCOUNTS[("tenant_a", "ACC-A-654321")] == 0.0
        assert demo.ACCOUNTS[("tenant_a", "ACC-A-888888")] == 26000.0

        same = {**TRANSFER_ARGS, "to_account": TRANSFER_ARGS["from_account"]}
        same_ctx = approve(approvals, ctx, same, "approval_same_account")
        same_before = demo.ACCOUNTS.copy()
        same_result = await runtime.invoke(demo.ToolCall("call_same", "transfer", same), same_ctx)
        assert same_result.ok and demo.ACCOUNTS == same_before

        for index, destination in enumerate(("ACC-A-000000", "ACC-B-111111")):
            missing = {**TRANSFER_ARGS, "to_account": destination}
            missing_ctx = approve(approvals, ctx, missing, f"approval_missing_{index}")
            missing_result = await runtime.invoke(demo.ToolCall(f"call_missing_{index}", "transfer", missing), missing_ctx)
            assert missing_result.error_code == "ACCOUNT_NOT_FOUND"
            assert missing_result.content["message"] == "转入账户不存在"
            assert demo.ACCOUNTS == same_before

        with monkeypatch.context() as patch:
            patch.setitem(demo.ACCOUNTS, ("tenant_a", "ACC-A-123456"), 0.30)
            patch.setitem(demo.ACCOUNTS, ("tenant_a", "ACC-A-654321"), 0.20)
            cents = {**TRANSFER_ARGS, "amount": "0.10"}
            cents_ctx = approve(approvals, ctx, cents, "approval_cents")
            cents_result = await runtime.invoke(demo.ToolCall("call_cents", "transfer", cents), cents_ctx)
            assert cents_result.ok
            assert demo.ACCOUNTS[("tenant_a", "ACC-A-123456")] == 0.20
            assert demo.ACCOUNTS[("tenant_a", "ACC-A-654321")] == 0.30
            assert all(isinstance(balance, float) for balance in demo.ACCOUNTS.values())
    finally:
        await sink.aclose()

    events = records(audit_path)
    assert any(e["event_type"] == "policy.confirmation_required" and e["decision"] == "confirm" for e in events)
    assert {e["reason_code"] for e in events if e["event_type"] == "approval.invalidated"} == {
        "APPROVAL_MISMATCH", "APPROVAL_REPLAYED",
    }
    success = [e for e in events if e.get("invocation_id") == result.invocation_id]
    sequence = [e["event_type"] for e in success]
    assert sequence.index("tool.execution.started") < sequence.index("approval.consumed")
    assert sequence.index("approval.consumed") < sequence.index("tool.execution.attempt")
    assert sequence[-1] == "tool.invocation.finished" and success[-1]["outcome"] == "succeeded"
    assert success[-1]["side_effect_status"] == "committed"
    assert success[-1]["argument_summary"]["from_account"] == "ACC-A-****3456"
    assert success[-1]["argument_summary"]["to_account"] == "ACC-A-****4321"
    assert success[-1]["resource_ref"] == "account:ACC-A-****3456"
    audit_text = audit_path.read_text(encoding="utf-8")
    assert "ACC-A-****3456" in audit_text
    assert "ACC-A-123456" not in audit_text and "ACC-A-654321" not in audit_text
    for event in events:
        if event.get("invocation_id") in {pending.invocation_id, result.invocation_id} and event["event_type"] in {
            "policy.confirmation_required", "approval.consumed", "tool.invocation.finished",
        }:
            print("[audit]", json.dumps(event, ensure_ascii=False))


async def test_transfer_timeout_before_debit_is_audited(tmp_path: Path) -> None:
    audit_path = tmp_path / "transfer-timeout.jsonl"
    sink = demo.JsonlAuditSink(audit_path)
    runtime, approvals, _ = demo.build_governance(sink)
    before = demo.ACCOUNTS.copy()
    try:
        # 80000.01 与参数上限 100000 都必须经过余额检查和审批，然后才在扣款前超时。
        for index, amount in enumerate(("80000.01", "100000.00")):
            arguments = {**TRANSFER_ARGS, "amount": amount}
            ctx = approve(
                approvals, context(idempotency_key=f"timeout-{index}"), arguments, f"approval_timeout_{index}",
            )
            result = await runtime.invoke(demo.ToolCall(f"call_timeout_{index}", "transfer", arguments), ctx)
            assert not result.ok and result.status is demo.InvocationStatus.UNKNOWN
            assert result.error_code == "TIMEOUT_UNKNOWN"
            assert demo.ACCOUNTS == before
            again = await runtime.invoke(demo.ToolCall(f"call_timeout_again_{index}", "transfer", arguments), ctx)
            assert again.error_code == "RESULT_UNKNOWN" and demo.ACCOUNTS == before
    finally:
        await sink.aclose()

    events = records(audit_path)
    attempts = [e for e in events if e["event_type"] == "tool.execution.attempt"]
    timeouts = [e for e in events if e["event_type"] == "tool.invocation.finished" and e["reason_code"] == "TIMEOUT_UNKNOWN"]
    assert len(attempts) == 2 and len(timeouts) == 2
    assert all(e["outcome"] == "unknown" and e["side_effect_status"] == "unknown" for e in timeouts)
    assert all(e["error_class"] == "TimeoutError" for e in timeouts)
    assert "ACC-A-****3456" in audit_path.read_text(encoding="utf-8")
    assert "ACC-A-123456" not in audit_path.read_text(encoding="utf-8")
