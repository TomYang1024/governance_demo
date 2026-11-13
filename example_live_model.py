"""真实模型只读示例：模型提议 get_order → 治理执行 → 结果回传 → 模型回答。

运行：
    cp .env.example .env                    # 填入真实 API Key
    .venv/bin/python example_live_model.py --env-file .env

也可直接设置 DEEPSEEK_API_KEY 后运行。仅模型请求联网；订单为本地模拟数据。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from provider_sdk.observability import configure_logging

from tool_governance_demo import (
    AgentRunner,
    ExecutionContext,
    JsonlAuditSink,
    ModelConfigError,
    ProviderSDKModelClient,
    RunLimits,
    RunStatus,
    build_governance,
    create_sdk,
    load_env_file,
    report,
    reset_demo_state,
)


async def run_example(args: argparse.Namespace) -> int:
    reset_demo_state()
    # 同一个 SDK 实例贯穿多轮请求，退出时关闭连接；不使用 Fake 或 MockTransport。
    async with create_sdk() as sdk:
        model = ProviderSDKModelClient(sdk, args.provider, args.model)
        model.ensure_ready()  # 缺凭证、Provider 错误、工具能力不满足时直接报错。

        sink = JsonlAuditSink(args.audit_log)
        try:
            runtime, _approvals, _sink = build_governance(sink)
            runner = AgentRunner(
                model,
                runtime,
                limits=RunLimits(
                    max_turns=4,
                    max_tool_calls=3,
                    max_output_tokens=args.max_output_tokens,
                    model_timeout_seconds=60,
                    run_timeout_seconds=150,
                ),
            )
            # 权限由应用设置：模型只能看见和调用 get_order，不能提交退款。
            ctx = ExecutionContext(
                run_id="unassigned",  # runner.run() 会生成真正的 run_id。
                user_id="u_100",
                tenant_id="tenant_a",
                permissions=frozenset({"order:read"}),
                allowed_tools=frozenset({"get_order"}),
            )
            print(f"[live] provider={args.provider} model={args.model}")
            print("[prompt]", args.prompt)
            result = await runner.run(args.prompt, ctx)

            # 展示脱敏后的结构化结果，便于确认模型确实调用了工具。
            for tool in result.tool_results:
                print("[tool]", json.dumps(tool.to_model_payload(), ensure_ascii=False))
            code = report(result, simulated_model=False)
            if result.status is RunStatus.COMPLETED and not any(
                tool.tool_name == "get_order" and tool.ok for tool in result.tool_results
            ):
                print("[check] 本次没有成功调用 get_order，尚未验证工具闭环；请检查提示词或模型能力。",
                      file=sys.stderr)
                code = 4
        finally:
            await sink.aclose()  # 确保审计元数据写入 JSONL 文件。

    print(f"[audit] {sink.path}")
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description="真实模型只读示例（会产生模型 API 调用费用）")
    parser.add_argument("--env-file", help="显式加载 .env；已有环境变量优先")
    parser.add_argument("--provider", help="默认 GOVERNANCE_DEMO_PROVIDER 或 deepseek")
    parser.add_argument("--model", help="默认 GOVERNANCE_DEMO_MODEL 或 deepseek-flash")
    parser.add_argument("--prompt", default="请调用 get_order 工具查询订单 ord_1001 的状态和可退金额，然后用一句话回答。")
    parser.add_argument("--audit-log", default="audit_logs/live-example.jsonl")
    parser.add_argument("--max-output-tokens", type=int, default=4096, help="单次输出上限，包含模型的思考 token")
    args = parser.parse_args()

    logs = configure_logging(level="WARNING", service="governance-live-example", stream=sys.stderr)
    try:
        if args.env_file:
            load_env_file(args.env_file)
        # 先加载 .env 再取默认值，使 .env 中的 Provider / 模型选择也能生效。
        args.provider = args.provider or os.environ.get("GOVERNANCE_DEMO_PROVIDER") or "deepseek"
        args.model = args.model or os.environ.get("GOVERNANCE_DEMO_MODEL") or "deepseek-flash"
        return asyncio.run(run_example(args))
    except ModelConfigError as exc:
        print(f"[配置错误] {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"[配置错误] {type(exc).__name__}: {exc.filename or ''}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[取消] 已中断。", file=sys.stderr)
        return 130
    finally:
        logs.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
