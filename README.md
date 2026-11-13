# governance_demo：工具调用、权限治理与人工审批

一个 Python 教学项目：模型提出工具调用，由 `ToolRuntime` 统一执行参数校验、权限检查、业务预检、人工审批、超时处理、幂等控制、结果脱敏和审计记录。

- **本地测试**：通过 `runtime.invoke()` 调用工具，或使用确定性的 Fake 模型演示订单流程，不需要 API Key。
- **真实模型**：通过 Provider SDK 请求模型，由模型根据自然语言选择工具，再经过同一套治理流程执行。

**订单、账户、退款和转账均为进程内模拟数据；真实模式中的模型 API 请求会产生费用，模拟转账不涉及真实资金。**

## 文件结构

| 文件 | 用途 |
| --- | --- |
| `tool_governance_demo.py` | 业务入口：工具定义、治理运行时、审计、模型适配、AgentRunner 和 CLI |
| `tests/test_tool_governance.py` | 转账的 5 项验收测试，所有转账调用经过 `runtime.invoke()` |
| `test_governance_demo.py` | 通用治理、审计、AgentRunner、SDK 协议与真实 Provider 测试 |
| `example_live_model.py` | 独立的真实模型只读查询示例 |
| `.env.example` | 空白模型凭证配置模板 |
| `requirements.txt` / `pytest.ini` | 依赖与测试配置 |
| `main.py` | IDE 生成的示例文件；业务入口为 `tool_governance_demo.py` |

`.env`、`架构图/`、`audit_logs/`、虚拟环境、缓存、IDE 配置和备份压缩包不上传到仓库。

## 安装

需要 **Python 3.11 或以上版本**及 Git，推荐 Python 3.12。Provider SDK 从 [provider-model](https://github.com/TomYang1024/provider-model) 安装，无需配置本地 SDK 路径。

```bash
git clone https://github.com/TomYang1024/governance_demo.git
cd governance_demo
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

下文的 `python` 指激活虚拟环境后的解释器。未激活时，可以改用 `.venv/bin/python`。

## 本地测试

本节命令不请求真实模型，不需要 API Key。

### 转账的 5 项验收

在项目根目录执行：

```bash
python -m pytest tests/test_tool_governance.py -v -k "transfer"
```

预期为 **5 passed**。每项测试内部覆盖多组输入与边界：

| 测试项 | 核心断言 |
| --- | --- |
| 参数校验 | 注入 `approved`、`user_id` 等额外字段，非法账号、金额为 0 或超过 100000，一律返回 `INVALID_ARGUMENT`，余额不变 |
| 业务预检 | `(50000, 80000]` 返回 `EXCEED_LIMIT`；余额不足返回 `INSUFFICIENT_BALANCE`；检查临界值、小数余额和租户隔离 |
| 权限与模式 | 无 `account:transfer` 权限、不在白名单、Plan 模式均拒绝；已有审批也不能绕过 |
| 审批与正常转账 | 未审批返回 `CONFIRM`；改金额使原审批与参数不匹配；原参数可成功执行；校验余额、脱敏、审计和审批防重放 |
| 超时处理 | 大于 80000 的转账在审批后等待 3 秒，触发 2 秒执行超时，返回 `TIMEOUT_UNKNOWN` 并记录审计，余额不变 |

显示 `CONFIRM` 和脱敏审计日志：

```bash
python -m pytest tests/test_tool_governance.py -v -s -k "transfer"

# 只查看审批、成功转账和审计场景
python -m pytest tests/test_tool_governance.py -v -s \
  -k "transfer_approval_success_redaction_and_no_replay"
```

日志中可看到 `ACC-A-****3456`、`ACC-A-****4321`。审批前的工具结果为 `status=pending_approval`、`decision=PermissionDecision.CONFIRM`；审计中的对应决策值为 `confirm`。

### 全部离线测试和单个用例

```bash
# pytest.ini 默认排除 live 测试
python -m pytest -q

# 指定测试文件
python -m pytest test_governance_demo.py -v

# 指定一个用例，显示 print 输出
python -m pytest test_governance_demo.py::test_example_read_only_loop -v -s

# 按关键词筛选
python -m pytest test_governance_demo.py -k "refund" -v
```

## 已注册的工具

`build_tools()` 组装工具；`demo_tools()` 是兼容入口。`build_governance()` 装配工具、权限引擎、审批存储、幂等存储和审计。

| 工具 | 参数 | 权限与策略 |
| --- | --- | --- |
| `get_order` | `order_id`，如 `ord_1001` | `order:read`；只读，无需审批 |
| `create_refund` | `order_id`、正数 `amount`、4–200 字的 `reason` | `refund:create`；高风险写操作，需要人工审批；2 秒执行超时 |
| `transfer` | `from_account`、`to_account`、`amount` | `account:transfer`；高风险写操作，需要人工审批；2 秒执行超时，不自动重试 |
| `run_shell` | `command` | 已禁用；不向模型暴露，不能执行 |

转账账号格式为 `ACC-大写字母-六位数字`，例如 `ACC-A-123456`。金额使用 `Decimal` 校验，须大于 0、不超过 100000，最多两位小数；账户字典中的余额保持 `float` 类型。

### 初始模拟数据

| 租户 | 账户 | 初始余额 |
| --- | --- | ---: |
| `tenant_a` | `ACC-A-123456` | 100000.0 |
| `tenant_a` | `ACC-A-654321` | 5000.0 |
| `tenant_a` | `ACC-A-888888` | 20000.0 |
| `tenant_b` | `ACC-B-111111` | 50000.0 |

`tenant_a` 的 `ord_1001` 为 `paid`，可退款金额 399.00；`ord_1002` 为 `shipped`，可退款金额 0.00。

账户和订单按租户隔离。`reset_demo_state()` 恢复初始数据；独立进程启动时也会重新初始化，模拟余额不会跨进程保存。

### 转账规则

1. 先检查教学规则：`50000 < amount <= 80000` 时返回 `EXCEED_LIMIT`。这是区间拦截，不是真实业务的单笔限额。
2. 再检查付款账户余额；余额不足或当前租户下查不到付款账户时返回 `INSUFFICIENT_BALANCE`。
3. 等待与用户、租户、工具及参数绑定的人工审批。
4. 执行时检查转入账户；不存在则返回 `ACCOUNT_NOT_FOUND`，不扣款。
5. `amount > 80000` 时在扣款前等待 3 秒，用于触发 2 秒执行超时，返回 `TIMEOUT_UNKNOWN`。

写操作结果未知时不自动重跑；同一幂等键再次调用返回 `RESULT_UNKNOWN`。

## 本地离线演示

```bash
# Fake 模型：订单查询闭环
python tool_governance_demo.py --offline --scenario read

# Fake 模型：退款流程，在终端输入 approve / reject
python tool_governance_demo.py --offline --scenario refund --approval interactive

# 仅离线测试允许模拟自动批准
python tool_governance_demo.py --offline --scenario refund --approval fake-approve

# 不经过模型，演示参数、权限、审批、禁用工具和模式限制
python tool_governance_demo.py --offline --scenario governance
```

离线 Fake 模型的脚本场景是订单查询和退款。**本地转账请运行前面的 5 项验收测试**；仅修改离线脚本的 `--prompt` 不会将固定脚本改为转账流程。

## 真实模型调用

### 配置凭证

```bash
cp -n .env.example .env
# 编辑 .env，填写 DEEPSEEK_API_KEY
```

```dotenv
DEEPSEEK_API_KEY=你的真实密钥
GOVERNANCE_DEMO_PROVIDER=deepseek
GOVERNANCE_DEMO_MODEL=deepseek-flash
```

`.env` 只在显式传入 `--env-file .env` 时加载；已有环境变量优先。也可以通过 `DEEPSEEK_API_KEY_FILE` 指向保存密钥的本地文件。配置模板不包含真实密钥。

### 查询订单

```bash
python tool_governance_demo.py \
  --live --env-file .env --provider deepseek --model deepseek-flash \
  --prompt "ord_1001 这单现在怎么样了？要是不想要了，还能退多少？" \
  --max-turns 4 --max-output-tokens 4096 \
  --audit-log audit_logs/live-order.jsonl
```

也可以运行只开放查询权限的独立示例：

```bash
python example_live_model.py --env-file .env
```

### 申请退款

```bash
python tool_governance_demo.py \
  --live --env-file .env --provider deepseek --model deepseek-flash \
  --prompt "ord_1001 我确定不要了，399元全额退吧，原因是临时改变购买计划，不再需要了。" \
  --approval interactive --max-output-tokens 4096 \
  --audit-log audit_logs/live-refund.jsonl
```

### 账户转账

```bash
python tool_governance_demo.py \
  --live --env-file .env --provider deepseek --model deepseek-flash \
  --prompt "我想从 ACC-A-123456 给 ACC-A-654321 转 1000 元，帮我处理一下。" \
  --approval interactive \
  --max-turns 4 --max-output-tokens 4096 --verbose \
  --audit-log audit_logs/live-transfer.jsonl
```

使用业务语言，让模型自行选择工具。出现审批提示后，检查工具、账号和金额，再输入 `approve` 或 `reject`。批准 1000 元的正常转账后，模拟余额应为 99000.0 和 6000.0。

| 替换金额 | 预期路径 |
| --- | --- |
| 1000 | 预检通过，等待审批，批准后完成本地模拟转账 |
| 60000 | 命中教学规则，返回 `EXCEED_LIMIT` |
| 90000 | 预检通过，批准后触发执行超时，返回 `TIMEOUT_UNKNOWN` |

只观察真实模型发出的调用和待审批状态时，使用 `--approval pending`；返回 `CONFIRM`，退出码为 3。

当前 CLI 每次运行接收一条用户消息。模型回答后如需补充信息，应使用新的 `--prompt` 重新运行；消息历史和待审批状态不支持跨进程恢复。

### 真实 Provider 的 pytest 测试

此测试会请求 API，必须显式启用。pytest 不会自动读取 `.env`，请先在终端配置凭证：

```bash
export DEEPSEEK_API_KEY="你的真实密钥"

GOVERNANCE_LIVE_TEST=1 \
GOVERNANCE_DEMO_PROVIDER=deepseek \
GOVERNANCE_DEMO_MODEL=deepseek-flash \
python -m pytest test_governance_demo.py::test_live_read_only_smoke -m live -v -s
```

此 pytest 用例是只读模型接入检查；真实模型转账使用上面的 CLI 命令。

## Python 代码调用工具

下面只执行本地代码，不请求模型 API。调用统一经过 `runtime.invoke()`；示例中的审批凭证由可信测试代码签发。

```python
import asyncio
from dataclasses import replace
from tool_governance_demo import (
    ExecutionContext, ToolCall, TransferArgs, build_governance,
)


async def demo():
    runtime, approvals, _sink = build_governance()
    ctx = ExecutionContext(
        run_id="run_example", user_id="u_100", tenant_id="tenant_a",
        permissions=frozenset({"order:read", "refund:create", "account:transfer"}),
        allowed_tools=frozenset({"get_order", "create_refund", "transfer"}),
    )
    order = await runtime.invoke(
        ToolCall("call_order", "get_order", {"order_id": "ord_1001"}), ctx,
    )
    print(order.content)

    refund = await runtime.invoke(ToolCall("call_refund", "create_refund", {
        "order_id": "ord_1001", "amount": "399.00", "reason": "临时改变购买计划",
    }), ctx)
    print(refund.decision.name)  # CONFIRM，尚未执行退款

    args = {
        "from_account": "ACC-A-123456", "to_account": "ACC-A-654321", "amount": "1000.00",
    }
    call = ToolCall("call_transfer_123456", "transfer", args)
    pending = await runtime.invoke(call, ctx)
    print(pending.decision.name)  # CONFIRM，尚未修改余额

    approvals.approve(
        "approval_example", user_id=ctx.user_id, tenant_id=ctx.tenant_id,
        tool_name="transfer", args=TransferArgs.model_validate(args), approver_id="ops_1",
    )
    result = await runtime.invoke(call, replace(ctx, approval_id="approval_example"))
    print(result.content)  # 成功结果中的账号已脱敏


asyncio.run(demo())
```

## 审计与常用参数

真实模式默认写入 `audit_logs/governance-audit.jsonl`；可通过 `--audit-log` 指定文件。本地测试使用内存审计或 pytest 临时目录中的 JSONL 文件。

```bash
python tool_governance_demo.py \
  --audit-summary audit_logs/live-transfer.jsonl --tenant-id tenant_a
```

审计包含调用、策略决策、审批消费、执行尝试及终态。账号在结果和审计摘要中展示为 `ACC-A-****3456`；邮箱和令牌也会脱敏。审计不保存完整提示词、模型回答、推理内容或 API Key。

| 参数 | 用途 |
| --- | --- |
| `--approval interactive` / `pending` | 人工交互审批 / 返回待审批状态 |
| `--max-turns` / `--max-tool-calls` | 模型轮数 / 工具调用次数上限 |
| `--max-output-tokens` | 每次模型输出 token 上限，包含思考 token |
| `--model-timeout` / `--run-timeout` | 单次模型请求 / 整次运行的时间上限 |
| `--mode plan` | Plan 模式，禁止写操作 |
| `--verbose` | 输出 SDK 请求与响应元数据 |
| `--otel console` | 输出追踪 span |

退出码：`0` 完成，`2` 配置错误，`3` 等待审批，`4` 失败或触达运行上限。工具返回 `TIMEOUT_UNKNOWN` 时，以工具状态和系统说明为准。

若终端已配置 HTTP 代理，可在真实模型命令前添加 `PROVIDER_SDK_TRUST_ENV=true`，让 SDK 使用终端的代理环境变量。

## 治理边界

- `PermissionEngine.decide` 的白名单和权限检查顺序保持不变，审批不能绕过权限或 Plan 模式。
- `TransferArgs` 从 `StrictArgs` 继承 `extra="forbid"`，模型不能通过额外参数注入身份或审批信息。
- 审批绑定用户、租户、工具、参数和有效期，成功执行后只能消费一次。
- 同一业务幂等键的成功结果可复用；改参冲突或结果未知时拒绝重跑。
- 运行状态、审批、幂等、资源锁、订单和账户均在内存中，不支持跨进程恢复或多实例协调。
- 本项目未实现真实资金结算、审批人认证、分布式事务、持久化业务存储或生产级审计防篡改。
