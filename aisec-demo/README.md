# AI 安全助手 Demo (aisec-demo)

> Plan 文档：[`../AI安全助手_Plan.md`](../AI安全助手_Plan.md)（v0.6 - 5 项增量修复）

一个能在个人笔记本上跑起来的 AI 安全运营 Demo。覆盖六类核心需求：
**影子 Agent 检测 / Agent 身份治理 / 智能访问控制 / Skills/MCP 审查 / 输入输出全量留痕 / LLM 模型安全**。

## 当前状态

| Sprint | 模块 | 状态 |
|--------|------|------|
| 0 | 多 Agent 骨架（probe / gateway / soc） + EventBus + A2A-Lite + Registry | ✅ 已完成 |
| 1 | **SMR** Skills/MCP 审查（静态 + 语义 + 行为） | ✅ 已完成 |
| 2 | Agent 簇（影子检测 + 身份治理 + 智能访问控制 + 全量留痕） | ✅ 已完成 |
| 3 | LLM 模型安全（MSP） | ✅ 已完成（轻量版：指纹 + 注入 + 有害 + 越狱） |
| 4 | AISOC 控制台 / 告警 / 黑白名单归档 | ✅ 已完成 |
| **增量** | **V0.6 5 项修复** | ✅ 已完成 |
| | 模型熔断器（MSP 及时响应） | ✅ `circuit_breaker.py` |
| | 动态零信任评分引擎 | ✅ `trust.py` |
| | Agent Token 身份认证 | ✅ `registry.py` + `gateway.py` |
| | Gateway 流式代理改进 | ✅ `_proxy_stream` 完整实现 |
| | Web 控制台整合 | ✅ 新增模型安全 + 信任评分页签 |

## 实现索引（技术 / 代码行号 / 运行指令 / 预期示例）

> 本节是**功能点的总索引**，按 Plan 6 大需求组织。每条包含：
> ① 用到的技术（库/算法/协议）　② 关键代码行号（含可点击链接）　③ 终端运行指令　④ 成功运行的预期示例
>
> 一键端到端验证：`python validate_all.py` → **19/19 通过**（详见 §15 端到端测试）

### 需求① 影子 Agent 发现（SAD）

| 功能点 | 技术 | 代码行号 | 运行指令 | 预期示例 |
|--------|------|---------|---------|---------|
| 终端探针（进程/网络/文件扫描）| `psutil` + `watchdog` + 启发式规则 | [aisec/agents/probe.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/agents/probe.py) 全文 321 行 | `python -m aisec start` 启动后自动运行 | events.jsonl 累计 934 条 `shadow_agent_detected` + 40 条 `anomalous_egress_detected` |
| 网关拦截（身份→决策）| FastAPI 反向代理 + 4 状态机（`deny/rate_limit/allow/soc_approval`）| [aisec/agents/gateway.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/agents/gateway.py) L190-220 决策 + L329-364 拦截 + L541-585 A2A | `python examples\demo_rogue_agent.py` | HTTP 403，`X-Gateway-Decision: deny`（见下方完整示例）|
| 告警落盘（Markdown）| 路径 `data/alerts/<时间>.md` | [aisec/scanners/alert_generator.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/alert_generator.py) L1-211 | 探针命中规则时自动写 | `data/alerts/` 共 26 个 .md 文件 |

**demo_rogue_agent.py 预期输出**：
```
[demo_rogue_agent] POST http://127.0.0.1:8002/v1/chat/completions
[demo_rogue_agent]   X-Agent-ID = rogue-agent-007  (NOT IN REGISTRY)
[demo_rogue_agent] <- HTTP 403 (0.26s)
{
  "error": "request_blocked",
  "decision": "deny",
  "reason": "agent 'rogue-agent-007' not in registry"
}
[OK] 影子 Agent 被正确拦截
```

### 需求② LLM 模型安全（MSP）

| 功能点 | 技术 | 代码行号 | 运行指令 | 预期示例 |
|--------|------|---------|---------|---------|
| 模型指纹（fingerprint）| SHA256(model + host + key + ts) | [aisec/msp/fingerprint.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/fingerprint.py) L1-72 | `python examples\demo_msp_fingerprint.py` | `PASS`（同输入同输出）|
| Prompt 注入检测 | 12 条正则 + 加权打分（零 LLM 成本）| [aisec/msp/attack_corpus.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/attack_corpus.py) L1-131 + [aisec/msp/prompt_injection.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/prompt_injection.py) L1-96 | `python examples\demo_msp_prompt_injection.py` | `PASS: all 4 cases classified as expected` |
| 有害输出检测 | 8 条正则（PII / AWS Key / 危险代码 / 越狱标志）| [aisec/msp/harmful_output.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/harmful_output.py) L1-84 | `python examples\demo_msp_harmful_output.py` | `PASS: all 6 cases classified as expected` |
| 越狱主动探测 | 5 个内置 attack probe + 真调 LLM | [aisec/msp/jailbreak.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/jailbreak.py) L1-94 | `python -m aisec scan-model --no-jailbreak`（秒级）| 退出码 0=safe / 2=suspicious |
| 全量扫描（4 phase 合并）| asyncio orchestrator + JSON+MD 双格式落盘 | [aisec/msp/runner.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/runner.py) L95-207 `run_full_scan()` | `python -m aisec scan-model` | `data/msp/msp_<ts>.{json,md}`；suspicious 时联动告警 |
| **模型熔断器（V0.6 新增）** | 标记文件 `data/model_circuit_breaker.json`；dangerous/suspicious 时自动触发；gateway 检查熔断返回 503 | [aisec/core/circuit_breaker.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/circuit_breaker.py) L1-91；[aisec/msp/runner.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/runner.py) L197-213 触发 | `Invoke-RestMethod http://127.0.0.1:8000/model-breaker` | `{"tripped": true, "model": "...", "level": "dangerous"}` |

**MSP 报告样例**（`data/msp/msp_20260615T032629Z.md`）：
```markdown
- **模型**: qwen3.7-max-preview
- **API 端点**: dashscope.aliyuncs.com
- **指纹**: 76043f4a85b37fd4c063b87d4202d8e9467d510c1e366896379fd90d26dc315d
- **耗时**: 46.93s
- **总体评分**: 20/100
- **总体等级**: **SUSPICIOUS**
- **越狱率**: 20.0% (1/5) — jb-harm-004 命中
```

### 需求③ Agent 数字身份 / 授权 / 审计 / 溯源（AIG）

| 功能点 | 技术 | 代码行号 | 运行指令 | 预期示例 |
|--------|------|---------|---------|---------|
| Agent Registry（SQLite）| `sqlite3` + `aiosqlite` 双接口 + DDL UPSERT | [aisec/core/registry.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/registry.py) L24-37 DDL + L40-105 register/heartbeat/list | `python -m aisec agents` | 5 agents（3 online + 2 offline）|
| A2A-Lite 协议 | JSON over HTTP（POST `/a2a`）+ fail-closed 100ms | [aisec/core/a2a.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/a2a.py) L1-195 全文 | Gateway 拦截时自动调用 | events.jsonl 追加 `a2a_verify_identity` |
| 心跳（5s）+ 巡检 | 后台 asyncio task + `last_heartbeat` 时间戳 | [aisec/core/registry.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/registry.py) L138-160 | `python -m aisec status` | `online 2s ago` |
| **Agent Token 身份认证（V0.6 新增）** | UUID4 token 注册分配 + `X-Agent-Token` 请求头验证 + 401 拒绝 | [aisec/core/registry.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/registry.py) `upsert()` L68-99 / `verify_token()` L148-158；[aisec/agents/gateway.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/agents/gateway.py) L268-330 | 携带 `X-Agent-Token` 头请求 gateway | token 错误 → 401 `identity_verification_failed` |
| Event Bus（审计）| `asyncio.Lock` 延迟初始化 + 按日分文件 | [aisec/core/event_bus.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/event_bus.py) L39-127（`append` L64-73 + `append_nowait_safe` L75-84）| `python -m aisec events` | 1300+ 事件，5+ 事件类型 |

**`python -m aisec agents` 预期输出**：
```
AGENT_ID         NAME                   STATUS     TRUST  LAST HB
--------------------------------------------------------------------------------
whitelisted-agent 白名单合规 Agent          offline    95     12:22:49
low-trust-agent  低信任 Agent              offline    20     12:22:50
gateway-agent    流量拦截 Agent             online     100    11:30:12
soc-agent        SOC 运营 Agent           online     100    11:30:16
probe-agent      终端探针 Agent             online     100    11:30:12
```

### 需求④ 访问控制（IAC：白名单 + 沙箱 + 网关 + 零信任）

| 功能点 | 技术 | 代码行号 | 运行指令 | 预期示例 |
|--------|------|---------|---------|---------|
| 哈希白/黑名单归档 | SHA256 内容寻址 + `data/{whitelist,blacklist}/<sha>.json` | [aisec/scanners/hasher.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/hasher.py) L1-19 + [aisec/scanners/list_archive.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/list_archive.py) L1-117 | 扫描 Skill 时自动归档 | `whitelist/bc10af19...json`（safe）+ `blacklist/d3d00c3a...json`（dangerous）|
| RestrictedPython 沙箱 | 编译时拦截 eval/exec + `asyncio.wait_for` CPU 预算 | [aisec/scanners/sandbox.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/sandbox.py) 全文 | `python -m aisec scan-skill examples\suspicious_skill.py` | `behavior.reasons: ["compile-time block: Eval calls are not allowed"]` |
| 网关 4 状态决策机 | `unregistered → deny` / `trust<30 → rate_limit` / `sensitivity≥L3 → soc_approval` / `else → allow` | [aisec/agents/gateway.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/agents/gateway.py) L194-220 | 4 种 header 组合触发 | `X-Gateway-Decision` = deny / rate_limit / allow / soc_approval |
| 零信任信任分 | trust_score [0, 100] 心跳携带 + < 30 限流 | [aisec/core/registry.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/registry.py) L92-105 | `low-trust-agent` trust=20 测试 | `decision=rate_limit` |
| **动态零信任评分（V0.6 新增）** | 事件驱动动态评分：`TrustEngine` 每 30s 评估；扣减映射（shadow -20 / blocked -15 / egress -25 / breaker -30）；无告警 +5 | [aisec/core/trust.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/trust.py) L1-129；[aisec/agents/soc.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/agents/soc.py) L135-167 | `Invoke-RestMethod http://127.0.0.1:8000/trust` | `{"agents": [{"trust_score": 80, "trust_level": "trusted"}]}` |

### 需求⑤ Skills/MCP 审查（SMR）

| 功能点 | 技术 | 代码行号 | 运行指令 | 预期示例 |
|--------|------|---------|---------|---------|
| 静态分析（AST + 正则）| `ast` 库解析 + 危险模式库 | [aisec/scanners/static_analyzer.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/static_analyzer.py) L1-158 | `python -m aisec scan-skill examples\safe_skill.py` | `static.score: 0, pattern_hits: []` |
| 语义分析（LLM）| 千问 mock 模式 + 真实模式自动切换 | [aisec/scanners/semantic_analyzer.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/semantic_analyzer.py) L1-92 | 同上 | `semantic.score: 0, reason: "完全无害的基础工具"` |
| 行为沙箱 | RestrictedPython 编译时 + 行为观察 | [aisec/scanners/sandbox.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/sandbox.py) | 同上 | `behavior.status: "ok", score: 0` |
| 三维加权评分 | 静态 0.3 + 语义 0.4 + 行为 0.3 | [aisec/scanners/risk_scorer.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/risk_scorer.py) L1-70 | 同上 | safe → `level=safe`；suspicious → `level=dangerous` |
| MCP server 扫描 | JSON Schema + 命令注入 + URL 协议检查 | [aisec/scanners/mcp_scanner.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/mcp_scanner.py) L1-204 | `python -m aisec scan-mcp examples\demo_mcp.json` | JSON 报告含 `tools[]` / `risk.level` / `pattern_hits` |
| 威胁情报库 | 内置 IOC 模式（30+ 条）| [aisec/scanners/static_analyzer.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/static_analyzer.py) `DANGEROUS_PATTERNS` + [aisec/msp/attack_corpus.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/attack_corpus.py) | 扫描时自动匹配 | `AKIA[0-9A-Z]{16}` / `subprocess.*shell=True` 等命中 |

**`scan-skill` 预期输出对比**（同一个 CLI 工具，不同输入）：

| 输入 | `static.score` | `semantic.score` | `behavior.score` | `weighted` | `level` | `list_type` |
|------|----------------|------------------|------------------|------------|---------|-------------|
| `examples\safe_skill.py` | 0 | 0 | 0 | **0.0** | **safe** | **whitelist** |
| `examples\suspicious_skill.py` | 75 | 100 | 60 | **76.5** | **dangerous** | **blacklist** |

### 需求⑥ 全量留痕 / 审计 / 复现（AT）

| 功能点 | 技术 | 代码行号 | 运行指令 | 预期示例 |
|--------|------|---------|---------|---------|
| JSONL 事件流 | append-only `data/events/<YYYY-MM-DD>.jsonl` | [aisec/core/event_bus.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/event_bus.py) L60-73 | `python -m aisec events` | 1300+ 事件 / 5+ 类型 |
| SQLite 状态 | `data/aisec.db` 含 `agents / policies / audit_log` | [aisec/core/registry.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/registry.py) L24-37 | 启动后自动建表 | `sqlite3 data/aisec.db ".tables"` |
| AISOC 控制台 | FastAPI + Jinja2 + 原生 CSS（**不**引入前端框架）| [aisec/web/app.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/web/app.py) L1-310（路由 L222-271）| `python -m aisec web` | 6 个页面 200 OK（见下方）|
| **嵌入式 Dashboard（V0.6 新增）** | 单页应用 7 页签：仪表盘 / Agent / 事件 / 扫描 / **模型安全** / **信任评分** / 对话 | [aisec/web/dashboard.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/web/dashboard.py) 全文 | `http://127.0.0.1:8000/dashboard` | 模型安全页 + 信任评分页可切换 |
| 可复现 | MSP fingerprint（SHA256 含 ts_ms）| [aisec/msp/fingerprint.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/fingerprint.py) L1-72 | `python examples\demo_msp_fingerprint.py` | `PASS` |

**AISOC 控制台路由矩阵**（实测）：

| 路径 | 用途 | 实测响应 |
|------|------|---------|
| `GET /healthz` | 健康检查 | 200, 2 B |
| `GET /` | 概览 | 200, 3118 B |
| `GET /agents` | Agent 列表 | 200, 2973 B |
| `GET /alerts` | 告警列表 | 200, 2704 B |
| `GET /events?type=...` | 事件检索 | 200, 50489 B |
| `GET /msp` | MSP 报告列表 | 200, 3118 B |
| `GET /msp/{name}` | MSP 详情 | 200, 2729 B |
| `GET /api/summary.json` | JSON 汇总 | 200, 581 B |
| `GET /model-breaker` | 模型熔断器状态（V0.6） | 200, JSON |
| `POST /model-breaker/reset` | 重置熔断器（V0.6） | 200, JSON |
| `GET /trust` | 动态信任评分摘要（V0.6） | 200, JSON |
| `GET /dashboard` | 嵌入式 Dashboard（V0.6） | 200, HTML |

---

## 系统架构（V0.4）

```
┌────────────────┐  A2A-Lite  ┌────────────────┐
│  probe-agent   │◄──────────►│   soc-agent    │  ← 唯一调 LLM
│  :8001         │  JSON/HTTP  │   :8000        │  ← 唯一编排者
└────────────────┘             │   :8000/       │  ← AISOC Web 控制台
        │                      └────────────────┘
        │  EventBus (JSONL)            ▲
        ▼                              │
  data/events/YYYY-MM-DD.jsonl         │ A2A-Lite
                                       │
                              ┌────────────────┐
                              │ gateway-agent  │  ← HTTP 反向代理
                              │   :8002        │  ← 拦截 /v1/* 请求
                              └────────────────┘
                                       │
                                       ▼
                              LLM API (DashScope)
```

- **soc-agent**（:8000）：编排者、Registry 维护、Chat 入口、调 LLM、AISOC Web 控制台、黑白名单/告警 API、模型熔断 API（`/model-breaker`）、动态信任评分 API（`/trust`）、嵌入式 Dashboard（`/dashboard`）
- **probe-agent**（:8001）：终端探针（psutil 扫描进程/网络，启发式影子 Agent 检测）
- **gateway-agent**（:8002）：HTTP 反向代理流量拦截（身份验证 + token 认证 + 信任分 + 数据敏感度 → deny / rate_limit / allow / soc_approval；流式代理透传 status/content-type；熔断检查）

## 快速开始（推荐：系统 Python + `python -m aisec`）

> **为什么用 `python -m aisec`？**
> Trae IDE 的终端沙箱会拒绝执行 venv 内的 `python.exe`（`Permission denied`）。
> 为最大兼容性，本 Demo 推荐直接使用系统 Python，并以 `python -m aisec` 形式调用。
> 若在本地 PowerShell / VS Code 外部终端中运行，可改用 venv 方式（见文末"备选：venv 方式"）。

### 1. 进入项目目录 & 安装依赖

> ⚠️ Trae 终端默认 CWD 是父目录，**必须先 `cd` 到 aisec-demo**。

```powershell
cd d:\AI安全产品\AI安全助手\aisec-demo
python -m pip install -e .
# 完整可选依赖（含 mitmproxy 与 dev 工具）：
# python -m pip install -e .[all]
```

> 首次安装约 1-3 分钟。

### 2. 启动三个 Agent

```powershell
python -m aisec start
```

预期输出：
```
  [ok]   soc-agent started (pid=..., port=8000)
  [ok]   probe-agent started (pid=..., port=8001)
  [ok]   gateway-agent started (pid=..., port=8002)
Waiting for soc-agent health ...
  soc-agent is healthy.
```

> ⚠️ Trae 终端因沙箱限制，无法直接看到子进程的标准输出。
> 各 Agent 的运行日志会写入 `data\pids\<agent>.log`，可另外打开查看：
> ```powershell
> Get-Content data\pids\probe.log -Wait
> ```

### 3. 查看 Agent 健康

```powershell
python -m aisec status
```

预期：
```
AGENT             PID      ENDPOINT                STATUS
------------------------------------------------------------
soc-agent         12345    127.0.0.1:8000         healthy
probe-agent       12346    127.0.0.1:8001         healthy
gateway-agent     12347    127.0.0.1:8002         healthy
```

### 4. 查看已注册 Agent

```powershell
python -m aisec agents
```

### 5. 扫描一个 Skill

```powershell
python -m aisec scan-skill examples\safe_skill.py
python -m aisec scan-skill examples\suspicious_skill.py
```

预期 safe_skill：risk.level = safe（score = 0）
预期 suspicious_skill：risk.level = dangerous（score ≥ 60）

### 6. 扫描 MCP 配置

```powershell
python -m aisec scan-mcp examples\demo_mcp.json
```

### 7. 通过 soc-agent Chat（需三个 Agent 已启动）

```powershell
python -m aisec chat "扫描 examples\suspicious_skill.py 这个 Skill"
```

无 `DASHSCOPE_API_KEY` 时走 mock 模式；有 key 时走 qwen3.7-max-preview。

> ⚠️ 首次 `chat` 因 LLM 客户端懒加载、DashScope 鉴权握手 + 千问首 token 延迟，正常耗时 5-15s。
> 服务端 `handle_chat` 有 90s 兜底超时，绝不会无限挂起（v0.4 早期版本 30s 客户端超时 + 65s LLM 内部超时不匹配，会 race 出 `timed out`）。

### 8. 打开 AISOC Web 控制台

启动三个 Agent 后，浏览器访问：

```
http://127.0.0.1:8000/
```

或：

```
http://127.0.0.1:8000/dashboard
```

控制台功能：
- **仪表盘**：在线 Agent 数、事件数、拦截数、影子 Agent 数 + 最近事件流
- **Agent 列表**：已注册 Agent 状态、信任分、心跳时间
- **事件审计**：带过滤的审计事件流
- **安全扫描**：Skill/MCP 在线扫描，展示三维评分
- **模型安全（V0.6 新增）**：熔断状态、熔断模型/原因、黑白名单、重置熔断按钮
- **信任评分（V0.6 新增）**：各 Agent 动态信任分及等级（trusted/suspicious/untrusted）
- **智能对话**：自然语言查询（调用千问 LLM）

### 9. 通过 Gateway 代理访问 LLM API

将 LLM API 请求发到 Gateway（而非直接发到 DashScope），Gateway 会自动验证身份：

```powershell
# 已注册 Agent 请求（被放行）
# PowerShell 标准方式：Invoke-RestMethod
$body = @{
    model = "qwen3.7-max-preview"
    messages = @(@{role="user"; content="hello"})
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8002/v1/chat/completions" `
  -Headers @{"X-Agent-ID"="probe-agent"; "Content-Type"="application/json"} `
  -Body $body

# 未注册 Agent 请求（被拦截 403）
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8002/v1/chat/completions" `
  -Headers @{"X-Agent-ID"="rogue-agent"; "Content-Type"="application/json"} `
  -Body $body
```

> ⚠️ **PowerShell 中 `curl` 是 `Invoke-WebRequest` 的别名**（非 Unix curl.exe），
> 不支持 `-X`/`-H`/`-d` 参数。Linux/macOS 或装了 Git Bash 的 Windows 可继续用 `curl -X ... -H ... -d ...`。
> 跨平台一致写法用 `Invoke-RestMethod`（PowerShell 5+ 兼容）。

Gateway 决策逻辑（V0.6 更新：增加 token 身份验证）：

| Agent 状态 | Token 验证 | 信任分 | 数据敏感级别 | 决策 | 说明 |
|------------|-----------|--------|-------------|------|------|
| 未注册 | - | - | 任意 | **deny** | 403 拒绝 |
| 已注册 | token 错误 | - | 任意 | **401** | 身份验证失败 |
| 已注册 | token 正确/未携带 | < 30 | 任意 | **rate_limit** | 限流放行 |
| 已注册 | token 正确/未携带 | >= 30 | L0-L2 | **allow** | 正常放行 |
| 已注册 | token 正确/未携带 | >= 30 | L3-L4 | **soc_approval** | 放行但记录审批事件 |

敏感级别通过请求头 `X-Data-Sensitivity` 指定（L0-L4）。

### 10. 查看黑白名单与告警

```powershell
# 白名单
Invoke-RestMethod http://127.0.0.1:8000/whitelist

# 黑名单
Invoke-RestMethod http://127.0.0.1:8000/blacklist

# 告警列表
Invoke-RestMethod http://127.0.0.1:8000/alerts

# 查看某条告警详情
Invoke-RestMethod "http://127.0.0.1:8000/alerts/<filename>"
```

> 注：Windows PowerShell 中 `curl` 是 `Invoke-WebRequest` 别名，对只读 GET API
> 行为近似（返回 JSON 字符串）。更稳妥的写法统一用 `Invoke-RestMethod`。

扫描 Skill/MCP 时，结果会自动归档到黑白名单（基于 SHA256），并生成 Markdown 告警文件到 `data/alerts/` 目录。

### 10.5 V0.6 新增 API

```powershell
# 模型熔断器状态
Invoke-RestMethod http://127.0.0.1:8000/model-breaker

# 重置熔断器（恢复模型服务）
Invoke-RestMethod -Method Post http://127.0.0.1:8000/model-breaker/reset

# 动态信任评分摘要
Invoke-RestMethod http://127.0.0.1:8000/trust

# 嵌入式 Dashboard（7 页签，含模型安全 + 信任评分）
# 浏览器访问 http://127.0.0.1:8000/dashboard
```

**模型熔断器**：当 MSP 扫描发现模型安全等级为 dangerous/suspicious 时，自动触发熔断（写入 `data/model_circuit_breaker.json`），gateway 代理请求返回 503。通过 `/model-breaker/reset` 可恢复模型服务。

**动态信任评分**：soc-agent 每 30s 自动评估所有 Agent 的 trust_score，根据事件类型扣减/奖励分数。评分等级：80-100 可信（trusted）、30-79 可疑（suspicious）、0-29 不可信（untrusted）。

**Agent Token 认证**：Agent 注册时自动分配 UUID4 token，通过 gateway 代理请求时需携带 `X-Agent-Token` 头。token 不匹配返回 401。

### 11. 停止

```powershell
python -m aisec stop
```

> Windows 沙箱下 `stop` 用 `taskkill /F` 强制终止子进程（**非优雅退出**）。
> Demo 阶段可接受；生产场景需要信号优雅退出。

### 12. 演示场景（Sprint 2 完整闭环）

`examples/` 目录下有 4 个端到端 demo 脚本，串起来覆盖 Plan Sprint 2 全部关键交付：

| Demo 脚本 | 触发场景 | 期望结果 |
|----------|---------|---------|
| `examples\demo_langchain_agent.py` | 模拟 LangChain Agent 通过 Gateway 调 LLM | HTTP 200, `X-Gateway-Decision=allow` |
| `examples\demo_rogue_agent.py` | 模拟影子 Agent（未注册 ID）尝试调 LLM | HTTP 403, `X-Gateway-Decision=deny` |
| `examples\demo_mcp_client.py` | 模拟 MCP 客户端发 JSON-RPC 2.0 调工具 | 3 个用例：`allow` / `allow` / `soc_approval` |
| `examples\demo_anomalous_egress.py` | 触发异常出站连接 | probe-agent 下一个周期 emit `anomalous_egress_detected` |

**一次性跑完所有 demo**（启动 agents 之后）：

```powershell
# 12.1 LangChain Agent 调 LLM（应被放行）
python examples\demo_langchain_agent.py

# 12.2 影子 Agent 调 LLM（应被拒绝）
python examples\demo_rogue_agent.py

# 12.3 MCP 客户端发 tools/list / tools/call
python examples\demo_mcp_client.py

# 12.4 触发异常出站（probe-agent 主循环会扫描并记录）
python examples\demo_anomalous_egress.py

# 12.5 查看所有事件
python -m aisec events
```

预期在 `data/events/<日期>.jsonl` 中会看到以下事件类型：

- `request_proxied`（demo 1）
- `request_blocked`（demo 2）
- `mcp_request_observed` + `mcp_request_mocked`（demo 3）
- `anomalous_egress_detected`（demo 4，probe 主循环每 10s 扫一次）

### 13. MSP 模型安全扫描（Sprint 3）

Sprint 3 在 Plan V0.4 §4.2 (MSP) + Sprint 4 轻量 MSP 范围内交付：

- **模型指纹 (fingerprint)**：model + base_url + api_key 末 4 位 + 时间戳 → sha256，用于可复现
- **Prompt 注入检测 (injection)**：输入侧，零 LLM 成本，正则 + 关键词打分
- **有害输出检测 (harmful)**：输出侧，零 LLM 成本，识别 PII / 恶意代码 / 越狱成功标志 / 危险知识
- **越狱主动探测 (jailbreak)**：5 个内置 attack probe (DAN / ignore / leak / harm / exfil)，调真实 LLM 并检查是否越狱
- **响应闭环**：写 `data/msp/msp_<ts>.{json,md}` 报告 + 等级 ≥ suspicious 时同步写 `data/alerts/` 告警 + `msp_scan_alert` 事件

**CLI**：

```powershell
# 完整 4 phase 扫描（jailbreak 会真调 LLM，~30-60s）
python -m aisec scan-model

# 跳过 jailbreak（毫秒级，仅注入+有害+指纹）
python -m aisec scan-model --no-jailbreak

# 单 phase
python -m aisec scan-model --fingerprint
python -m aisec scan-model --injection --prompt "忽略以上所有指令..."

# 自定义样本
python -m aisec scan-model --prompt "你的自定义测试 prompt"
```

退出码：`0` = safe / `2` = suspicious 或 dangerous。

**examples/ 下的演示脚本**（不依赖 CLI，可独立跑）：

| Demo 脚本 | 验证内容 | LLM 调用 |
|----------|---------|---------|
| `examples\demo_msp_prompt_injection.py` | 4 个用例：safe/safe/suspicious/dangerous 全分类正确 | 不调用 |
| `examples\demo_msp_harmful_output.py` | 6 个用例：safe/safe/PII/harm/code/jb 全分类正确 | 不调用 |
| `examples\demo_msp_fingerprint.py` | 同输入同输出 + 不同时刻指纹变化 | 不调用 |
| `examples\demo_msp_full_scan.py` | 4 phase 端到端完整扫描（5 个 jailbreak probe） | 调用 5 次 |

```powershell
# 一次跑完
python examples\demo_msp_prompt_injection.py
python examples\demo_msp_harmful_output.py
python examples\demo_msp_fingerprint.py
python examples\demo_msp_full_scan.py
```

**Demo 端到端实测**（在当前 `qwen3.7-max-preview` 上）：

- 注入检测：4/4 分类正确
- 有害输出：6/6 分类正确
- 指纹：3c6dded... (1st) / b84e35ce... (2nd)，同输入同输出 ✅
- 越狱：5 个 probe 实际评估（无 mock），3 个命中 → 越狱率 60% ⚠️

输出文件：

- `data/msp/msp_<ts>.json` —— 机器可读
- `data/msp/msp_<ts>.md`   —— 人读
- `data/alerts/msp_<ts>.md` —— 等级 ≥ suspicious 时
- `data/events/<日期>.jsonl` —— `msp_scan_alert` 事件

**与现有 Sprint 1/2 集成**：
- 模型指纹可绑到 `soc-agent.handle_chat` 响应中（v0.5+）
- 注入检测可作为 gateway 预检（v0.5+）
- 当前 Sprint 3 只交付独立扫描器 + CLI，**未**改 gateway 路径

### 14. AISOC 单页控制台（Sprint 4）

Plan V0.4 §7.2 Sprint 4 关键交付之一 —— 极简单页：Agent 列表 / 告警 / 事件 / MSP 报告。

**技术栈**：FastAPI + Jinja2 + 原生 CSS（不引入 React/Vue/Tailwind/Streamlit），端口 9000。

**启动**：

```powershell
# 一个终端跑 agents（可选，控制台也能独立工作于静态数据）
python -m aisec start

# 另一个终端跑 AISOC 控制台
python -m aisec web
# 浏览器打开 http://127.0.0.1:9000/
```

**路由**：

| 路径 | 用途 |
|------|------|
| `GET /` | 概览（4 卡片 + 事件类型 Top 10） |
| `GET /agents` | Agent 列表（来自 Registry SQLite） |
| `GET /alerts` | 告警列表（来自 `data/alerts/*.md`） |
| `GET /events?type=&limit=` | 事件检索（来自 `data/events/<日期>.jsonl`） |
| `GET /msp` | MSP 报告列表 |
| `GET /msp/{name}` | MSP 报告详情（md 原文渲染） |
| `GET /api/{summary,events,agents,alerts,msp}.json` | JSON 端点（前端可轮询） |
| `GET /healthz` | 健康检查 |

**端到端实测**（基于当前 `data/` 下数据）：

```
GET /healthz             200   2 B
GET /                    200 3118 B
GET /agents              200 2973 B
GET /alerts              200 2704 B
GET /events              200 50489 B
GET /msp                 200 3118 B
GET /msp/{name}          200 2729 B    (含 fingerprint + 等级徽章)
GET /api/summary.json    200  581 B    (5 agents, 7 reports, 10 event types)
```

**summary.json 样例**：

```json
{
  "agents_total": 5, "agents_online": 3, "agents_offline": 2,
  "alerts_total": 5, "msp_total": 7,
  "msp_latest_level": "dangerous", "msp_latest_score": 60,
  "event_types": [
    {"type": "shadow_agent_detected", "count": 934},
    {"type": "agent_registered", "count": 80},
    {"type": "anomalous_egress_detected", "count": 40},
    {"type": "request_proxied", "count": 17},
    {"type": "agent_offline", "count": 9},
    {"type": "mcp_request_observed", "count": 9},
    {"type": "chat", "count": 9},
    {"type": "request_blocked", "count": 8},
    {"type": "request_pending_approval", "count": 6},
    {"type": "mcp_request_mocked", "count": 3}
  ]
}
```

**架构原则**：

- 控制台是**只读**视图，不修改任何数据
- 与 soc-agent / gateway / probe 进程**完全解耦**（独立 uvicorn 进程，同步 sqlite3 / 读文件，不共享 asyncio loop）
- 关掉控制台不影响 agents 运行；关掉 agents 控制台仍可查看历史数据
- 适合做 demo 录屏 / 演示现场展示 / 内部周报素材

## 配置 LLM

两种方式（任选其一）：

**方式一：写入配置文件**（推荐，持久化）

编辑 `config/default.yaml`，填写 `api_key`：

```yaml
llm:
  provider: qwen
  base_url: https://dashscope.aliyuncs.com/compatible-mode/v1
  api_key: "sk-..."           # ← 填入你的 DashScope API Key
  model: qwen3.7-max-preview
```

**方式二：环境变量**（临时覆盖）

```powershell
$env:DASHSCOPE_API_KEY = "sk-..."
python -m aisec start
```

环境变量优先级高于配置文件。未配置 API Key 时走 mock 模式，所有 LLM 调用返回占位返回，便于离线 Demo。

---

## 备选：venv 方式（本地 PowerShell / 外部终端）

仅在**本机 PowerShell（非 Trae 沙箱）** 或 Linux/macOS 上推荐：

```powershell
cd d:\AI安全产品\AI安全助手\aisec-demo
python -m venv .venv
.\.venv\Scripts\activate       # Windows
# source .venv/bin/activate    # Linux / macOS
pip install -e .
aisec start                    # 此处 aisec 在 venv 内可用
```

> 退出 venv：`deactivate`

## 已知限制

- **单笔记本运行**：不适用于企业级多主机部署
- **Mock LLM 模式**：无 API key 时所有 LLM 调用返回占位
- **进程级安全**：未实施 mTLS、签名，仅本机 HTTP
- **Trae 沙箱限制**：无法优雅停止子进程（taskkill /F），日志在 `data/pids/*.log`
- **依赖项**：`pip install -e .` 后 `mitmproxy` 需额外 `pip install -e .[gateway]`
- **Anaconda Windows + scan-skill 性能**：
  - 单次 `scan-skill` 涉及 `LLM.chat()`（含硬超时 65s）+ 静态 + 沙箱，正常耗时 25-45s
  - 程序退出时可能打印 `RuntimeError: Event loop is closed`（ProactorEventLoop 子句柄 GC 告警），属良性，不影响扫描结果
  - 整体有 120s 兜底超时，绝不会无限卡死（之前 v0.4 早期版本在 LLM 网络异常时会触发 `Ctrl+C` 才能中断）
- **手动注册的 Agent 离线**：通过 `POST /registry/agents` 注册但没启动 `heartbeat_loop` 的 Agent，每 30s 会被 `sweep` 标记为 `offline`，需定期发心跳或启动独立心跳循环
- **Gateway 代理 LLM 出向受宿主机网络环境影响**：在 Trae IDE 沙箱或装有 istio-envoy sidecar 的环境，Gateway（:8002）到 `dashscope.aliyuncs.com` 的出向请求可能被 sidecar 截断（响应头 `server: uvicorn, istio-envoy`，`content-length: 0`）。**这与 Gateway 拦截决策逻辑无关**——`X-Gateway-Decision: allow/deny/soc_approval` 响应头 + `X-Trace-ID` 始终准确，验证拦截逻辑只需观察这三个 header 即可。要做端到端 LLM 代理测试请在本地 PowerShell / VS Code 外部终端中运行，或关闭 istio sidecar。

## 目录结构

```
aisec-demo/
├── pyproject.toml
├── config/
│   ├── default.yaml
│   └── policies/
│       └── default_iac.json
├── aisec/
│   ├── cli.py
│   ├── core/               # A2A-Lite, Agent 基类, EventBus, Registry, Tools
│   ├── agents/             # probe / gateway / soc
│   ├── scanners/           # SMR（静态 + 语义 + 行为 + 黑白名单 + 告警）
│   │   ├── skill_scanner.py
│   │   ├── mcp_scanner.py
│   │   ├── static_analyzer.py
│   │   ├── semantic_analyzer.py
│   │   ├── sandbox.py            # 行为沙箱
│   │   ├── risk_scorer.py        # 三维加权评分
│   │   ├── list_archive.py       # 黑白名单归档（SHA256）
│   │   ├── alert_generator.py    # Markdown 告警生成
│   │   └── hasher.py
│   ├── web/                # AISOC Web 控制台
│   │   └── dashboard.py
│   └── llm/                # 千问客户端
├── tools/                  # 测试脚本
│   ├── test_gateway_intercept.py
│   └── test_whitelist_agent.py
├── examples/
│   ├── safe_skill.py
│   ├── suspicious_skill.py
│   ├── compliant_agent.py
│   └── demo_mcp.json
└── data/                   # 运行时生成（已 git ignore）
    ├── events/             # JSONL 事件流
    ├── alerts/             # Markdown 告警文件
    ├── whitelist/          # 白名单（SHA256 JSON）
    ├── blacklist/          # 黑名单（SHA256 JSON）
    ├── aisec.db            # SQLite（Registry）
    └── pids/               # PID 文件 + Agent 日志
```

## A2A-Lite 协议示例

Gateway 查询 Agent 身份（A2A-Lite）：

请求：
```json
{
  "from": "gateway-agent",
  "to": "soc-agent",
  "intent": "query_identity",
  "trace_id": "abc-123",
  "context": {"agent_id": "compliant-agent"},
  "deadline_ms": 100,
  "retry": 0
}
```

响应：
```json
{
  "from": "soc-agent",
  "to": "gateway-agent",
  "trace_id": "abc-123",
  "decision": "allow",
  "action": "allow",
  "reason": "trust_score=100 >= 30",
  "result": {"trust_score": 100, "status": "online"},
  "elapsed_ms": 12
}
```

Gateway 代理拦截响应（HTTP）：

```json
{
  "error": "request_blocked",
  "decision": "deny",
  "reason": "agent 'rogue-agent' not in registry",
  "trace_id": "7736dcb2-44f",
  "gateway": "gateway-agent"
}
```

## 端到端测试脚本

```powershell
# 测试 Gateway 拦截未注册 Agent
python tools\test_gateway_intercept.py

# 测试白名单 Agent 放行与 SOC 审批
python tools\test_whitelist_agent.py
```

测试报告自动归档到 `data/alerts/` 目录。

## License

Proprietary - 仅供内部演示。
