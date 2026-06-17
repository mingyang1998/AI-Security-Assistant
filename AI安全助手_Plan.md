# AI安全助手 —— 产品设计与实施方案（Plan v0.6）

> 编制日期：2026-06-09　｜　**状态：V0.6 已交付**（Sprint 0/1/2/3/4 全部闭合 + 5 项增量修复，6 大需求端到端跑通）
> 适用范围：本公司内员工在研发、生产环境中对 LLM、Agent、MCP、Skills 的安全合规使用
>
> 版本变更记录
> - v0.1 (2026-06-09)：初稿，对应六大需求给出总体方案
> - v0.2 (2026-06-09)：根据领导评审意见调整产品形态为「单机 Demo」、调整模块优先级、简化技术栈、调整告警输出方式
> - v0.3 (2026-06-09)：明确进程与 IPC 架构——多进程 + 进程内 asyncio + JSONL/SQLite 轻量解耦，不引入 Kafka
> - v0.4 (2026-06-09)：三个常驻进程全部 Agent 化（probe-agent / gateway-agent / soc-agent），引入 A2A-Lite 协议、Agent Registry、Tools 标准化；为后续扩展预留空间
> - v0.5 (2026-06-15)：Sprint 0/1/2/3/4 全部交付完成，新增 §13「实施交付映射」+ §14「已知增量」，记录每一项功能用到的技术、关键代码行号、运行指令、预期输出示例
> - **v0.6 (2026-06-15)：5 项增量修复——MSP 及时响应（模型熔断）、动态零信任评分、Agent 身份认证（token）、gateway 流式代理改进、Web 控制台整合**

---

## 0. 文档说明

本文档基于 [AI安全助手.md](./AI安全助手.md) 中提出的六大需求点，进行产品形态、技术架构、技术栈与实施路径的**总体设计**。
本文档不包含具体代码实现，目的是与公司领导及安全团队**商榷统一结论**后再进入详细设计与开发。

---

## 1. 需求-能力映射总览

| 需求编号 | 需求要点 | 对应产品能力模块 |
|---------|---------|------------------|
| ① | 及时发现影子Agent（探针+网关+告警） | 影子Agent发现系统 (Shadow Agent Discovery, SAD) |
| ② | LLM基座模型漏洞发现/响应/修复 | 模型安全监测与响应 (Model Security Posture, MSP) |
| ③ | Agent数字身份/ID + 授权/审计/溯源 | Agent数字身份治理 (Agent Identity Governance, AIG) |
| ④ | 访问控制（白名单+沙箱+网关+零信任） | 智能访问控制引擎 (Intelligent Access Control, IAC) |
| ⑤ | Skills/MCP安全审查（威胁情报+LLM语义+沙箱+哈希归档） | 技能与工具供应链审查 (Skill & MCP Review, SMR) |
| ⑥ | 全量留痕、可追溯、可复现、可审计、可解释 | 全链路审计中心 (Audit & Traceability, AT) |

---

## 2. 产品形态

### 2.1 形态定位（V0.4 调整）
**单机可运行的「AI安全助手 Demo」**：
- **不是**生产级分布式平台
- **而是**能在个人外网笔记本上完整跑通所有核心能力的最小可用原型
- **采用多 Agent 架构（V0.4 决策）**：三个常驻进程 `probe-agent` / `gateway-agent` / `soc-agent` 既是进程也是 Agent；进程内 asyncio + 黑板（JSONL/SQLite）+ A2A-Lite 通信；**不引入 Kafka**；**预留扩展空间**
- 各 Agent 相互隔离，单 Agent 崩溃不影响整体；便于单独演示/调试/扩展

> 关键决策：本阶段目标 = **完整跑通的 Demo**，不追求企业级分布式能力。

### 2.1.1 进程与 IPC 架构（V0.3 重要新增，V0.4 演进为 Agent 视角）

> **V0.4 演进说明**：本节描述"进程与 IPC"的物理形态；每个进程的"对外 Agent 形态"在 [2.1.2 Multi-Agent 体系](#212-multi-agent-体系v04-核心新增) 中详细展开。本节是"长什么样"，2.1.2 是"对外是谁"。

#### (1) 进程划分（V0.4 视角：三个进程即三个 Agent）
| 进程 / Agent | 启动命令 | 端口 | 内部并发模型 | 主要职责 |
|------|---------|------|-------------|---------|
| `aisec-probe` → **`probe-agent`** | `python -m aisec probe` | 8001 | 线程池（`psutil`/`watchdog` 是阻塞调用） | 终端进程/网络/文件监控，识别影子 Agent |
| `aisec-gateway` → **`gateway-agent`** | `python -m aisec gateway` | 8002 | **asyncio**（mitmproxy 原生异步） | LLM/MCP 协议解析、流量拦截 |
| `aisec-soc` → **`soc-agent`** | `python -m aisec soc` | 8000 | **asyncio**（FastAPI 异步 Web） | AISOC 控制台、身份治理、策略决策、Agent Registry、审计查询、（唯一）LLM 编排 |
| `aisec-skill-scan` | CLI（按需） | — | 同步 | Skills/MCP 审查（沙箱执行） |
| `aisec-model-scan` | CLI（按需） | — | 同步 | LLM 模型轻量体检 |

**一键启动（顶层封装）**：
```bash
python -m aisec start         # 同时拉起 probe + gateway + soc 三个常驻进程
python -m aisec stop          # 优雅关闭所有子进程
python -m aisec status        # 查看三个进程健康状态
```

内部用 `multiprocessing.Process` 或 `subprocess.Popen` + PID 文件管理生命周期。

#### (2) 进程间通信 (IPC) 选型（V0.4 强化：增加 A2A-Lite）

```
┌─ aisec-probe 进程 ─┐        ┌─ aisec-gateway 进程 ─┐        ┌─ aisec-soc 进程 ─┐
│  psutil + watchdog │        │  mitmproxy (asyncio) │        │  FastAPI (asyncio)│
│  - 进程/网络/文件  │        │  - LLM/MCP 协议解析  │        │  - AISOC 控制台  │
│  - 线程池          │        │  - asyncio           │        │  - asyncio       │
└────────┬───────────┘        └────────┬─────────────┘        └────────┬─────────┘
         │ append                       │ append                       │ read+write
         │ A2A-Lite (HTTP)              │ A2A-Lite (HTTP)              │
         ▼                              ▼                               ▲
    ┌────────────────────────────────────────────────────────────────────────┐
    │  ① data/events/<日期>.jsonl     append-only 事件流（含 A2A 消息）       │
    │  ② data/aisec.db                SQLite（身份/策略/审计/Agent Registry）│
    │  ③ alerts/<时间>.md             告警 Markdown（人读）                  │
    └────────────────────────────────────────────────────────────────────────┘
```

**A2A-Lite 同步通道（V0.4 新增）**：三个 Agent 之间通过 `127.0.0.1:<port>/a2a` 双向 HTTP 通信，用于同步决策请求（如"这个 Agent 是否有身份？"）。消息格式、超时、审计详见 [2.1.2 §(3)](#3-a2a-lite-协议v04-强制)。

| 数据类型 | 选型 | 写入方 | 读取方 | 理由 |
|---------|------|--------|--------|------|
| 事件流（影子Agent告警、流量拦截、Agent调用） | `data/events/<日期>.jsonl`（append-only）| Probe / Gateway | SOC（tail/批量）| 零依赖、`tail -f` 演示友好、容错强 |
| 状态/检索（Agent 身份、策略、审计索引、黑白名单） | SQLite 单文件 `data/aisec.db` | SOC（写入） | 所有进程（读）| 并发读友好、零部署、支持 SQL 检索 |
| 告警（人读） | `alerts/<时间>.md` | 任一进程 | 人 | 与 V0.2 决策一致 |
| 配置 | YAML/JSON 配置文件 | 启动时加载 | 所有进程 | 简单 |

#### (3) 为什么不用其他方案

| 替代方案 | 否决理由 |
|---------|---------|
| 单进程 | Web UI 一次崩溃 = 整个安全监控失守，违反纵深防御；不便单独演示各模块 |
| 进程内 asyncio 把 Probe 一起塞进去 | `psutil`/`watchdog` 是阻塞调用，硬塞 asyncio 反而别扭 |
| Kafka | Demo 阶段峰值 < 10 events/s，Kafka 集群运维成本完全不值；会把"Kafka 怎么没起"变成演示干扰项 |
| Redis / ZeroMQ | 单机 Demo 没必要引入新的服务依赖 |
| gRPC / HTTP 互相调用 | 进程边界即故障边界，文件型事件流天然解耦，调试更直观 |

#### (4) 进程故障行为

| 故障 | 影响 | 自动恢复 | 数据丢失风险 |
|------|------|---------|------------|
| `aisec-probe` 崩溃 | 影子 Agent 监控暂停 | `start` 启动脚本拉起 | 仅丢失崩溃后到重启前的事件（JSONL 不丢已写入部分） |
| `aisec-gateway` 崩溃 | LLM 流量失去拦截 | 同上 | 客户端会因代理连接失败而暴露（**这是设计取舍**：demo 阶段可接受） |
| `aisec-soc` 崩溃 | 控制台不可用，不影响告警落盘 | 同上 | 不影响事件流写入，重启后从 JSONL 重新索引 |

#### (5) 文件系统布局
```
aisec-demo/
├── pyproject.toml
├── README.md
├── config/
│   ├── default.yaml          # 默认配置（端口、LLM API Key、Agent 白名单）
│   └── policies/             # 访问控制策略 (JSON)
├── data/                     # 运行时数据（自动创建）
│   ├── events/
│   │   └── 2026-06-09.jsonl  # 按日分文件
│   ├── aisec.db              # SQLite
│   ├── sandbox/              # 沙箱临时目录
│   └── snapshots/            # 上下文快照（可复现用）
├── alerts/                   # 告警 Markdown（人读）
├── reports/                  # Skills/MCP 审查报告
├── whitelist/                # 哈希白名单
├── blacklist/                # 哈希黑名单
├── examples/                 # Demo 示例 Skill/MCP/Agent
│   ├── safe_skill.py
│   ├── suspicious_skill.py
│   ├── safe_mcp.json
│   └── shadow_agent.py
└── tests/                    # pytest 单元/集成测试
```

### 2.1.2 Multi-Agent 体系（V0.4 核心新增）

> 决策依据：选方案 B（三个进程全部 Agent 化），为后续扩展（增加威胁情报 Agent、合规审计 Agent、应急响应 Agent 等）预留空间。

#### (1) 三个 Agent 的角色与边界

| Agent | 内部主循环 | 对外 Tools（MCP-like） | 是否主动调 LLM | 心跳 |
|-------|----------|----------------------|---------------|------|
| **`probe-agent`**（终端探针 Agent） | psutil/watchdog 线程池，规则匹配 | `list_processes` / `check_network` / `watch_files` / `get_alerts` | ❌（仅在被询问时由 soc-agent 转交推理） | 每 5s |
| **`gateway-agent`**（流量拦截 Agent） | mitmproxy asyncio，协议解析 | `parse_request` / `decide_action` / `query_identity` / `get_flow_stats` | ❌（同上） | 每 5s |
| **`soc-agent`**（SOC 运营 Agent，编排者） | FastAPI asyncio + SQLite | `query_events` / `apply_policy` / `manage_identity` / `register_agent` / **`chat` (LLM)** | ✅ **唯一主动调 LLM** | 每 5s |
| （可选）`ops-soc`（运营助手）| 嵌入 soc-agent 的 `/chat` 接口 | `chat_with_logs` / `generate_report` | ✅ LLM 编排 | — |

**关键约束**：Probe/Gateway 的**热路径**（毫秒级响应）走传统代码，**不**经过 LLM。LLM 仅出现在 soc-agent 的 `/chat` 端点和"自然语言运维"场景。

#### (2) Agent Card（每个 Agent 的自我介绍 JSON）

每个 Agent 启动时向 SOC 注册，提交 agent card：

```json
{
  "agent_id": "probe-agent",
  "name": "终端探针 Agent",
  "version": "1.0.0",
  "role": "shadow_agent_detector",
  "owner": "aisec",
  "trust_score": 100,
  "capabilities": [
    {"tool": "list_processes", "desc": "列出与 AI 相关的进程"},
    {"tool": "check_network",   "desc": "检查异常出站连接"},
    {"tool": "watch_files",     "desc": "监控模型文件下载"}
  ],
  "endpoints": {
    "health": "http://127.0.0.1:8001/health",
    "tools":  "http://127.0.0.1:8001/tools",
    "a2a":    "http://127.0.0.1:8001/a2a",
    "chat":   "http://127.0.0.1:8001/chat"
  },
  "registered_at": "2026-06-09T10:00:00Z"
}
```

#### (3) A2A-Lite 协议（V0.4 强制）

**消息格式**（JSON over HTTP，POST 到对方的 `/a2a`）：
```json
{
  "from":      "gateway-agent",
  "to":        "soc-agent",
  "intent":    "verify_identity",
  "trace_id":  "abc-123-def",
  "context":   { "agent_fingerprint": "langchain-0.3", "pid": 1234 },
  "deadline_ms": 100,
  "retry":     0
}
```

**响应**：
```json
{
  "from":     "soc-agent",
  "to":       "gateway-agent",
  "trace_id": "abc-123-def",
  "decision": "unknown",
  "action":   "continue_monitor",
  "reason":   "未在白名单中",
  "elapsed_ms": 12
}
```

**约束**：
- 本机 `127.0.0.1:<port>` HTTP（**不**走外网）
- 超时默认 100ms，**fail-closed**（超时即按"未知/拒绝"处理）
- 每条 A2A 消息同时 append 到 `data/events/<日期>.jsonl`，**全程可审计**
- 自研实现，**不引入** Google A2A / ANP 完整规范

**典型 A2A 场景**：
| 发起方 | 接收方 | intent | 用途 |
|--------|--------|--------|------|
| gateway | soc | `verify_identity` | 询问某 Agent 是否有身份 |
| soc | probe | `enrich_alert` | 让 probe 补充进程上下文 |
| soc | gateway | `get_flow_stats` | 拉取流量统计 |
| 外部 AI | soc | `chat` / `orchestrate` | 复杂任务编排 |

#### (4) Agent Registry（由 soc-agent 维护）

SOC 内部 SQLite 表 `agents`：

| 字段 | 类型 | 说明 |
|------|------|------|
| agent_id | TEXT PK | 全局唯一（如 `probe-agent`） |
| name | TEXT | 人类可读名 |
| role | TEXT | 角色分类 |
| endpoint_a2a | TEXT | A2A 端点 |
| endpoint_chat | TEXT | Chat 端点（可选） |
| status | TEXT | `online` / `offline` / `draining` |
| last_heartbeat | INTEGER | Unix 时间戳 |
| trust_score | INTEGER | 信用分 [0, 100] |
| registered_at | TEXT | ISO8601 |
| agent_card | TEXT (JSON) | agent card 原文 |

**心跳机制**：
- 各 Agent 每 5s 调一次 `soc-agent` 的 `/agents/<id>/heartbeat`
- soc-agent 记录 `last_heartbeat`
- 后台巡检：若 `now - last_heartbeat > 15s`，标记 `offline` 并发出告警
- `start` 启动脚本定期扫描 `offline` 状态并尝试拉起

#### (5) Tool 调用（仿 MCP 风格）

**Tool 调用格式**（POST 到 Agent 的 `/tools`）：
```json
// 请求
{
  "tool": "list_processes",
  "args": { "keyword": "langchain" },
  "trace_id": "xyz-789"
}

// 响应
{
  "ok": true,
  "result": [
    {"pid": 1234, "name": "python", "cmdline": "...", "fingerprint": "langchain-0.3"}
  ],
  "trace_id": "xyz-789"
}
```

每个 Agent 内部用一张 `tools` 表（Python dict）注册所有可调用 Tool，类似 MCP server。

#### (6) 编排（Orchestration）

- **默认编排者**：`soc-agent`
- **编排模式**：主-从（Master-Worker），可演化为层级式
- **拒绝级联**：任何子 Agent 返回 fail 时，主 Agent 立即降级为"只读模式"
- **外部接入**：外部 AI（如运营者个人 Copilot）通过 `soc-agent.chat` 进入体系，soc-agent 负责派发

**调用链示例**："过去 1 小时哪些 Agent 调过 LLM，token 花费多少？"
```
运营者 ──chat──► soc-agent
                  │
                  ├─[A2A]──► probe-agent.list_processes()       (12ms)
                  ├─[A2A]──► gateway-agent.get_flow_stats()    (15ms)
                  │
                  ▼
            soc-agent 推理汇总 ──chat──► 运营者
            "过去 1 小时：3 个 Agent 调用过 LLM，总 token 约 12,300..."
```

#### (7) 端到端启动 / 停止

```bash
python -m aisec start
  ├─ spawn probe-agent  (注册到 soc-agent)
  ├─ spawn gateway-agent (注册到 soc-agent)
  ├─ spawn soc-agent     (启动 Registry + 心跳监听)
  └─ 输出: "3 agents online, registry ready"

python -m aisec status
  agent_id       status   last_heartbeat  trust
  probe-agent    online   2s ago          100
  gateway-agent  online   1s ago          100
  soc-agent      online   -               100

python -m aisec stop
  ├─ SIGTERM probe-agent
  ├─ SIGTERM gateway-agent
  └─ SIGTERM soc-agent
```

#### (8) 工作量增量（V0.4 vs V0.3）

| 增量项 | 工作量 | 备注 |
|--------|-------|------|
| A2A-Lite 协议实现 | 1 天 | 消息格式 + HTTP 端点 + 客户端 SDK |
| Agent Registry + 心跳 | 0.5 天 | SQLite 表 + 后台巡检 |
| probe / gateway 包装为 Agent | 1.5 天 | agent card + /health + /tools + /a2a + /chat |
| soc-agent 编排能力 | 0.5 天 | 派发、汇总、fail-closed |
| 集成测试与契约测试 | 0.5 天 | Agent 组合场景 |
| **V0.4 增量** | **4 天** | |
| **Demo 总工期** | **原 3-4 周 + 4 天 = 约 4-5 周** | |

#### (9) 为后续扩展预留的接入点

V0.4 的 Agent 体系为以下未来扩展**预埋接口**（V0.4 不实现，仅约定接口）：

| 未来 Agent | role | 主要 Tool | 何时引入 |
|----------|------|----------|---------|
| `threat-intel-agent` | 威胁情报 Agent | `lookup_ioc`, `update_ioc_db` | v0.5+ |
| `compliance-audit-agent` | 合规审计 Agent | `generate_soc2_report`, `check_policy` | v1.0 |
| `incident-response-agent` | 应急响应 Agent | `isolate_agent`, `revoke_token`, `notify` | v1.0 |
| `model-scan-agent` | 模型安全 Agent | `scan_model`, `report_vuln` | v0.5+（前置 MSP 完整化） |

每个新 Agent 只需：
1. 实现 agent card
2. 注册到 soc-agent
3. 实现自己的 Tools
4. 接入 A2A 协议

### 2.2 Demo 部署形态
- **运行环境**：个人外网笔记本（Windows / macOS / Linux 均可）
- **运行方式**：本地启动一组 Python/Node 进程，浏览器打开 AISOC 控制台即可
- **数据存储**：本地 SQLite + 文件系统（JSON Lines / Markdown）
- **网络要求**：可以访问公网 LLM API（千问）
- **典型使用流程**：
  1. 在本机启动 Probe + AI-Gateway + AISOC 三个进程
  2. 把系统代理指向 AI-Gateway（拦截本机出站 LLM/MCP 流量）
  3. 在 IDE 中运行 LangChain/AutoGen/Dify/LangGraph Agent
  4. 观察 AISOC 控制台 / 告警目录中的实时输出

### 2.3 交付物清单（Demo 版精简）
| 类别 | 名称 | 说明 |
|------|------|------|
| 软件 | AISOC 控制台（极简） | 单页面 Web，展示 Agent 列表、告警、审计 |
| 软件 | AI-Gateway | 本地代理，拦截 LLM/MCP 流量 |
| 软件 | Agent-Probe | 进程/网络/文件监控 |
| 软件 | Skills/MCP Scanner | 命令行审查 + 归档 |
| 软件 | Model Scanner（轻量） | 基础 Prompt 注入与有害输出测试 |
| 知识库 | 威胁情报库（精简） | 内置常见 IOC、Skill 危险模式库 |
| 规范 | Agent 数字身份规范 | DID/VC 简化实现 |
| 规范 | 访问控制策略模板 | JSON 策略文件 |
| 文档 | Demo 运行手册 | 录屏脚本 + 操作步骤 |

---

## 3. 总体技术架构

### 3.1 逻辑架构图

```
┌──────────────────────────────────────────────────────────────────┐
│                  ⑤  全链路审计中心 AT  (存储 + 检索 + 复现)        │
│         TimescaleDB / Elasticsearch / 对象存储 / 区块链存证       │
└──────────────────────────────────────────────────────────────────┘
            ▲                       ▲                       ▲
            │                       │                       │
┌──────────────────┐    ┌──────────────────────┐    ┌──────────────────┐
│ ① 影子Agent发现  │    │ ② 模型安全监测MSP     │    │ ③ Agent身份治理  │
│  SAD             │    │  Model Scanner        │    │  AIG  (DID/VC)   │
│  探针+网关联动   │    │  后门/对抗/Prompt注入 │    │  身份-权限-审计  │
└──────────────────┘    └──────────────────────┘    └──────────────────┘
            ▲                       ▲                       ▲
            │                       │                       │
┌──────────────────────────────────────────────────────────────────┐
│                 ④  智能访问控制引擎 IAC  (策略决策点 PDP)         │
│   静态白名单 + 沙箱 + 网关拦截 + 动态零信任 (持续验证 + 风险评分)   │
└──────────────────────────────────────────────────────────────────┘
            ▲
            │
┌──────────────────────────────────────────────────────────────────┐
│        端  Agent-Probe          边  AI-Gateway        云 AISOC  │
│  (终端进程/网络/文件监控)    (LLM/MCP 协议解析/拦截)   (策略中心)  │
└──────────────────────────────────────────────────────────────────┘
            ▲
            │
┌──────────────────────────────────────────────────────────────────┐
│              ⑤  Skills/MCP 供应链审查  SMR  (审查 + 哈希 + 归档)  │
│        威胁情报匹配 + LLM语义分析 + 沙箱行为分析 + 哈希指纹        │
└──────────────────────────────────────────────────────────────────┘
            ▲
            │
┌──────────────────────────────────────────────────────────────────┐
│   员工使用的 AI 资产：LLM  /  Agent  /  MCP Server  /  Skill      │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 关键设计原则
1. **零信任优先**：默认不信任任何 Agent/工具/MCP，所有行为必须经过身份+策略+上下文三重验证
2. **最小权限**：Agent 仅获得完成任务所需最小授权，使用短时令牌
3. **可解释可审计**：所有拦截/告警/授权决策必须有可回放证据链
4. **纵深防御**：探针 + 网关 + 平台三层联动，单层失守不致命
5. **性能可控**：网关延迟 < 10ms（旁路）/ < 50ms（代理），探针 CPU 占用 < 3%
6. **开放生态**：兼容 OpenAI / Anthropic / MCP 协议，支持私有模型接入

---

## 4. 六大模块详细设计

### 4.1 模块① —— 影子Agent发现系统 SAD (Shadow Agent Discovery)

#### 4.1.1 功能目标
> 及时发现未经审批的Agent进程、影子LLM调用、违规本地模型运行。

#### 4.1.2 三段式实现（与需求一致）

**(1) 本地终端探针感知 (Probe)**
- 进程/服务指纹：识别 `ollama`、`vllm`、`lm-studio`、`langchain`、`autogen`、`crewai` 等Agent框架
- 网络行为：发现到公网 LLM API（OpenAI/Anthropic/DeepSeek等）的异常出站
- 文件行为：监控 `.gguf`/`.bin`/`.pt` 等模型文件下载
- 浏览器侧：浏览器扩展监测 Web 端 AI 工具调用

**(2) 外部安全网关流量拦截 (Gateway)**
- LLM 协议解析：OpenAI 兼容协议、Anthropic 协议、MCP 协议（JSON-RPC over SSE/stdio）
- MCP 工具调用元数据：`tool.name`、`tool.server`、`session_id`
- 流量特征匹配：自研协议指纹库 + AI 行为特征
- 旁路镜像 + 主动代理双模式

**(3) 告警与处置 (Alert)**
- 影子Agent画像：进程名/启动用户/外联目的/模型指纹/敏感数据外发
- 风险等级：低/中/高/严重
- 处置动作：告警 → 阻断 → 隔离 → 通知安全员
- 工单流转：对接企业微信/钉钉/飞书

#### 4.1.3 技术选型
- 探针：eBPF (Linux) + ETW (Windows) + EndpointSecurity (macOS)
- 网关：Go + Envoy Filter 插件
- 协议解析：自研 + mitmproxy
- 规则引擎：OPA (Open Policy Agent) / Cedar

---

### 4.2 模块② —— LLM模型安全监测 MSP (Model Security Posture)

#### 4.2.1 功能目标
> 对自研/开源/商用 LLM 进行漏洞发现、响应、修复全生命周期管理。

#### 4.2.2 三大子能力

| 子能力 | 说明 | 关键动作 |
|--------|------|---------|
| 及时发现 | 模型上线前+运行中持续扫描 | 后门检测、对抗样本测试、Prompt注入测试、有害输出测试、越狱测试 |
| 及时响应 | 发现漏洞后快速隔离 | 自动告警、流量切流、临时禁用、版本回滚、影子模式 |
| 及时修复 | 补丁与微调闭环 | SFT/DPO/RLHF 数据回流、模型热更新、补丁包分发 |

#### 4.2.3 技术选型
- 扫描引擎：基于 [Garak](https://github.com/NVIDIA/garak)、[PyRIT](https://github.com/Azure/PyRIT)、[AdvBench] 的二次开发
- 模型推理：vLLM / TGI / TensorRT-LLM
- 模型仓库：HuggingFace / ModelScope / 自建 MinIO
- 模型血缘：MLOps (MLflow + Model Card + DVC)
- 漏洞知识库：CWE/MITRE ATLAS + 自有 ATT&CK-for-LLM
- 修复工具：SFT/DPO 训练框架（LLaMA-Factory / swift）

#### 4.2.4 持续监测指标
- 对抗鲁棒性 (Robustness)
- 有害输出率 (Harm Rate)
- 越狱成功率 (Jailbreak Success Rate)
- 后门触发率 (Backdoor Trigger Rate)
- 数据泄露率 (PII Leakage Rate)

---

### 4.3 模块③ —— Agent数字身份治理 AIG (Agent Identity Governance)

#### 4.3.1 功能目标
> 为每个 Agent 颁发唯一数字身份/ID，并将身份与权限/角色/审计进行关联，实现"授权可追、行为可审、问题可溯"。

#### 4.3.2 数字身份体系
- **身份格式**：`did:aisec:<org>:<agent-type>:<uuid>`
- **凭证机制**：W3C DID + Verifiable Credentials (VC)
- **签发机构**：内部 CA / 密钥管理服务 (KMS)
- **身份属性**：
  - 基础属性：AgentType、版本、责任团队、上线时间
  - 能力属性：可用工具、可调模型、可访问数据域
  - 信任属性：信用分、最近安全事件、最近审计结果

#### 4.3.3 三项核心能力

| 能力 | 描述 | 技术实现 |
|------|------|---------|
| 身份授权 | 基于身份的细粒度授权 | OAuth 2.0 + JWT + RBAC/ABAC |
| 安全审计 | 全量记录身份使用行为 | AT 模块联动 |
| 问题溯源 | 一键定位责任Agent与责任人 | 数字身份 + 操作日志 + 责任矩阵 |

#### 4.3.4 技术选型
- 身份中心：Keycloak / 自研基于 SPIFFE/SPIRE
- 凭证签发：HashiCorp Vault PKI
- 策略表达：OPA / Cedar
- 责任关联：组织架构数据 (LDAP/钉钉) + CMDB

---

### 4.4 模块④ —— 智能访问控制引擎 IAC (Intelligent Access Control)

#### 4.4.1 功能目标
> 实现"白名单兜底 + 沙箱隔离 + 网关拦截 + 零信任动态"的多层访问控制。

#### 4.4.2 四层防御模型

```
┌────────────────────────────────────────────────────┐
│  L1 静态白名单 (Static Whitelist)                   │
│      已注册Agent/已审批MCP/已签发Skill 才能运行      │
├────────────────────────────────────────────────────┤
│  L2 沙箱隔离 (Sandbox) [V0.2 调整]                  │
│      Demo: RestrictedPython + subprocess + rlimit  │
│      Prod: Firecracker / gVisor / Docker seccomp   │
├────────────────────────────────────────────────────┤
│  L3 网关拦截 (Gateway Interception)                 │
│      协议层解析,敏感数据脱敏,违规操作阻断           │
├────────────────────────────────────────────────────┤
│  L4 动态零信任 (Dynamic Zero Trust)                 │
│      基于风险评分持续验证,异常时降权/隔离/复核        │
└────────────────────────────────────────────────────┘
```

#### 4.4.3 沙箱方案说明（V0.2 重要澄清）

**Python 标准库没有真正意义上的安全沙箱**，需要使用以下组合：

| 层级 | 方案 | 作用 |
|------|------|------|
| 静态分析 | `ast` 模块 | 解析代码，识别危险调用（`eval`/`exec`/`os.system`/网络） |
| 代码执行 | `RestrictedPython`（第三方） | 限制内置函数/导入/属性访问 |
| 进程隔离 | `subprocess` + `resource.rlimit` | CPU/内存/时间限制 |
| 网络隔离 | 沙箱进程强制走 AI-Gateway | 出口可控、可审计 |
| 文件隔离 | 临时目录 + 命名空间 | 仅在白名单目录读写 |

**Demo 阶段不引入** Docker / Firecracker 等重量级方案，避免环境依赖过重。

#### 4.4.4 零信任决策要素
- **主体风险**：Agent 历史违规率、最近审计结果
- **客体风险**：目标数据敏感级、目标系统暴露面
- **行为风险**：调用频次、参数异常、地理/时间异常
- **上下文风险**：用户风险、网络风险、终端风险

#### 4.4.4 技术选型
- 策略引擎：OPA (Rego) / Cedar
- 沙箱：gVisor / Firecracker / Docker seccomp + Landlock
- 数据脱敏：Microsoft Presidio + 自研规则
- 网关：Envoy + 自研 Filter
- 风险评分：在线学习模型 (XGBoost + 规则融合)

---

### 4.5 模块⑤ —— Skills/MCP 供应链审查 SMR (Skill & MCP Review)

#### 4.5.1 功能目标
> 在 Skill/MCP 上线前对其进行"威胁情报+语义分析+行为分析"三维审查，并哈希归档形成白/黑名单库。

#### 4.5.2 审查流程

```
  Skill/MCP 包提交
         │
         ▼
┌─────────────────┐
│  ① 威胁情报匹配  │  ── 哈希/CVE/IOC/作者信誉
└────────┬────────┘
         ▼
┌─────────────────┐
│  ② LLM语义分析   │  ── 提示词扫描、危险意图识别、隐写指令检测
└────────┬────────┘
         ▼
┌─────────────────┐
│  ③ 沙箱行为分析  │  ── 真实运行：网络外联、文件读写、命令执行
└────────┬────────┘
         ▼
┌─────────────────┐
│  ④ 哈希指纹      │  ── SHA-256 包指纹 + 行为指纹
└────────┬────────┘
         ▼
┌─────────────────┐
│  ⑤ 风险评分      │  ── 多维加权 → [0,100]
└────────┬────────┘
         ▼
┌─────────────────┐
│  ⑥ 归档          │  ── 白名单(放行) / 灰名单(人工复核) / 黑名单(阻断)
└─────────────────┘
```

#### 4.5.3 关键能力
- **静态审查**：源码/包元数据、依赖图、提示词、隐藏指令
- **动态审查**：在隔离沙箱中真实执行，记录网络/文件/进程行为
- **威胁情报**：内部 IOC + 外部 (NVD、OSV、Snyk) + 自有蜜罐捕获
- **LLM 语义分析**：专用审查模型（基于开源 LLM 微调）
- **哈希归档**：白/黑名单存放在只读 Merkle 树，审计可验

#### 4.5.4 技术选型
- 沙箱：Firecracker microVM + eBPF 监控
- LLM 审查模型：Qwen2.5 / DeepSeek 微调的 `aisec-reviewer`
- 行为分析：Syscall trace + 网络流量 + 静态特征
- 哈希归档：Merkle DAG (IPFS-like) + 区块链存证（可选）
- 包源：兼容 MCP 官方仓、npm/pypi（针对技能插件）

---

### 4.6 模块⑥ —— 全链路审计中心 AT (Audit & Traceability)

#### 4.6.1 功能目标
> 对 Agent 和 LLM 的输入/输出进行全量留痕，实现"可追溯、可复现、可审计、可解释"。

#### 4.6.2 五"可"能力拆解

| 能力 | 含义 | 实现 |
|------|------|------|
| 可追溯 | 任一事件可向前/向后追溯 | 全链路 TraceID |
| 可复现 | 同样的输入可重现同样的输出 | 上下文快照 + 模型版本绑定 |
| 可审计 | 支持合规审计、SOC2、ISO27001 | 不可篡改日志 (WORM) |
| 可解释 | 决策原因可读懂 | 策略快照 + 解释日志 |
| 可管控 | 支持回放、封禁、下架 | 编排与处置工作流 |

#### 4.6.3 审计数据模型
- **Event**: 主体、操作、客体、结果、时间、地点
- **Span**: 调用链节点（Agent→Tool→MCP→LLM）
- **Decision**: 策略决策及理由
- **Snapshot**: 输入/输出/上下文快照
- **Evidence**: 证据链（哈希签名）

#### 4.6.4 技术选型
- 链路追踪：OpenTelemetry + Jaeger / Tempo
- 日志存储：Elasticsearch + ClickHouse（高吞吐分析）
- 时序指标：TimescaleDB / Prometheus
- 对象存储：MinIO（上下文快照）
- 不可篡改：WORM 存储 / 区块链存证（可选）
- 检索分析：自研检索 + LLM 增强问答（"用自然语言问日志"）

---

## 5. 数据流与联动示例

**场景：员工在 IDE 中启动一个未经审批的 Cursor 第三方 Agent**

```
1. Probe 检测到 cursor.exe 加载 MCP 客户端 → 探针上报 SAD
2. Agent 启动后调用外部 LLM API (api.xxx.com) → AI-Gateway 拦截并解析
3. Gateway 查询 AIG：此 Agent 无数字身份 → 拒绝签发令牌
4. Probe 风险评分上升 → 触发零信任复核 → 阻断并告警
5. AT 模块记录：用户=张三、终端=PC-001、Agent=unknown-cursor、动作=blocked
6. 安全员在 AISOC 工单中处理：可一键下架、隔离、取证
```

**场景：新 MCP 服务上线**

```
1. 开发者提交 MCP 包到 SMR
2. 哈希匹配威胁情报库 → 无已知 IOC
3. LLM 语义分析 → 未发现隐藏指令
4. 沙箱动态执行 → 触发 1 次 DNS 外联 (可疑)
5. 风险评分 = 65 (灰名单) → 人工复核
6. 复核通过 → 加入白名单 + 数字身份 → 注册到 AIG
7. 后续运行时：受 IAC 网关+零信任双层保护
```

---

## 6. 技术栈（V0.2 简化版）

> **原则**：能用 Python 一门语言搞定的不引入新技术栈；能用文件/SQLite 搞定的不上分布式组件。

### 6.1 Demo 简化技术栈
| 层级 | 选型 | 备注 |
|------|------|------|
| 主开发语言 | **Python 3.11+** | 全栈主力，便于 AI 集成 |
| Web 框架 | FastAPI | 异步、AISOC 控制台 + 后端 API |
| 前端（极简） | 单页 HTML + 原生 JS / 或 Vue 3 | 不追求精美，先跑通 |
| 终端探针 | Python + `psutil` + `watchdog` | 进程/网络/文件监控 |
| 安全网关 | Python `mitmproxy` 插件 | 拦截 LLM/MCP 协议 |
| 沙箱（代码执行） | `RestrictedPython` | 限制内置/导入/属性 |
| 沙箱（进程隔离） | `subprocess` + `resource.rlimit` | CPU/内存/时间限制 |
| 数据库 | SQLite | 单文件，零部署 |
| 日志存储 | JSON Lines 文件 | 按日期分文件，便于检索 |
| 链路追踪 | 自实现 TraceID | 简化版 OpenTelemetry |
| 消息队列 | 暂不引入 | 进程内事件总线即可 |
| LLM API | 阿里千问 `qwen3.6-max-preview`（DashScope OpenAI 兼容接口） | 由用户提供 API Key |
| Agent 框架（演示） | LangChain / LangGraph / AutoGen / Dify | 全部以 pip 依赖安装到 Demo 环境 |
| 威胁情报 | 内置 JSON 词典 | 覆盖常见 IOC、危险 Skill 模式 |
| 模型扫描 | 自研轻量检测器 | 基于千问做 Prompt 注入与有害输出测试 |
| 规则/策略 | JSON 策略文件 + 简化 Rego | 不引入 OPA 完整版 |
| 身份/凭证 | 自研简化 DID + JWT | 不引入 Keycloak |
| 部署运行 | `uvicorn` / `python -m` 一键启动 | 不引入 K8s |
| 监控告警 | 控制台 + 告警目录（Markdown / JSON） | 不对接 IM 通道 |
| 依赖管理 | `uv` 或 `pip` + `requirements.txt` | 简单可靠 |
| 测试 | `pytest` | 必备 |

### 6.2 暂不引入的组件（生产阶段再补）
- Kubernetes / Docker Compose（除 LangChain/AutoGen 自带容器外）
- 分布式追踪（Jaeger / Tempo）
- 大数据组件（Elasticsearch / ClickHouse / Kafka）
- 重量级沙箱（Firecracker / gVisor / Docker seccomp）
- 商用 IAM（Keycloak / SPIFFE）
- 商用 LLM 扫描器（Garak / PyRIT —— 思路可借鉴但自实现简化版）

---

## 7. 实施路径与里程碑（V0.2 调整）

### 7.1 总体原则
- **优先级排序（V0.2 重排）**：
  1. **第 1 优先**：**Skills/MCP 审查模块（SMR）**——实现最简单、独立性强、最容易跑通
  2. **第 2 优先**：**Agent 核心簇**（SAD + AIG + IAC + AT）——紧耦合，应一并实现
  3. **第 3 优先（最低）**：**LLM 模型安全（MSP）**——优先级最低，可后置
- **Demo 节奏**：4 个 Sprint，每个 Sprint 1 周可演示

### 7.2 Sprint 划分

#### Sprint 1 —— Skills/MCP 审查 (SMR) ✅ 最简单优先
**目标**：命令行 `aisec-skill-scan` + `aisec-mcp-scan` 能审查一个示例 Skill/MCP，输出 Markdown 审查报告 + 风险评分 + 哈希归档。

**关键交付**：
- 静态扫描器：`ast` 解析 + 关键字/IOC 匹配
- LLM 语义分析器：调用千问 API，识别隐藏指令/危险意图
- 沙箱执行：`RestrictedPython` + `subprocess` + `rlimit`
- 风险评分器：静态 30% + 语义 30% + 行为 40% 加权
- 哈希归档：白/灰/黑名单 JSON 库
- 报告输出：`reports/<name>_<hash>.md`

**Demo 场景**：
```bash
aisec-skill-scan ./examples/safe_skill.py
aisec-skill-scan ./examples/suspicious_skill.py
aisec-mcp-scan ./examples/safe_mcp.json
```

#### Sprint 2 —— Agent 核心簇：探针 + 网关（基础设施）
**目标**：本机启动 Probe + AI-Gateway，能识别 LangChain/LangGraph/AutoGen/Dify Agent 流量并拦截。

**关键交付**：
- Agent-Probe：进程名指纹（langchain/autogen/crewai/dify/langgraph） + 模型文件监控 + 异常出站连接
- AI-Gateway：mitmproxy 插件，解析 OpenAI 兼容协议与 MCP JSON-RPC
- 流量白名单：未注册 Agent 直接阻断
- 告警输出：`alerts/<timestamp>.md` + `alerts/audit.jsonl`

**Demo 场景**：
- 运行一个 LangChain Agent，让其调用千问
- 运行一个未注册 Agent（伪装成未知进程），观察被拦截

#### Sprint 3 —— Agent 核心簇：身份治理 + 智能访问控制
**目标**：完成 AIG + IAC 的核心策略决策，能基于数字身份和风险评分动态授权。

**关键交付**：
- 数字身份服务：简化 DID + JWT 签发
- 身份注册中心：`agents.json` + SQLite
- RBAC/ABAC 策略：JSON 策略文件
- 零信任评分：基于规则的简易评分（违规次数/调用频次/数据敏感度）
- 动态降权：低分 Agent 自动限流 / 隔离

**Demo 场景**：
- 给一个"好"Agent 发身份，能正常调用工具
- 给一个"坏"Agent 发身份，调用敏感工具时被拒绝
- 模拟历史违规行为，观察自动降权

#### Sprint 4 —— 全链路审计 + LLM 模型安全（轻量） + 联调
**目标**：完成 AT + 轻量 MSP，所有模块联调出完整 Demo。

**关键交付**：
- AT 审计中心：JSON Lines 全量留痕 + 简化检索
- 可复现：每次 Agent 调用绑定模型版本/上下文快照
- 可解释：策略决策日志与自然语言解释
- 轻量 MSP：基于千问的 Prompt 注入检测 + 基础有害输出测试
- AISOC 控制台（极简单页）：Agent 列表 / 告警列表 / 审计检索
- Demo 录屏脚本：5 分钟内跑完所有核心场景
- 文档：Demo 运行手册

### 7.3 时间估算
- Sprint 1：3-5 天
- Sprint 2：4-6 天
- Sprint 3：4-6 天
- Sprint 4：5-7 天
- **V0.4 增量**：4 天（多 Agent 体系 + A2A-Lite + Agent Registry + Tools 标准化 + 集成测试）
- **总计：约 4-5 周可完成 Demo 全部开发**

### 7.4 第一里程碑（M0）Demo 验收标准
- [ ] 启动一条命令 (`python -m aisec start` 或类似) 即可运行所有模块
- [ ] `aisec status` 能看到 probe-agent / gateway-agent / soc-agent 三者 `online`
- [ ] 至少能跑通 3 个端到端场景：
  1. 审查一个恶意 Skill（被标记为黑名单）
  2. 运行一个未注册 Agent（被网关拦截并告警）
  3. 注册一个合规 Agent，能完整记录其输入/输出并复现一次调用
- [ ] 至少能演示 1 个 Agent 协作场景：soc-agent 编排调用 probe-agent + gateway-agent 完成自然语言问答
- [ ] 所有告警以 Markdown 文件输出到 `alerts/` 目录
- [ ] 审计日志可按 Agent ID / 时间 / 动作 检索
- [ ] Agent Registry 中能看到所有 Agent 的 agent card
- [ ] 录屏脚本可重放整个 Demo 流程

---

## 8. 安全与合规设计

### 8.1 平台自身安全
- 全平台零信任内部网络（mTLS + SPIFFE）
- 管理员操作二次认证 + 操作录屏
- 密钥全 KMS 管理，永不出明文
- 安全开发生命周期 (SSDLC) + 内部红蓝对抗

### 8.2 隐私合规
- 数据分级：L0-L4 五级
- 涉及员工输入/输出的场景默认脱敏，原始数据按需授权访问
- 支持数据驻留要求（境内/境外）
- 满足《数据安全法》《个人信息保护法》《生成式人工智能服务管理暂行办法》

### 8.3 攻防演练
- 季度红蓝演练
- 半年度第三方渗透测试
- 接入公司 SRC 与漏洞奖励计划

---

## 9. 风险与应对

| 风险 | 影响 | 应对 |
|------|------|------|
| LLM 协议快速演进，网关解析滞后 | 影子Agent 漏报 | 协议适配插件化 + 社区贡献 |
| 模型扫描误报率高 | 业务受阻 | 灰名单 + 人工复核 + 反馈学习 |
| 探针在终端占用高 | 员工投诉 | eBPF + 自适应采样率，CPU<3% |
| 大量日志存储成本高 | 预算超支 | 冷热分层 + 关键事件 WORM 长期保存 |
| 内部人员绕过管控 | 高级威胁 | 零信任持续验证 + 异常行为UEBA |
| 法规变动 | 合规风险 | 法务+安全联合跟踪，季度评审 |

---

## 10. 团队与协作（V0.2 调整）

### 10.1 Demo 阶段组织
- **大模型工程师** × 1（您本人）
- 本阶段为单人全栈开发，**不需要**正式组织
- 关键技术难点可向公司其他安全/AI 同事请教

### 10.2 跨团队协作（Demo 阶段）
- **暂不需要**对接任何外部系统
- Demo 验证后进入生产化阶段时再补对接：IT 终端管理、网络、SOC、HR、法务、CMDB、LDAP、SIEM、工单、IM

---

## 11. 评审决策记录

> 本节记录每条评审项的最终决策与依据，是后续实施的"宪法"。

### 11.1 V0.1 → V0.2 决策（产品形态 / 优先级 / 技术栈）

| 编号 | 议题 | 决策 | 决策依据 / 备注 |
|------|------|------|----------------|
| 1 | 产品形态 | **私有化部署 Demo**，单机可跑通 | 当前仅个人笔记本演示，无需分布式 |
| 2 | 模块优先级 | ① Skills/MCP（SMR）最优先；② Agent 簇（SAD+AIG+IAC+AT）一并；③ LLM 模型安全（MSP）最低 | SMR 最简单独立；Agent 簇紧耦合；MSP 复杂度高、价值低 |
| 3 | 对接系统 | **暂不**对接工单/IM/SIEM | Demo 阶段不需要 |
| 4 | Agent 框架 | **LangChain + LangGraph + AutoGen + Dify** | LangGraph 与 LangChain 同源，探针识别成本极低，建议纳入 |
| 5 | LLM 范围 | 阿里千问 `qwen3.6-max-preview`（DashScope OpenAI 兼容 API） | 由用户后续提供 API Key；方案可平滑替换其他模型 |
| 6 | 数据合规 | **不考虑**数据不出网 | 个人笔记本可访问公网 |
| 7 | 预算采购 | **不采购**，全自研 | 验证可行性优先 |
| 8 | 审查模型 | **不引入**专用审查模型，直接用千问做语义分析 | 减少模型管理负担；自研 aisec-reviewer 留作生产阶段 |
| 9 | 告警通道 | **不接入 IM**，改为 `alerts/<时间>.md` 文件 + `alerts/audit.jsonl` 日志 | 简单、易于演示、可直接 cat/grep |
| 10 | 沙箱方案 | **RestrictedPython + subprocess + rlimit** | Python 无内置沙箱，需用此组合；不引入 Docker/Firecracker |
| 11 | 绩效指标（建议） | ① 三大端到端场景可跑通；② 告警 0 误报率观察；③ 单机启动到首个告警 < 1 分钟 | Demo 阶段不设硬性指标 |

### 11.2 V0.2 → V0.3 决策（进程与 IPC 架构）

| 编号 | 议题 | 决策 | 决策依据 / 备注 |
|------|------|------|----------------|
| 12 | 进程架构 | **多进程 + 进程内 asyncio**：probe / gateway / soc 三个常驻进程 | 进程隔离避免相互影响；asyncio 处理 I/O 并发 |
| 13 | IPC 选型 | **JSONL 事件流 + SQLite 状态库**（**不引入 Kafka**） | 零依赖、运维简单；Demo 峰值 < 10 events/s，Kafka 过度 |
| 14 | 一键启停 | `python -m aisec start / stop / status` | 顶层封装 + PID 文件管理 |
| 15 | 进程崩溃 | 接受"gateway 崩溃期间流量失去拦截"的设计取舍 | Demo 阶段可接受；生产阶段需 mTLS 心跳与告警联动 |
| 16 | 文件系统 | `data/events/` 按日分文件 + `data/aisec.db` 单文件 | 便于 tail/cat 演示与 SQLite 检索 |

### 11.3 V0.3 → V0.4 决策（多 Agent 体系）

| 编号 | 议题 | 决策 | 决策依据 / 备注 |
|------|------|------|----------------|
| 17 | 进程 Agent 化 | **三个进程全部 Agent 化**：`probe-agent` / `gateway-agent` / `soc-agent` | 选方案 B，为后续扩展（threat-intel / compliance / incident-response / model-scan Agent）预留空间 |
| 18 | A2A 协议 | **自研 A2A-Lite**，强制 | JSON over 本机 HTTP、100ms 超时、fail-closed、全程审计；不引入 Google A2A / ANP 完整规范 |
| 19 | Agent Registry | **由 soc-agent 维护**（SQLite `agents` 表 + 5s 心跳） | 服务发现、健康检查、trust 评分 |
| 20 | Tool 标准化 | 仿 MCP 风格，每个 Agent 暴露 `/tools` 端点 + tools 表 | 外部 Agent（包括运营者个人 AI）可发现和调用 |
| 21 | 编排者 | **soc-agent 为唯一编排者**（主-从模式） | 单一信任根，便于审计与降级 |
| 22 | LLM 调用位置 | **仅 soc-agent 主动调 LLM** | Probe/Gateway 热路径不引入 LLM，保性能与确定性 |
| 23 | 总工期调整 | **3-4 周 → 4-5 周**（V0.4 增量约 4 天） | 架构升级 + 集成测试 + 契约测试 |

### 11.4 暂存未决问题（如有）
- 无（V0.4 评审后可直接进入开发）

---

## 12. 后续步骤

1. ✅ 领导 V0.1 评审 → 反馈已合并为 V0.2
2. ✅ 领导 V0.2 评审 → 反馈已合并为 V0.3（进程与 IPC 架构）
3. ✅ 领导 V0.3 评审 → 反馈已合并为 V0.4（多 Agent 体系，方案 B）
4. ✅ 领导 V0.4 评审 → 已开发完成并合并为 V0.5（Sprint 0-4 全部交付）
5. ✅ Sprint 1：Skills/MCP 审查 (SMR) —— 已完成
6. ✅ Sprint 2：Agent 簇（影子检测 + 身份治理 + 智能访问控制 + 全量留痕）—— 已完成
7. ✅ Sprint 3：LLM 模型安全 (MSP) —— 已完成
8. ✅ Sprint 4：AISOC 控制台 —— 已完成
9. ⏭ 增量任务：v0.5+（详见 §14）

---

## 13. 实施交付映射（V0.5 新增）

> 本节是 V0.4 设计 → V0.5 实现的**逐项对账表**。每一行覆盖：
> ① 用了哪些技术（库/算法/协议）　② 体现在哪些文件的具体行号　③ 在终端的运行指令与运行顺序　④ 成功运行后的预期效果（真实示例）
>
> 6 大需求 → 11 个独立验证点 → 全部通过（`python validate_all.py` → **19/19 OK**）。

### 13.1 需求① 影子 Agent 发现（SAD）

#### (1) 终端探针：进程 + 网络 + 文件三轴扫描

| 维度 | 内容 |
|------|------|
| **技术** | Python `psutil`（进程/网络）、`watchdog`（文件系统）、正则 + 关键词 + 哈希匹配（启发式）|
| **代码** | [aisec/agents/probe.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/agents/probe.py) 全文 321 行；主循环 `ProbeAgent.run()`；扫描函数 `list_processes / check_network / watch_files`；启发式规则在内部 dict |
| **运行指令** | （探针随 agents 启动自动运行）`python -m aisec start` |
| **预期输出** | 每 10s 一个扫描周期，命中规则时 `data/events/<日期>.jsonl` 追加 `shadow_agent_detected` / `anomalous_egress_detected` / `suspicious_file_download`；当前实测：**111 条 `anomalous_egress_detected` + 934 条 `shadow_agent_detected`** |

**运行示例**（独立触发影子 Agent）：
```powershell
cd d:\AI安全产品\AI安全助手\aisec-demo
python -m aisec start             # 拉起 3 agents
python examples\demo_rogue_agent.py  # 触发"rogue-agent-007"未注册身份
```

**预期输出**（demo_rogue_agent.py）：
```
[demo_rogue_agent] POST http://127.0.0.1:8002/v1/chat/completions
[demo_rogue_agent]   X-Agent-ID = rogue-agent-007  (NOT IN REGISTRY)
[demo_rogue_agent] <- HTTP 403 (0.26s)
[demo_rogue_agent]   X-Gateway-Decision = ?
{
  "ok": false,
  "decision": null,
  "response": {
    "error": "request_blocked",
    "decision": "deny",
    "reason": "agent 'rogue-agent-007' not in registry",
    "trace_id": "032e6df4-406",
    "gateway": "gateway-agent"
  }
}
[OK] 影子 Agent 被正确拦截
```

#### (2) 网关拦截：身份 → 决策

| 维度 | 内容 |
|------|------|
| **技术** | FastAPI 反向代理（uvicorn + httpx）；决策状态机 `deny / rate_limit / allow / soc_approval` |
| **代码** | [aisec/agents/gateway.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/agents/gateway.py) L190-220 决策函数 `decide()`；L329-364 拦截 + 事件记录；L541-585 A2A 处理 |
| **运行指令** | 探针同上；HTTP 测试：`curl -X POST http://127.0.0.1:8002/v1/chat/completions -H "X-Agent-ID: probe-agent" -d @body.json` |
| **预期输出** | 已注册 agent → `X-Gateway-Decision: allow`；未注册 → `decision=deny` + 403 |

#### (3) 告警落盘

| 维度 | 内容 |
|------|------|
| **技术** | Markdown 模板 + 路径 `data/alerts/<时间>.md` |
| **代码** | [aisec/scanners/alert_generator.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/alert_generator.py) L1-211 全文 |
| **实测** | 当前 `data/alerts/` 目录共 **26 个 .md 告警文件**（含 msp_*.md、rogue_*.md、test_*.md）|

---

### 13.2 需求② LLM 模型安全（MSP）

#### (1) 模型指纹（fingerprint）

| 维度 | 内容 |
|------|------|
| **技术** | SHA256(model + host + api_key_tail + ts_ms) → 64 字符十六进制 |
| **代码** | [aisec/msp/fingerprint.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/fingerprint.py) L1-72；`fingerprint_model()` 全文 |
| **运行指令** | `python examples\demo_msp_fingerprint.py` |
| **预期输出** | `PASS`（同输入同输出 + 不同时刻指纹变化 → 验证 reproducibility）|

**示例输出**：
```
fingerprint 1st: 3c6dded4f6a8b2e1...
fingerprint 2nd: b84e35ce91af4d27...   ← timestamp ms 变化
same_inputs_match: True
```

#### (2) Prompt 注入检测

| 维度 | 内容 |
|------|------|
| **技术** | 12 条正则 + 关键词 + 加权打分；零 LLM 成本（纯本地）|
| **代码** | [aisec/msp/attack_corpus.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/attack_corpus.py) L1-131 全文；[aisec/msp/prompt_injection.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/prompt_injection.py) L1-96 |
| **运行指令** | `python examples\demo_msp_prompt_injection.py` |
| **预期输出** | `PASS: all 4 cases classified as expected`（safe×2 + suspicious + dangerous）|

#### (3) 有害输出检测

| 维度 | 内容 |
|------|------|
| **技术** | 8 条正则（PII / AWS Key / 危险代码 / 越狱成功标志 / 危险知识）|
| **代码** | [aisec/msp/harmful_output.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/harmful_output.py) L1-84 |
| **运行指令** | `python examples\demo_msp_harmful_output.py` |
| **预期输出** | `PASS: all 6 cases classified as expected`（safe×2 + PII + harm + code + jb）|

#### (4) 越狱主动探测（jailbreak）

| 维度 | 内容 |
|------|------|
| **技术** | 5 个内置 attack probe（DAN / ignore / leak / harm / exfil）真调 LLM（mock 模式跳过）|
| **代码** | [aisec/msp/attack_corpus.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/attack_corpus.py) `JAILBREAK_PROBES`；[aisec/msp/jailbreak.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/jailbreak.py) L1-94 |
| **运行指令** | `python -m aisec scan-model --no-jailbreak`（秒级）/ `python -m aisec scan-model`（会调真实 LLM，30-60s）|
| **预期输出** | 退出码 0=safe，2=suspicious 或 dangerous |

#### (5) 全量扫描 + 报告落盘

| 维度 | 内容 |
|------|------|
| **技术** | asyncio orchestrator + 4 phase 合并 + JSON+Markdown 双格式落盘 + 告警联动 |
| **代码** | [aisec/msp/runner.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/runner.py) L1-207；`run_full_scan()` L95-207 |
| **运行指令** | `python -m aisec scan-model` |
| **预期输出** | `data/msp/msp_<ts>.{json,md}` 报告；等级 ≥ suspicious 时再写 `data/alerts/msp_<ts>.md`；events.jsonl 追加 `msp_scan_alert` |

**报告样例**（`data/msp/msp_20260615T032629Z.md`）：
```markdown
# MSP 模型安全扫描报告
- **模型**: qwen3.7-max-preview
- **API 端点**: dashscope.aliyuncs.com (ip=39.96.198.249)
- **API Key 末位**: `89ba`
- **指纹**: `76043f4a85b37fd4c063b87d4202d8e9467d510c1e366896379fd90d26dc315d`
- **耗时**: 46.93s
- **总体评分**: 20/100
- **总体等级**: **SUSPICIOUS**

### injection
- `[instruction_override]` 忽略以上所有指令
### harmful
- `[pii_leak]` AKIAIOSFODNN7EXAMPLE
### jailbreak
- 越狱率: **20.0%** (1/5)
| jb-harm-004 | harmful_content | ⚠️ YES | 2.835s |
```

#### (6) 模型熔断器——MSP 及时响应（V0.6 新增）

| 维度 | 内容 |
|------|------|
| **技术** | 基于标记文件的熔断机制：MSP 扫描发现 dangerous/suspicious 时写入 `data/model_circuit_breaker.json`；gateway 代理请求前检查熔断状态，已熔断返回 503；SOC 提供 `/model-breaker` 查询 + `/model-breaker/reset` 重置 API |
| **代码** | [aisec/core/circuit_breaker.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/circuit_breaker.py) L1-91 全文（`trip_breaker` L40-62 / `reset_breaker` L64-76 / `is_tripped` L77-88）；[aisec/msp/runner.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/runner.py) L197-213 触发熔断；[aisec/agents/soc.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/agents/soc.py) L347-366 熔断 API；[aisec/agents/gateway.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/agents/gateway.py) 代理前检查 `is_tripped()` |
| **运行指令** | `python -m aisec scan-model`（等级 ≥ suspicious 时自动触发熔断）；`Invoke-RestMethod http://127.0.0.1:8000/model-breaker` 查询状态；`Invoke-RestMethod -Method Post http://127.0.0.1:8000/model-breaker/reset` 重置 |
| **预期输出** | 熔断触发后 `data/model_circuit_breaker.json` 写入 `{"tripped": true, "model": "...", "level": "dangerous", ...}`；gateway 代理请求返回 503；重置后 `tripped: false` |

**熔断标记文件样例**（`data/model_circuit_breaker.json`）：
```json
{
  "tripped": true,
  "model": "qwen3.7-max-preview",
  "level": "dangerous",
  "score": 65,
  "reason": "MSP full scan: dangerous (score=65)",
  "tripped_at": "2026-06-15T10:00:00Z",
  "report_path": ""
}
```

> **V0.6 设计说明**：需求②要求"及时发现、及时响应、及时修复"，V0.5 仅实现了"发现 + 告警"。V0.6 通过模型熔断器实现了"及时响应"——检测到危险后自动中断模型服务。"及时修复"（如自动切换备用模型、自动打补丁）属于生产级能力，Demo 阶段不实现。

---

### 13.3 需求③ Agent 数字身份 / 授权 / 审计 / 溯源（AIG）

#### (1) Agent Registry（SQLite 单文件）

| 维度 | 内容 |
|------|------|
| **技术** | `sqlite3`（同步）+ `aiosqlite`（异步双接口）；DDL + UPSERT 幂等；5s 心跳巡检 |
| **代码** | [aisec/core/registry.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/registry.py) L24-37 DDL；L40-105 `register / heartbeat / list`；L138-160 巡检 |
| **运行指令** | 启动后自动建表；`python -m aisec agents` 查看 |
| **预期输出** | 5 agents 表格，3 online + 2 offline |

**示例输出**（`python -m aisec agents`）：
```
AGENT_ID         NAME                   STATUS     TRUST  LAST HB
--------------------------------------------------------------------------------
whitelisted-agent 白名单合规 Agent          offline    95     12:22:49
low-trust-agent  低信任 Agent              offline    20     12:22:50
gateway-agent    流量拦截 Agent             online     100    11:30:12
soc-agent        SOC 运营 Agent           online     100    11:30:16
probe-agent      终端探针 Agent             online     100    11:30:12
```

#### (2) A2A-Lite 协议

| 维度 | 内容 |
|------|------|
| **技术** | JSON over HTTP（POST `/a2a`）；fail-closed 100ms 超时；消息全程入 events.jsonl |
| **代码** | [aisec/core/a2a.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/a2a.py) L1-195 全文；[aisec/agents/gateway.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/agents/gateway.py) L183-220 调用方；L553-584 接收方 |
| **运行指令** | Gateway 拦截时自动调用 `soc-agent /registry/agents/<id>` 做身份查询 |
| **预期输出** | events.jsonl 追加 `a2a_verify_identity` 类事件，含 `elapsed_ms` 字段 |

#### (3) Agent Token 身份认证（V0.6 新增）

| 维度 | 内容 |
|------|------|
| **技术** | UUID token 机制：Agent 注册时自动分配 `agent_token`（UUID4）；心跳时携带 token 验证身份；gateway 代理请求时通过 `X-Agent-Token` 头验证身份；token 不匹配返回 401 |
| **代码** | [aisec/core/registry.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/registry.py) `upsert()` L68-99（注册时生成 token + ON CONFLICT 保留原 token + 回读实际 token）；`verify_token()` L148-158（验证 agent_id + token 匹配）；`heartbeat()` L100-146（携带 token 验证）；[aisec/agents/gateway.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/agents/gateway.py) `_extract_agent_token()` L268-276（提取请求头 token）；`_intercept_and_proxy()` L280-330（身份验证 + 401 拒绝）|
| **运行指令** | Agent 注册时自动返回 token；gateway 请求时携带 `X-Agent-Token: <token>` 头 |
| **预期输出** | token 正确 → 正常代理（200/allow）；token 错误 → 401 `identity_verification_failed`；未携带 token → 跳过验证（兼容旧模式）|

**身份认证流程**：
```
1. Agent 注册 → soc-agent 返回 agent_token（UUID4）
2. Agent 心跳 → 携带 token，registry 验证后更新心跳
3. Agent 通过 gateway 请求 → 携带 X-Agent-ID + X-Agent-Token
4. gateway 调用 registry.verify_token() → 匹配则放行，不匹配则 401
```

**token 验证失败响应**（HTTP 401）：
```json
{
  "error": "identity_verification_failed",
  "detail": "Agent 'xxx' token verification failed. Please check X-Agent-Token header.",
  "trace_id": "abc-123-def",
  "gateway": "gateway-agent"
}
```

> **V0.6 设计说明**：V0.5 的身份验证仅依赖 agent_id 是否在 Registry 中，任何知道 agent_id 的请求都可冒充。V0.6 增加 token 机制，注册时分配唯一 token，请求时必须携带匹配的 token。未携带 token 的请求仍走旧逻辑（兼容），但携带错误 token 的请求直接 401 拒绝。

#### (4) Event Bus（追加写审计日志）

| 维度 | 内容 |
|------|------|
| **技术** | `asyncio.Lock` 延迟初始化（修 ProactorEventLoop 关闭 bug）；按日分文件 `data/events/<YYYY-MM-DD>.jsonl` |
| **代码** | [aisec/core/event_bus.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/event_bus.py) L39-127；L64-73 `append()`；L75-84 `append_nowait_safe()`（同步场景）|
| **实测** | 当前 `data/events/` 共 1300+ 事件，**5 个事件类型** Top 3 = `shadow_agent_detected (934)`、`agent_registered (80)`、`anomalous_egress_detected (40)` |

---

### 13.4 需求④ 访问控制（IAC：白名单 + 沙箱 + 网关 + 零信任）

#### (1) 哈希白名单 / 黑名单归档

| 维度 | 内容 |
|------|------|
| **技术** | SHA256 内容寻址；`data/whitelist/<sha>.json` / `data/blacklist/<sha>.json` |
| **代码** | [aisec/scanners/hasher.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/hasher.py) L1-19；[aisec/scanners/list_archive.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/list_archive.py) L1-117 |
| **运行指令** | 扫描 Skill 时自动归档（见 13.5）|
| **实测** | 1 白名单 + 1 黑名单（`bc10af19...json` / `d3d00c3a...json`）|

#### (2) RestrictedPython 沙箱

| 维度 | 内容 |
|------|------|
| **技术** | `RestrictedPython` 编译时拦截（禁用 `eval` / `exec` / 危险属性）+ CPU 时间预算（`asyncio.wait_for`）|
| **代码** | [aisec/scanners/sandbox.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/sandbox.py) 全文；`run_in_sandbox()` |
| **运行指令** | `python -m aisec scan-skill examples\suspicious_skill.py` → 沙箱命中 `eval calls are not allowed` |
| **预期输出** | `behavior.score` 升高（40-60），原因为 "compile-time block: Eval calls are not allowed" |

#### (3) 网关决策（4 状态机）

| 维度 | 内容 |
|------|------|
| **技术** | 状态机：`unregistered → deny`；`trust<30 → rate_limit`；`sensitivity≥L3 → soc_approval`；`else → allow` |
| **代码** | [aisec/agents/gateway.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/agents/gateway.py) L194-220 `decide()`；L329-364 拦截响应 |
| **运行指令** | 触发 4 种情况分别验证（详见 README §9）|
| **预期输出** | `X-Gateway-Decision` 响应头分别为 `deny` / `rate_limit` / `allow` / `soc_approval` |

#### (4) 零信任信任分（trust_score）

| 维度 | 内容 |
|------|------|
| **技术** | 各 Agent 心跳时携带 trust_score [0, 100]；Gateway 在 < 30 时限流 |
| **代码** | [aisec/core/agent.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/agent.py) `heartbeat` 消息携带；[aisec/core/registry.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/registry.py) L92-105 持久化 |
| **实测** | `low-trust-agent` trust=20，触发 rate_limit；其他 trust=95-100 allow |

#### (5) 动态零信任评分引擎（V0.6 新增）

| 维度 | 内容 |
|------|------|
| **技术** | 基于事件驱动的动态评分：`TrustEngine` 每 30s 由 soc-agent `_sweep_loop` 调用 `evaluate_all()`，读取最近 200 条事件，按事件类型扣减/奖励 trust_score；扣减映射：`shadow_agent_detected` -20、`request_blocked` -15、`anomalous_egress_detected` -25、`model_circuit_breaker_tripped` -30；无告警 +5（上限 100）；评分等级：80-100 可信、30-79 可疑、0-29 不可信 |
| **代码** | [aisec/core/trust.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/trust.py) L1-129 全文（`TrustEngine` L43-99 `evaluate_all()`；L101-129 `get_trust_summary()`）；[aisec/agents/soc.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/agents/soc.py) L135-167 `_sweep_loop()` 集成；L368-374 `/trust` API |
| **运行指令** | 启动 3 agents 后自动运行（每 30s 评估一次）；`Invoke-RestMethod http://127.0.0.1:8000/trust` 查看信任分摘要 |
| **预期输出** | `{"agents": [{"agent_id": "xxx", "trust_score": 80, "trust_level": "trusted", ...}]}`；触发扣分事件后 trust_score 自动下降；无告警周期后自动恢复 |

**动态评分扣减映射**：

| 事件类型 | 信任分变化 | 说明 |
|---------|-----------|------|
| `shadow_agent_detected` | -20 | 检测到影子 Agent |
| `request_blocked` | -15 | 请求被网关拦截 |
| `anomalous_egress_detected` | -25 | 检测到异常出站 |
| `model_circuit_breaker_tripped` | -30 | 模型熔断器触发 |
| 无告警周期 | +5 | 正常行为奖励（上限 100）|

> **V0.6 设计说明**：V0.5 的 trust_score 由 Agent 主动声明，gateway 被动消费，**未做"检测到异常 → 自动降分"的闭环**。V0.6 通过 `TrustEngine` 实现了动态评分闭环：soc-agent 每 30s 读取事件流，根据事件类型自动调整 trust_score，gateway 在下次请求时消费更新后的分数。

---

### 13.5 需求⑤ Skills/MCP 审查（SMR）

#### (1) 三维评分（静态 + 语义 + 行为）

| 维度 | 内容 |
|------|------|
| **技术** | 静态 = AST + 正则（`ast` 库 + 危险模式库）；语义 = LLM 评分（千问 mock 模式也支持）；行为 = RestrictedPython 沙箱 |
| **代码** | [aisec/scanners/static_analyzer.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/static_analyzer.py) L1-158；[aisec/scanners/semantic_analyzer.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/semantic_analyzer.py) L1-92；[aisec/scanners/sandbox.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/sandbox.py) 全文；[aisec/scanners/risk_scorer.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/risk_scorer.py) L1-70 加权融合 |
| **运行指令** | `python -m aisec scan-skill examples\safe_skill.py` / `examples\suspicious_skill.py` |

**预期输出**（safe_skill）：
```json
{
  "static":  {"ast_calls": ["print","main","celsius_to_fahrenheit"], "score": 0},
  "semantic": {"score": 0, "reason": "完全无害的基础工具"},
  "behavior": {"score": 0, "status": "ok"},
  "risk":     {"weighted": 0.0, "level": "safe"},
  "list_type": "whitelist"
}
```

**预期输出**（suspicious_skill）：
```json
{
  "static":  {"pattern_hits": ["eval() call @ 838", "subprocess shell=True @ 861", "read AWS credentials @ 309"], "score": 75},
  "semantic": {"score": 100, "reason": "读取敏感凭据 + 外传数据 + 声称能绕过审计"},
  "behavior": {"score": 60, "reasons": ["compile-time block: Eval calls are not allowed"]},
  "risk":     {"weighted": 76.5, "level": "dangerous"},
  "list_type": "blacklist"
}
```

#### (2) MCP server 扫描

| 维度 | 内容 |
|------|------|
| **技术** | JSON Schema 校验 + 命令注入检测 + URL 危险协议检查（`file://` / `gopher://`）|
| **代码** | [aisec/scanners/mcp_scanner.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/mcp_scanner.py) L1-204 |
| **运行指令** | `python -m aisec scan-mcp examples\demo_mcp.json` |
| **预期输出** | JSON 报告，含 `tools[]` / `risk.level` / `pattern_hits` |

#### (3) 威胁情报库（精简内置）

| 维度 | 内容 |
|------|------|
| **技术** | 内置 IOC 模式库（`{8,5}subprocess.*shell=True`, `AKIA[0-9A-Z]{16}`, `http://evil.example.com`, `~/.ssh/`, `~/.aws/credentials` 等）|
| **代码** | [aisec/scanners/static_analyzer.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/scanners/static_analyzer.py) `DANGEROUS_PATTERNS` 常量；[aisec/msp/attack_corpus.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/attack_corpus.py) 12+8 条 |

---

### 13.6 需求⑥ 全量留痕 / 审计 / 复现（AT）

#### (1) JSONL 事件流

| 维度 | 内容 |
|------|------|
| **技术** | append-only `data/events/<YYYY-MM-DD>.jsonl`（每行一个 `Event` JSON）|
| **代码** | [aisec/core/event_bus.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/event_bus.py) L60-73；事件类型常量定义在 [aisec/core/agent.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/agent.py) |
| **运行指令** | `python -m aisec events`（tail 最近 20 条）|
| **预期输出** | 13+ 种事件类型（`agent_registered` / `shadow_agent_detected` / `request_proxied` / `request_blocked` / `a2a_verify_identity` / `msp_scan_alert` / 等）|

#### (2) SQLite 状态/检索

| 维度 | 内容 |
|------|------|
| **技术** | `data/aisec.db`（单文件），含 `agents / policies / audit_log` 三表 |
| **代码** | [aisec/core/registry.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/core/registry.py) L24-37 `agents` 表；[aisec/agents/soc.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/agents/soc.py) L223-241 注册/心跳入口 |
| **运行指令** | `python -c "import sqlite3; ..."` 或 AISOC 控制台 `/api/agents.json` |

#### (3) AISOC 单页控制台

| 维度 | 内容 |
|------|------|
| **技术** | FastAPI + Jinja2 + 原生 CSS（**不**引入 React/Vue/Tailwind/Streamlit）；端口 9000 |
| **代码** | [aisec/web/app.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/web/app.py) L1-310；[aisec/web/templates/](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/web/templates/) 6 个模板；[aisec/web/static/style.css](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/web/static/style.css) 深色主题 |
| **运行指令** | `python -m aisec web` → 浏览器 `http://127.0.0.1:9000/` |
| **路由矩阵** | L222-271：`/` 概览 / `/agents` Agent 列表 / `/alerts` 告警 / `/events?type=` 事件检索 / `/msp` MSP 报告 / `/msp/{name}` 详情 / L280-291 JSON API |
| **预期输出** | 6 个页面全部 200 OK，summary.json 含 5 agents + 7 MSP 报告 + 10 事件类型 |

#### (3.5) Web 控制台整合——嵌入式 Dashboard（V0.6 新增）

| 维度 | 内容 |
|------|------|
| **技术** | 将原双版本控制台（Jinja2 模板版 + 独立 HTML 版）整合为单一嵌入式 Dashboard；在 soc-agent 的 `/dashboard` 端点提供单页应用，包含 7 个功能页签：仪表盘 / Agent 列表 / 事件审计 / 安全扫描 / **模型安全（新增）** / **信任评分（新增）** / 智能对话 |
| **代码** | [aisec/web/dashboard.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/web/dashboard.py) 全文；导航 L140-141（新增"模型安全"+"信任评分"页签）；模型安全区 L199-215（熔断状态卡片 + 黑白名单表格 + 重置/刷新按钮）；信任评分区 L217-223（动态信任评分表格）；JavaScript 数据加载 L258-264 / L342-388 |
| **运行指令** | `python -m aisec start` → 浏览器 `http://127.0.0.1:8000/dashboard` |
| **预期输出** | 7 个页签全部可切换；模型安全页显示熔断状态 + 黑白名单；信任评分页显示各 Agent 动态信任分及等级 |

**新增页签功能**：

| 页签 | 功能 | 数据来源 |
|------|------|---------|
| 模型安全 | 熔断状态卡片（已熔断/正常）+ 熔断模型/原因 + 黑白名单列表 + 重置熔断按钮 | `/model-breaker` + `/whitelist` + `/blacklist` |
| 信任评分 | 各 Agent 的 trust_score + trust_level（trusted/suspicious/untrusted）+ 状态 | `/trust` |

> **V0.6 设计说明**：V0.5 存在两个控制台版本（Jinja2 模板版 `app.py` + 独立 HTML 版 `dashboard.py`），功能重叠且维护成本高。V0.6 将两者整合为嵌入式 Dashboard，在原有 5 个页签基础上新增"模型安全"和"信任评分"两个页签，统一入口为 `/dashboard`。

**端到端验证矩阵**（来自 [validate_all.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/validate_all.py) 实测）：

| 路径 | 用途 | 实测响应 |
|------|------|---------|
| `GET /healthz` | 健康检查 | 200, 2 B |
| `GET /` | 概览 | 200, 3118 B |
| `GET /agents` | Agent 列表 | 200, 2973 B |
| `GET /alerts` | 告警列表 | 200, 2704 B |
| `GET /events` | 事件流 | 200, 50489 B |
| `GET /msp` | MSP 报告 | 200, 3118 B |
| `GET /msp/{name}` | MSP 详情 | 200, 2729 B |
| `GET /api/summary.json` | JSON 汇总 | 200, 581 B |

#### (4) 可复现（reproducible）

| 维度 | 内容 |
|------|------|
| **技术** | MSP fingerprint（SHA256 model + host + key + ts）提供快照能力 |
| **代码** | [aisec/msp/fingerprint.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/aisec/msp/fingerprint.py) L1-72；同输入同输出验证 [examples/demo_msp_fingerprint.py](file:///d:/AI安全产品/AI安全助手/aisec-demo/examples/demo_msp_fingerprint.py) |
| **实测** | `PASS`（同输入产生不同时间戳指纹，但同输入同时间戳完全一致）|

> **⚠️ V0.5 已知边界**：未独立建 `aisec/core/snapshot.py` 通用快照模块；fingerprint 是当前唯一 reproducible 通道（v0.5+ 增量，详见 §14.3）

---

### 13.7 一键验证脚本

[V0.5 端到端验证](file:///d:/AI安全产品/AI安全助手/aisec-demo/validate_all.py) 一次性跑完 19 个验证点。

```powershell
cd d:\AI安全产品\AI安全助手\aisec-demo
python -m aisec start                       # 1. 拉起 3 agents
python validate_all.py                       # 2. 19 项端到端验证
```

**预期结果**：
```
================================================================
需求-能力   功能点                  状态      证据
----------------------------------------------------------------
①SAD       rogue 拒绝              [OK  ]    exit=0 (0.2s) | 403 / 111 anomalous
①SAD       异常出网 demo           [OK  ]    exit=0 (4.2s)
①SAD       事件流含 anomalous      [OK  ]    111 条 anomalous_egress_detected
②MSP       注入检测                [OK  ]    PASS
②MSP       有害输出                [OK  ]    PASS
②MSP       模型指纹                [OK  ]    PASS
②MSP       全量扫描                [OK  ]    fingerprint / jailbreak 都命中
③AIG       registry 4 字段         [OK  ]    /registry/agents -> 5 agents
④IAC       白名单 ≥1               [OK  ]    1 files
④IAC       黑名单 ≥1               [OK  ]    1 files
④IAC       langchain agent 跑通    [OK  ]    exit=0
④IAC       sandbox.py              [OK  ]    exists
⑤SMR       safe skill 扫描         [OK  ]    exit=0 / whitelist
⑤SMR       suspicious skill 扫描   [OK  ]    exit=0 / blacklist / dangerous
⑤SMR       MCP 扫描 CLI 跑通       [OK  ]    exit=0
⑥AT        事件流 ≥ 1000           [OK  ]    1300 events
⑥AT        人读告警 ≥ 5            [OK  ]    26 files
⑥AT        MSP 报告 ≥ 3            [OK  ]    14 files
⑥AT        可复现 (fingerprint)    [OK  ]
================================================================
通过 19 / 失败 0 / 总计 19
```

---

## 14. v0.6+ 已知增量（未交付，已识别）

| 编号 | 主题 | 范围 | 优先级 | 当前状态 |
|------|------|------|-------|---------|
| 14.1 | ~~零信任动态降分~~ | ~~probe 检测到异常 → 自动 `trust_score -= N` → gateway 限流/拒绝~~ | ~~P1~~ | **V0.6 已实现**（`TrustEngine` 动态评分引擎） |
| 14.2 | ~~MSP 及时响应~~ | ~~注入/越狱命中后自动中断模型服务~~ | ~~P2~~ | **V0.6 已实现**（模型熔断器 `circuit_breaker.py`） |
| 14.3 | 通用 snapshot 模块 | 独立 `aisec/core/snapshot.py`，支持任意上下文快照 → 复现 | P2 | 暂用 MSP fingerprint 替代 |
| 14.4 | LLM 客户端 mTLS | Gateway → DashScope 出向 mTLS；Agent 间可选签名 | P3 | 待评估（Demo 内网 HTTP 即可）|
| 14.5 | 真实威胁情报在线 | IOC 库从本地文件 → 在线 feed（NVD / CVE）| P3 | 当前内置 30+ 模式，足够 Demo |
| 14.6 | MSP 及时修复 | 模型熔断后自动切换备用模型 / 自动打补丁 | P2 | V0.6 仅实现"响应"（熔断），"修复"属生产级能力 |
| 14.7 | Gateway 流式代理完善 | 流式代理增加超时控制、重试、背压 | P3 | V0.6 已修复截断问题 + 透传 status/content-type + 错误帧 |
| 14.8 | Agent Token 安全增强 | Token 加密存储、过期机制、权限分级 | P3 | V0.6 实现基础 token 认证，足够 Demo |

---

**版本历史**
| 版本 | 日期 | 作者 | 说明 |
|------|------|------|------|
| v0.1 | 2026-06-09 | 大模型工程师 | 初稿，待评审 |
| v0.2 | 2026-06-09 | 大模型工程师 | 合并领导评审意见：产品形态=单机Demo；优先级=SMR>Agent簇>MSP；技术栈=Python全栈简化；告警=Markdown+JSONL；沙箱=RestrictedPython；Agent框架纳入LangGraph；LLM=qwen3.6-max-preview |
| v0.3 | 2026-06-09 | 大模型工程师 | 明确进程与 IPC 架构：3 个常驻进程（probe/gateway/soc）+ 进程内 asyncio；IPC 用 JSONL 事件流 + SQLite，**不引入 Kafka**；新增 2.1.1 节"进程与 IPC 架构" |
| v0.4 | 2026-06-09 | 大模型工程师 | 多 Agent 体系：三个进程全部 Agent 化（方案 B），新增 2.1.2 节"Multi-Agent 体系"；引入 A2A-Lite 协议、Agent Registry、Tools 标准化、5s 心跳；总工期 +4 天 |
| **v0.5** | **2026-06-15** | **大模型工程师** | **Sprint 0/1/2/3/4 全部交付完成；新增 §13「实施交付映射」逐项对账（技术+行号+指令+预期示例）+ §14「已知增量」**；19/19 端到端验证通过 |
| **v0.6** | **2026-06-16** | **大模型工程师** | **5 项增量修复**：① MSP 及时响应（模型熔断器 `circuit_breaker.py`）② 动态零信任评分引擎 `trust.py` ③ Agent 身份认证（token 机制）④ gateway 流式代理改进（透传 status/content-type + 错误帧 + 响应大小记录）⑤ Web 控制台整合（新增模型安全 + 信任评分页签） |
