"""告警 Markdown 生成器。

将安全扫描结果、影子 Agent 检测、流量拦截等事件生成为 Markdown 告警文件，
保存到 data/alerts/ 目录。
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AlertGenerator:
    """告警 Markdown 生成器。"""

    def __init__(self, data_dir: str | Path):
        self.alerts_dir = Path(data_dir) / "alerts"
        self.alerts_dir.mkdir(parents=True, exist_ok=True)

    def _write_alert(self, filename: str, content: str) -> Path:
        path = self.alerts_dir / filename
        path.write_text(content, encoding="utf-8")
        logger.info(f"alert written: {path}")
        return path

    @staticmethod
    def _risk_badge(level: str) -> str:
        badges = {
            "safe": "![SAFE](https://img.shields.io/badge/Risk-SAFE-green)",
            "suspicious": "![SUSPICIOUS](https://img.shields.io/badge/Risk-SUSPICIOUS-yellow)",
            "dangerous": "![DANGEROUS](https://img.shields.io/badge/Risk-DANGEROUS-red)",
        }
        return badges.get(level, f"**{level.upper()}**")

    def generate_scan_alert(self, scan_result: dict[str, Any]) -> Path:
        """根据 Skill/MCP 扫描结果生成告警 Markdown。"""
        now = datetime.now()
        kind = scan_result.get("kind", "unknown")
        path = scan_result.get("path", "unknown")
        sha256 = scan_result.get("sha256", "N/A")
        risk = scan_result.get("risk", {})
        level = risk.get("level", "unknown")
        score = risk.get("score", "N/A")

        # 不为 safe 级别生成告警（仅归档）
        if level == "safe":
            return self._generate_safe_report(scan_result)

        static = scan_result.get("static", {})
        semantic = scan_result.get("semantic", {})
        behavior = scan_result.get("behavior", {})

        filename = f"{now.strftime('%Y%m%d_%H%M%S')}_{kind}_{level}_{sha256[:12]}.md"

        md = f"""# 安全告警：{kind.upper()} 扫描检测到 {level.upper()} 风险

{self._risk_badge(level)}

## 基本信息

| 项目 | 值 |
|------|-----|
| **类型** | {kind} |
| **文件路径** | `{path}` |
| **SHA256** | `{sha256}` |
| **风险等级** | {level.upper()} |
| **综合评分** | {score}/100 |
| **检测时间** | {now.strftime('%Y-%m-%d %H:%M:%S')} |

## 风险详情

### 静态分析（权重 0.3）

- **分数**: {static.get('score', 'N/A')}/100
- **检测项**: {len(static.get('reasons', []))} 项
- **详情**:
{self._format_reasons(static.get('reasons', []))}

### 语义分析（权重 0.3）

- **分数**: {semantic.get('score', 'N/A')}/100
- **风险描述**: {semantic.get('reason', 'N/A')}

### 行为分析（权重 0.4）

- **分数**: {behavior.get('score', 'N/A')}/100
- **检测项**: {len(behavior.get('reasons', []))} 项
- **详情**:
{self._format_reasons(behavior.get('reasons', []))}

## 建议处置

{self._recommendation(level)}

---
*由 AISOC 安全运营中心自动生成 | {now.isoformat()}*
"""
        return self._write_alert(filename, md)

    def _generate_safe_report(self, scan_result: dict[str, Any]) -> Path:
        """为 safe 级别生成简要报告。"""
        now = datetime.now()
        kind = scan_result.get("kind", "unknown")
        path = scan_result.get("path", "unknown")
        sha256 = scan_result.get("sha256", "N/A")
        risk = scan_result.get("risk", {})
        score = risk.get("score", "N/A")

        filename = f"{now.strftime('%Y%m%d_%H%M%S')}_{kind}_safe_{sha256[:12]}.md"

        md = f"""# 安全报告：{kind.upper()} 扫描通过

![SAFE](https://img.shields.io/badge/Risk-SAFE-green)

| 项目 | 值 |
|------|-----|
| **类型** | {kind} |
| **文件路径** | `{path}` |
| **SHA256** | `{sha256}` |
| **综合评分** | {score}/100 |
| **检测时间** | {now.strftime('%Y-%m-%d %H:%M:%S')} |

该文件已通过安全扫描，可安全使用。

---
*由 AISOC 安全运营中心自动生成 | {now.isoformat()}*
"""
        return self._write_alert(filename, md)

    def generate_shadow_agent_alert(self, event_payload: dict[str, Any]) -> Path:
        """影子 Agent 检测告警。"""
        now = datetime.now()
        processes = event_payload.get("processes", [])
        count = len(processes)

        filename = f"{now.strftime('%Y%m%d_%H%M%S')}_shadow_agent.md"

        proc_lines = ""
        for p in processes[:10]:
            proc_lines += f"| {p.get('pid', '?')} | {p.get('name', '?')} | `{p.get('cmdline', '?')[:80]}` |\n"

        md = f"""# 安全告警：检测到影子 Agent

![DANGEROUS](https://img.shields.io/badge/Risk-DANGEROUS-red)

## 概要

在终端扫描中发现 **{count}** 个未注册的疑似 AI Agent 进程。

## 进程列表

| PID | 名称 | 命令行 |
|-----|------|--------|
{proc_lines}
{"> 仅显示前 10 个进程" if count > 10 else ""}

## 建议处置

1. 确认这些进程是否为已授权的 AI Agent
2. 若未授权，建议终止进程并调查来源
3. 将已确认安全的 Agent 注册到 AISOC Registry

---
*由 AISOC 安全运营中心自动生成 | {now.isoformat()}*
"""
        return self._write_alert(filename, md)

    def generate_traffic_alert(self, event_payload: dict[str, Any]) -> Path:
        """流量拦截告警。"""
        now = datetime.now()
        decision = event_payload.get("decision", "unknown")
        agent_id = event_payload.get("agent_id", "unknown")
        path = event_payload.get("path", "unknown")
        reason = event_payload.get("reason", "unknown")
        trace_id = event_payload.get("trace_id", "N/A")

        level = "dangerous" if decision == "deny" else "suspicious"
        filename = f"{now.strftime('%Y%m%d_%H%M%S')}_traffic_{decision}_{trace_id}.md"

        md = f"""# 安全告警：流量拦截 - {decision.upper()}

{self._risk_badge(level)}

## 详情

| 项目 | 值 |
|------|-----|
| **决策** | {decision.upper()} |
| **Agent ID** | `{agent_id}` |
| **请求路径** | `{path}` |
| **原因** | {reason} |
| **Trace ID** | `{trace_id}` |
| **时间** | {now.strftime('%Y-%m-%d %H:%M:%S')} |

## 建议处置

{self._recommendation(level)}

---
*由 AISOC 安全运营中心自动生成 | {now.isoformat()}*
"""
        return self._write_alert(filename, md)

    @staticmethod
    def _format_reasons(reasons: list[str]) -> str:
        if not reasons:
            return "无异常"
        return "\n".join(f"  - {r}" for r in reasons)

    @staticmethod
    def _recommendation(level: str) -> str:
        if level == "dangerous":
            return """1. **立即阻止**该 Skill/MCP 的加载和执行
2. **隔离**相关文件，防止被其他 Agent 调用
3. **调查**来源，确认是否为供应链攻击
4. **归档**到黑名单，防止再次引入"""
        elif level == "suspicious":
            return """1. **暂停**该 Skill/MCP 的使用
2. **人工审查**代码和权限
3. 确认安全后可加入白名单
4. 持续监控其运行行为"""
        return "无需特殊处置。"
