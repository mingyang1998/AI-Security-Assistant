"""MCP server 配置扫描器。

MCP server 配置一般是 JSON：
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
      "env": {...}
    }
  }
}

扫描维度：
- command 可疑（curl, wget, powershell, python -c, bash -c）
- args 包含敏感路径（/etc, ~/.ssh, C:\\Windows, ..)
- env 注入风险（写敏感环境变量）
- 远端 URL
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Any

from aisec.scanners.hasher import file_hash
from aisec.scanners.risk_scorer import RiskScorer

logger = logging.getLogger(__name__)


DANGEROUS_CMDS = {
    "curl", "wget", "powershell", "pwsh", "cmd", "cmd.exe",
    "bash", "sh", "zsh", "nc", "ncat", "netcat", "telnet",
    "python", "python3", "perl", "ruby", "node",
}
SENSITIVE_PATH_RE = [
    re.compile(r"/etc/(?!ssl/certs)"),
    re.compile(r"\.ssh(/|$)"),
    re.compile(r"\.aws(/|$)"),
    re.compile(r"~/?\.kube(/|$)"),
    re.compile(r"C:\\Windows", re.IGNORECASE),
    re.compile(r"C:\\Users\\[^\\]+\\.(?!cursor)"),
]
DANGEROUS_ENV_KEYS = {
    "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID",
    "GITHUB_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "DATABASE_URL", "DB_PASSWORD",
}


def _scan_server(name: str, server: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    score = 0
    cmd = (server.get("command") or "").lower()
    args = server.get("args") or []
    env = server.get("env") or {}
    url = server.get("url") or ""
    transport = server.get("transport") or "stdio"

    # 1. 可疑命令
    if cmd and any(cmd == d or cmd.endswith("/" + d) for d in DANGEROUS_CMDS):
        reasons.append(f"suspicious command: {cmd}")
        score += 20
    # 2. -c / /c 形参（命令执行）
    if "-c" in args or "/c" in args:
        reasons.append("shell command-line execution")
        score += 20
    # 3. 管道执行（| bash / | sh）—— args 可能被拆成多个 token
    has_pipe = any(str(a) == "|" for a in args)
    has_shell = any(str(a).lower() in ("bash", "sh", "zsh", "ash") for a in args)
    if (has_pipe and has_shell) or any(
        "|" in str(a) and any(sh in str(a) for sh in ["bash", "sh", "zsh", "ash"]) for a in args
    ):
        reasons.append("pipe-to-shell pattern")
        score += 20
    # 4. 敏感路径
    for a in args:
        for pat in SENSITIVE_PATH_RE:
            if pat.search(str(a)):
                reasons.append(f"sensitive path in args: {a}")
                score += 15
                break
    # 5. 危险 env
    for k, v in env.items():
        if k in DANGEROUS_ENV_KEYS:
            reasons.append(f"敏感环境变量: {k}")
            score += 15
        if "http://" in str(v) or "https://" in str(v):
            reasons.append(f"env 包含 URL: {k}={v}")
            score += 10
    # 6. 非 HTTPS 远端
    if url and not url.startswith("https://"):
        reasons.append(f"非 HTTPS 远端: {url}")
        score += 15
    # 7. 远端 URL 形参（download-from-url）
    for a in args:
        s = str(a)
        if s.startswith("http://") or s.startswith("https://"):
            if any(pat in s for pat in [".sh", ".ps1", "raw.githubusercontent", "gist.github"]):
                reasons.append(f"fetch script URL: {s}")
                score += 30
                break
    # 8. transport 为 http 缺 SSL
    if transport == "http" and not url.startswith("https://"):
        reasons.append(f"transport=http but not HTTPS")
        score += 10

    score = min(100, score)
    return {
        "name": name,
        "command": cmd,
        "args": args,
        "env_keys": list(env.keys()),
        "url": url,
        "transport": transport,
        "score": score,
        "reasons": reasons,
    }


def analyze_mcp_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"score": 0, "reasons": [f"file not found: {path}"], "servers": []}
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as e:
        return {"score": 0, "reasons": [f"read error: {e}"], "servers": []}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return {"score": 30, "reasons": [f"JSON 解析失败: {e}"], "servers": []}

    servers_dict = data.get("mcpServers") or data.get("servers") or data
    if not isinstance(servers_dict, dict):
        return {"score": 20, "reasons": ["mcpServers 字段不是对象"], "servers": []}

    results = []
    max_score = 0
    all_reasons: list[str] = []
    for name, server in servers_dict.items():
        r = _scan_server(name, server)
        results.append(r)
        max_score = max(max_score, r["score"])
        all_reasons.extend(r["reasons"])
    return {"score": max_score, "reasons": all_reasons, "servers": results, "raw_text": text[:2000]}


def scan_mcp(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    # 延迟导入：避免环形依赖
    from aisec.core.config import get_settings

    settings = get_settings()
    smr = settings.smr
    scorer = RiskScorer(
        w_static=smr.static_weight,
        w_semantic=0,
        w_behavior=smr.behavior_weight,
        t_safe=smr.thresholds.get("safe", 30),
        t_suspicious=smr.thresholds.get("suspicious", 60),
    )

    static = analyze_mcp_file(p)
    # MCP 没有代码可跑，behavior 恒 0；用 score_for_kind 提升 static 权重
    rs = scorer.score_for_kind(
        kind="mcp",
        static=static.get("score", 0),
        semantic=0,
        behavior=0,
        reasons=static.get("reasons", []),
    )

    return {
        "kind": "mcp",
        "path": str(p),
        "sha256": file_hash(p),
        "size_bytes": p.stat().st_size,
        "static": static,
        "semantic": {"score": 0, "reason": "MCP 配置不做语义分析"},
        "behavior": {"score": 0, "reasons": ["MCP 配置不跑沙箱"]},
        "risk": rs.to_dict(),
    }


async def scan_mcp_async(path: str | Path) -> dict[str, Any]:
    """异步版本：用 to_thread 避免阻塞事件循环，并自动归档+告警。"""
    result = await asyncio.to_thread(scan_mcp, path)
    # 自动归档到黑/白名单 + 生成告警 Markdown
    await asyncio.to_thread(_archive_and_alert_mcp, result)
    return result


def _archive_and_alert_mcp(scan_result: dict[str, Any]) -> None:
    """归档到黑/白名单 + 生成告警 Markdown。"""
    try:
        from aisec.core.config import get_settings
        from aisec.scanners.list_archive import ListArchive
        from aisec.scanners.alert_generator import AlertGenerator

        s = get_settings()
        data_dir = Path(s.data_dir)
        archive = ListArchive(data_dir)
        alert_gen = AlertGenerator(data_dir)
        archive.auto_archive(scan_result)
        alert_gen.generate_scan_alert(scan_result)
    except Exception as e:
        logger.warning(f"archive/alert failed: {e}")
