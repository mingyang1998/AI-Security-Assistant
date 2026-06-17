"""CLI: python -m aisec start / stop / status / scan-skill / scan-mcp / scan-model / web

命令清单：
    start       启动三个 Agent（soc -> probe/gateway 后启动）
    stop        优雅停止所有 Agent
    status      查看各 Agent 健康状态
    agents      列出已注册 Agent
    events      tail JSONL 事件
    scan-skill  Sprint 1 工具 - 扫描单个 Skill 文件
    scan-mcp    Sprint 1 工具 - 扫描单个 MCP 配置
    scan-model  Sprint 3 MSP - 跑一次 LLM 模型安全扫描
    web         Sprint 4 - 启动 AISOC 单页控制台
    chat        向 soc-agent 发自然语言查询
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import yaml

from aisec.core.config import get_settings
from aisec.core.event_bus import EventBus

logger = logging.getLogger(__name__)

PID_DIR = Path("data/pids")


def _ensure_dirs() -> None:
    s = get_settings()
    PID_DIR.mkdir(parents=True, exist_ok=True)
    (s.abs(s.audit.events_dir)).mkdir(parents=True, exist_ok=True)
    s.abs(s.audit.db_path).parent.mkdir(parents=True, exist_ok=True)
    s.abs(s.alerts.dir).mkdir(parents=True, exist_ok=True)
    s.abs(s.sandbox.temp_dir).mkdir(parents=True, exist_ok=True)


def _pid_path(agent_id: str) -> Path:
    return PID_DIR / f"{agent_id}.pid"


def _is_running(agent_id: str) -> int | None:
    p = _pid_path(agent_id)
    if not p.exists():
        return None
    try:
        pid = int(p.read_text().strip())
        # Windows 下没有 signals.SIGTERM 概念；用 tasklist 简单判断
        if sys.platform == "win32":
            r = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}"],
                capture_output=True, text=True,
            )
            return pid if str(pid) in r.stdout else None
        else:
            try:
                os.kill(pid, 0)
                return pid
            except ProcessLookupError:
                return None
    except Exception:
        return None


def _spawn_agent(agent_module: str, port: int) -> int:
    """子进程启动一个 Agent 进程。返回 PID。"""
    # -u: 无缓冲输出，确保日志文件能即时看到
    cmd = [sys.executable, "-u", "-m", agent_module]
    log_path = PID_DIR / f"{agent_module.split('.')[-1]}.log"
    log_f = open(log_path, "ab")
    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    p = subprocess.Popen(
        cmd,
        stdout=log_f,
        stderr=subprocess.STDOUT,
        creationflags=creationflags,
        cwd=os.getcwd(),
    )
    return p.pid


def cmd_start(args: argparse.Namespace) -> int:
    _ensure_dirs()
    s = get_settings()
    # 启动顺序：soc -> probe -> gateway
    plan = [
        ("soc-agent", "aisec.agents.soc", s.agents.soc_agent.port),
        ("probe-agent", "aisec.agents.probe", s.agents.probe_agent.port),
        ("gateway-agent", "aisec.agents.gateway", s.agents.gateway_agent.port),
    ]
    started: list[tuple[str, int]] = []
    for agent_id, mod, port in plan:
        if _is_running(agent_id):
            print(f"  [skip] {agent_id} already running (pid={_is_running(agent_id)})")
            continue
        pid = _spawn_agent(mod, port)
        _pid_path(agent_id).write_text(str(pid))
        print(f"  [ok]   {agent_id} started (pid={pid}, port={port})")
        started.append((agent_id, pid))
        time.sleep(0.5)

    # 等待 soc-agent 启动
    if started:
        print("Waiting for soc-agent health ...")
        soc_url = f"http://{s.agents.soc_agent.host}:{s.agents.soc_agent.port}/health"
        for _ in range(20):
            try:
                r = httpx.get(soc_url, timeout=1.0)
                if r.status_code == 200:
                    print("  soc-agent is healthy.")
                    break
            except Exception:
                time.sleep(0.5)
        else:
            print("  [warn] soc-agent not healthy after 10s. Check data/pids/*.log")
    print("Done. Try: aisec status")
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    plan = ["gateway-agent", "probe-agent", "soc-agent"]
    for agent_id in plan:
        pid = _is_running(agent_id)
        if pid is None:
            print(f"  [skip] {agent_id} not running")
            _pid_path(agent_id).unlink(missing_ok=True)
            continue
        try:
            if sys.platform == "win32":
                # CTRL_BREAK_EVENT：子进程注册了 signal handler 即可优雅退出
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    check=False, capture_output=True,
                )
            else:
                os.kill(pid, signal.SIGTERM)
            print(f"  [ok]   {agent_id} stopping (pid={pid})")
        except Exception as e:
            print(f"  [err]  {agent_id} stop failed: {e}")
        _pid_path(agent_id).unlink(missing_ok=True)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    s = get_settings()
    rows = []
    for agent_id, cfg in [
        ("soc-agent", s.agents.soc_agent),
        ("probe-agent", s.agents.probe_agent),
        ("gateway-agent", s.agents.gateway_agent),
    ]:
        pid = _is_running(agent_id)
        url = f"http://{cfg.host}:{cfg.port}/health"
        health = "down"
        if pid is not None:
            try:
                r = httpx.get(url, timeout=1.0)
                if r.status_code == 200:
                    health = "healthy"
            except Exception:
                health = "unhealthy"
        rows.append((agent_id, pid or "-", f"{cfg.host}:{cfg.port}", health))
    print(f"{'AGENT':<16} {'PID':<8} {'ENDPOINT':<22} STATUS")
    print("-" * 60)
    for r in rows:
        print(f"{r[0]:<16} {str(r[1]):<8} {r[2]:<22} {r[3]}")
    return 0


def cmd_agents(args: argparse.Namespace) -> int:
    s = get_settings()
    url = f"http://{s.agents.soc_agent.host}:{s.agents.soc_agent.port}/registry/agents"
    try:
        r = httpx.get(url, timeout=2.0)
        if r.status_code != 200:
            print(f"soc-agent not reachable: HTTP {r.status_code}")
            return 1
        rows = r.json()
    except Exception as e:
        print(f"soc-agent not reachable: {e}")
        return 1
    if not rows:
        print("No agents registered yet.")
        return 0
    print(f"{'AGENT_ID':<16} {'NAME':<22} {'STATUS':<10} {'TRUST':<6} LAST HB")
    print("-" * 80)
    for row in rows:
        from datetime import datetime
        ts = row.get("last_heartbeat") or 0
        ts_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "-"
        print(f"{row['agent_id']:<16} {row['name']:<22} {row['status']:<10} {row['trust_score']:<6} {ts_str}")
    return 0


def cmd_events(args: argparse.Namespace) -> int:
    bus = EventBus(get_settings())
    evs = bus.tail_sync(n=args.limit)
    for e in evs:
        print(f"[{e.ts}] {e.source:<16} {e.type:<24} {json.dumps(e.payload, ensure_ascii=False)[:120]}")
    return 0


def cmd_scan_skill(args: argparse.Namespace) -> int:
    from aisec.scanners import skill_scanner

    path = Path(args.path)
    if not path.exists():
        print(f"file not found: {path}")
        return 1
    result = skill_scanner.scan_skill(path)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_scan_mcp(args: argparse.Namespace) -> int:
    from aisec.scanners import mcp_scanner

    path = Path(args.path)
    if not path.exists():
        print(f"file not found: {path}")
        return 1
    result = mcp_scanner.scan_mcp(path)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_scan_model(args: argparse.Namespace) -> int:
    """Sprint 3 MSP: 跑一次 LLM 模型安全扫描（轻量 Demo 版）。"""
    import asyncio

    from aisec.core.event_bus import EventBus
    from aisec.core.config import get_settings
    from aisec.msp.runner import run_full_scan, save_report

    s = get_settings()
    phases: list[str] = []
    if args.fingerprint: phases.append("fingerprint")
    if args.injection:   phases.append("injection")
    if args.harmful:     phases.append("harmful")
    if args.jailbreak:   phases.append("jailbreak")
    if not phases:
        phases = ["fingerprint", "injection", "harmful", "jailbreak"]

    report = asyncio.run(run_full_scan(
        phases=phases,
        sample_prompt=args.prompt,
        sample_output=args.output,
        do_jailbreak=args.jailbreak,
    ))

    paths = save_report(report, out_dir=str(s.abs("data/msp")))

    # 写一份 Markdown 告警到 alerts（如果等级 >= suspicious）
    if report.overall_level in ("suspicious", "dangerous"):
        from datetime import datetime
        alert_path = s.abs(s.alerts.dir) / f"msp_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.md"
        alert_path.write_text(report.to_markdown(), encoding="utf-8")
        # 同步写一条事件
        try:
            bus = EventBus(s)
            bus.append_nowait_safe(
                event_type="msp_scan_alert",
                payload={
                    "level": report.overall_level,
                    "score": report.overall_score,
                    "model": report.fingerprint.model,
                    "fingerprint": report.fingerprint.fingerprint,
                    "report_json": str(paths["json"]),
                    "report_md": str(alert_path),
                },
                source="cli",
            )
        except Exception as e:
            print(f"warn: event log failed: {e}")

    # 控制台摘要
    fp = report.fingerprint
    print(f"[msp] model={fp.model}  provider={fp.provider}  mock={fp.mock_mode}")
    print(f"[msp] fingerprint={fp.fingerprint[:16]}...  host={fp.host}")
    print(f"[msp] overall_score={report.overall_score}  level={report.overall_level}  "
          f"elapsed={report.elapsed_sec:.2f}s")
    print(f"[msp] report_json={paths['json']}")
    print(f"[msp] report_md  ={paths['md']}")
    for name, p in report.phases.items():
        if name == "jailbreak":
            print(f"  - {name:12s} rate={p.get('jailbreak_rate_pct', 0):.1f}%  "
                  f"successes={p.get('successes', 0)}/{p.get('evaluated', 0)}")
        else:
            print(f"  - {name:12s} score={p.get('score', 0):>3}  level={p.get('level', 'safe')}")
    return 0 if report.overall_level == "safe" else 2


def cmd_web(args: argparse.Namespace) -> int:
    """Sprint 4: 启动 AISOC 单页控制台。"""
    from aisec.web import main as web_main
    return web_main(host=args.host, port=args.port)


def cmd_chat(args: argparse.Namespace) -> int:
    s = get_settings()
    url = f"http://{s.agents.soc_agent.host}:{s.agents.soc_agent.port}/chat"
    try:
        # 超时 90s = server LLM timeout(30s) + max_retries(2) + 缓冲
        # LLM 内部也已用 asyncio.wait_for 兜底 65s
        r = httpx.post(url, json={"query": args.query}, timeout=90.0)
    except Exception as e:
        print(f"chat failed: {e}")
        return 1
    print(json.dumps(r.json(), ensure_ascii=False, indent=2))
    return 0


# ---------- argparse ----------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aisec", description="AI 安全助手 Demo CLI")
    p.add_argument("--config", default=None, help="配置文件路径")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("start", help="启动三个 Agent").set_defaults(func=cmd_start)
    sub.add_parser("stop", help="停止三个 Agent").set_defaults(func=cmd_stop)
    sub.add_parser("status", help="查看 Agent 健康").set_defaults(func=cmd_status)
    sub.add_parser("agents", help="查看注册 Agent").set_defaults(func=cmd_agents)

    p_e = sub.add_parser("events", help="tail 事件流")
    p_e.add_argument("--limit", type=int, default=20)
    p_e.set_defaults(func=cmd_events)

    p_ss = sub.add_parser("scan-skill", help="扫描 Skill 文件")
    p_ss.add_argument("path", help="Skill 文件路径")
    p_ss.set_defaults(func=cmd_scan_skill)

    p_sm = sub.add_parser("scan-mcp", help="扫描 MCP server 配置")
    p_sm.add_argument("path", help="MCP server 配置文件路径（JSON）")
    p_sm.set_defaults(func=cmd_scan_mcp)

    p_sm2 = sub.add_parser("scan-model", help="Sprint 3 MSP - LLM 模型安全扫描")
    p_sm2.add_argument("--fingerprint", action="store_true", help="仅跑模型指纹")
    p_sm2.add_argument("--injection", action="store_true", help="仅跑 prompt 注入检测")
    p_sm2.add_argument("--harmful", action="store_true", help="仅跑有害输出检测")
    p_sm2.add_argument("--no-jailbreak", dest="jailbreak", action="store_false",
                        help="跳过越狱主动探测（默认开启）")
    p_sm2.add_argument("--prompt", help="自定义测试 prompt（注入检测用）")
    p_sm2.add_argument("--output", help="自定义测试输出（有害检测用）")
    p_sm2.set_defaults(func=cmd_scan_model, jailbreak=True)

    p_web = sub.add_parser("web", help="Sprint 4 - 启动 AISOC 单页控制台")
    p_web.add_argument("--host", default="127.0.0.1", help="监听地址 (默认 127.0.0.1)")
    p_web.add_argument("--port", type=int, default=9000, help="端口 (默认 9000)")
    p_web.set_defaults(func=cmd_web)

    p_c = sub.add_parser("chat", help="向 soc-agent 发自然语言查询")
    p_c.add_argument("query", help="查询文本")
    p_c.set_defaults(func=cmd_chat)

    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    parser = build_parser()
    args = parser.parse_args(argv)
    # 加载配置
    if args.config:
        from aisec.core.config import load_config
        load_config(args.config)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
