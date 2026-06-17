"""probe-agent（终端探针 Agent）。

职责（V0.4 Plan §2.1.2）：
- 扫描本机进程、网络连接、文件系统变更
- 检测"影子 Agent"：未在白名单但行为类似 Agent 的进程
- 触发 alert 写入 EventBus

实现路线：Sprint 1 阶段提供 process 扫描 + 影子 Agent 启发式规则。
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import psutil
from aisec.core.agent import Agent, AgentRole
from aisec.core.config import Settings, get_settings
from aisec.core.event_bus import Event
from aisec.core.tools import tool

logger = logging.getLogger(__name__)


# 简易影子 Agent 启发式：进程名/命令行中含以下特征
SHADOW_AGENT_HINTS = [
    "langchain", "langgraph", "autogen", "dify", "crewai",
    "openai", "anthropic", "claude", "qwen", "deepseek",
    "agent", "llm", "gpt",
]

# 已知 LLM / 公共可信出站目的（域名/IP 片段）
EGRESS_WHITELIST = (
    "127.0.0.1", "::1", "localhost",
    "dashscope.aliyuncs.com", "aliyuncs.com",
    "openai.com", "api.openai.com",
    "anthropic.com", "api.anthropic.com",
    "deepseek.com", "api.deepseek.com",
    "huggingface.co",
    "pypi.org", "pypi.python.org", "files.pythonhosted.org",
    "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "googleapis.com", "gstatic.com",
    "1.1.1.1", "8.8.8.8", "8.8.4.4",  # 公共 DNS（白名单放行）
)

# 高风险端口（常被 reverse shell / 挖矿 / 勒索用）
HIGH_RISK_PORTS = frozenset({
    22, 23, 135, 139, 445, 3389,        # 远程管理
    1337, 31337, 4444, 5555,            # 常见 backdoor
    6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669,  # IRC 僵尸网络
    9001, 9030, 9050, 9150,             # Tor
    8332, 8333,                         # 比特币
})

# 进程白名单（系统关键进程，扫描时跳过以减少噪音）
SKIP_PROC_NAMES = frozenset({
    "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe", "services.exe",
    "System", "systemd", "init", "kthreadd", "ksoftirqd",
})


class ProbeAgent(Agent):
    """终端探针 Agent。"""

    def __init__(self, settings: Settings | None = None):
        super().__init__(settings)
        self._scan_count = 0
        self._shadow_alerts: list[dict[str, Any]] = []

    # ---------- Agent 元信息 ----------

    @property
    def agent_id(self) -> str:
        return "probe-agent"

    @property
    def name(self) -> str:
        return "终端探针 Agent"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def role(self) -> AgentRole:
        return AgentRole.SHADOW_AGENT_DETECTOR

    def _endpoints(self) -> dict[str, str]:
        cfg = self.settings.agents.probe_agent
        return {
            "a2a": f"http://{cfg.host}:{cfg.port}/a2a",
            "chat": f"http://{cfg.host}:{cfg.port}/chat",
        }

    # ---------- 生命周期 ----------

    async def setup(self) -> None:
        logger.info(f"[{self.agent_id}] setup done")
        # 注册业务工具
        self.tools.register("list_processes", self._tool_list_processes, "列出本机进程")
        self.tools.register("check_network", self._tool_check_network, "列出本机网络连接")
        self.tools.register("scan_shadow_agents", self._tool_scan_shadow_agents, "扫描疑似影子 Agent 进程")
        self.tools.register("watch_files", self._tool_watch_files, "监控目录变更")
        self.tools.register("scan_anomalous_egress", self._tool_scan_anomalous_egress, "扫描异常出站连接")

    async def main_loop(self) -> None:
        """主循环：每 N 秒扫一次进程/网络，触发影子 Agent + 异常出站检测。"""
        interval = 10  # 秒
        # 同时跑心跳
        hb_task = asyncio.create_task(self.heartbeat_loop(), name="probe-heartbeat")
        try:
            while not self._stop_event.is_set():
                try:
                    shadow = await self._scan_shadow_agents()
                    if shadow:
                        await self._emit_shadow_alert(shadow)
                except Exception as e:
                    logger.exception(f"shadow scan failed: {e}")
                try:
                    anomalies = await self._scan_anomalous_egress()
                    if anomalies:
                        await self._emit_egress_alert(anomalies)
                except Exception as e:
                    logger.exception(f"egress scan failed: {e}")
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=interval)
                    break
                except asyncio.TimeoutError:
                    pass
        finally:
            hb_task.cancel()

    # ---------- 业务工具 ----------

    async def _tool_list_processes(self, name_contains: str = "", limit: int = 200) -> dict[str, Any]:
        procs: list[dict[str, Any]] = []
        for p in psutil.process_iter(["pid", "name", "cmdline", "username"]):
            try:
                info = p.info
                cmd = " ".join(info.get("cmdline") or [])
                if name_contains and name_contains.lower() not in (info["name"] or "").lower() and name_contains.lower() not in cmd.lower():
                    continue
                procs.append({
                    "pid": info["pid"],
                    "name": info["name"],
                    "username": info.get("username"),
                    "cmdline": (cmd[:200] + "...") if len(cmd) > 200 else cmd,
                })
                if len(procs) >= limit:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return {"count": len(procs), "processes": procs}

    async def _tool_check_network(self, kind: str = "inet") -> dict[str, Any]:
        conns: list[dict[str, Any]] = []
        try:
            for c in psutil.net_connections(kind=kind):
                if c.status != "ESTABLISHED":
                    continue
                conns.append({
                    "fd": c.fd,
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                    "pid": c.pid,
                    "status": c.status,
                })
        except Exception as e:
            logger.warning(f"net_connections failed: {e}")
        return {"count": len(conns), "connections": conns}

    async def _tool_scan_shadow_agents(self) -> dict[str, Any]:
        shadow = await self._scan_shadow_agents()
        return {"count": len(shadow), "shadow_agents": shadow}

    async def _tool_watch_files(self, path: str, duration_sec: int = 30) -> dict[str, Any]:
        """简易文件监控：duration_sec 内观察 path 下的变更。"""
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError:
            return {"ok": False, "error": "watchdog not installed"}

        events: list[dict[str, Any]] = []

        class Handler(FileSystemEventHandler):
            def on_any_event(self, event):
                events.append({
                    "type": event.event_type,
                    "path": event.src_path,
                    "is_directory": event.is_directory,
                    "ts": time.time(),
                })

        obs = Observer()
        obs.schedule(Handler(), path, recursive=True)
        obs.start()
        try:
            await asyncio.sleep(duration_sec)
        finally:
            obs.stop()
            obs.join()
        return {"count": len(events), "events": events}

    async def _tool_scan_anomalous_egress(self) -> dict[str, Any]:
        """工具方法：扫描异常出站连接并返回。"""
        anomalies = await self._scan_anomalous_egress()
        return {"count": len(anomalies), "anomalies": anomalies}

    # ---------- 内部 ----------

    async def _scan_shadow_agents(self) -> list[dict[str, Any]]:
        """启发式扫描：进程名/命令行匹配 LLM/Agent 关键字。"""
        self._scan_count += 1
        hits: list[dict[str, Any]] = []
        for p in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                info = p.info
                name = (info.get("name") or "").lower()
                cmd = " ".join(info.get("cmdline") or []).lower()
                matched = [k for k in SHADOW_AGENT_HINTS if k in name or k in cmd]
                if matched:
                    hits.append({
                        "pid": info["pid"],
                        "name": info["name"],
                        "matched_keywords": matched,
                        "cmdline": cmd[:300],
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        self._shadow_alerts = hits
        return hits

    async def _emit_shadow_alert(self, shadow: list[dict[str, Any]]) -> None:
        evt = Event(
            type="shadow_agent_detected",
            source=self.agent_id,
            payload={"count": len(shadow), "agents": shadow[:20]},
        )
        await self.event_bus.append(evt)

    async def _scan_anomalous_egress(self) -> list[dict[str, Any]]:
        """扫描异常出站连接。

        规则：
        1. 高风险端口（reverse shell / 僵尸网络） -> anomaly
        2. 目的 IP 不在 EGRESS_WHITELIST 中且非 loopback -> anomaly
        3. 系统关键进程（svchost 等）的连接忽略（噪音）
        """
        hits: list[dict[str, Any]] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as e:
            logger.warning(f"net_connections failed (need admin?): {e}")
            return hits

        proc_cache: dict[int, psutil.Process] = {}
        for c in conns:
            if c.status != "ESTABLISHED" or not c.raddr:
                continue
            ip = c.raddr.ip
            port = c.raddr.port
            # loopback 跳过
            if ip in ("127.0.0.1", "::1", "0.0.0.0"):
                continue
            # 解析进程名
            proc_name = ""
            if c.pid:
                try:
                    if c.pid not in proc_cache:
                        proc_cache[c.pid] = psutil.Process(c.pid)
                    proc_name = proc_cache[c.pid].name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            # 系统关键进程跳过
            if proc_name in SKIP_PROC_NAMES:
                continue
            # 1. 高风险端口
            if port in HIGH_RISK_PORTS:
                hits.append({
                    "pid": c.pid,
                    "proc_name": proc_name,
                    "ip": ip,
                    "port": port,
                    "kind": "high_risk_port",
                    "reason": f"连接到高风险端口 {port}",
                })
                continue
            # 2. 非白名单目的
            ip_lower = ip.lower()
            whitelisted = any(
                ip_lower == w or ip_lower.endswith("." + w)
                for w in EGRESS_WHITELIST
            )
            if not whitelisted:
                hits.append({
                    "pid": c.pid,
                    "proc_name": proc_name,
                    "ip": ip,
                    "port": port,
                    "kind": "non_whitelisted_egress",
                    "reason": f"非白名单目的: {ip}:{port}",
                })
        return hits

    async def _emit_egress_alert(self, anomalies: list[dict[str, Any]]) -> None:
        evt = Event(
            type="anomalous_egress_detected",
            source=self.agent_id,
            payload={"count": len(anomalies), "anomalies": anomalies[:50]},
        )
        await self.event_bus.append(evt)
        logger.warning(f"[{self.agent_id}] anomalous egress: {len(anomalies)} hits")


def main() -> None:
    """probe-agent 进程入口。"""
    import asyncio
    import logging
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout,
    )
    settings = get_settings()
    cfg = settings.agents.probe_agent
    agent = ProbeAgent(settings)
    print(f"[probe-agent] starting on {cfg.host}:{cfg.port}", flush=True)
    asyncio.run(agent.run(host=cfg.host, port=cfg.port))


if __name__ == "__main__":
    main()
