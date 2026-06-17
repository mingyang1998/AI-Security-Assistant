"""soc-agent（SOC 运营 Agent，编排者）。

职责（V0.4 决策 21 - 唯一编排者）：
- 维护 Agent Registry
- 主动调 LLM（V0.4 决策 22 - 唯一可以主动调 LLM 的 Agent）
- 提供 /chat 端点接收自然语言查询
- 调用 probe / gateway 完成复杂任务

注册额外 FastAPI 路由：
    /registry/agents               POST 注册
    /registry/agents/{id}/heartbeat POST 心跳
    /registry/agents/{id}          GET  详情
    /registry/agents               GET  列表
    /events                        GET  最近事件
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from aisec.core.agent import Agent, AgentRole
from aisec.core.a2a import A2AClient
from aisec.core.config import Settings, get_settings
from aisec.core.event_bus import Event
from aisec.core.registry import AgentRegistry
from aisec.core.tools import tool
from aisec.llm import LLMClient
from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)


SYSTEM_PROMPT_SOC = """你是 aisec-demo 的 SOC 运营 Agent，名为 soc-agent。
你是编排者（V0.4 决策 21），唯一可以主动调用 LLM 的 Agent。

你可以调用的工具：
- probe-agent.list_processes / check_network / scan_shadow_agents
- gateway-agent.decide_action / query_identity
- 本地：scan_skill / scan_mcp / get_alerts / get_status

规则：
1. 用户查询涉到"扫描 Skill/MCP"，调用 scan_skill / scan_mcp。
2. 涉到"Agent 拦截/放行/信任"，调 gateway 的工具。
3. 涉到"进程/网络/影子 Agent"，调 probe 的工具。
4. 不要编造数据；未拿到数据前要明示"未获取到"。

回答结构：
- 直接结论
- 简要推理
- 引用了哪些 tool（trace_id）
"""


class SOCAgent(Agent):
    """SOC 运营 Agent（编排者）。"""

    def __init__(self, settings: Settings | None = None):
        super().__init__(settings)
        self.llm = LLMClient(self.settings)
        self.a2a_client = A2AClient(self.settings, from_id=self.agent_id)

    @property
    def agent_id(self) -> str:
        return "soc-agent"

    @property
    def name(self) -> str:
        return "SOC 运营 Agent"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def role(self) -> AgentRole:
        return AgentRole.SOC_OPERATOR

    def _endpoints(self) -> dict[str, str]:
        cfg = self.settings.agents.soc_agent
        return {
            "a2a": f"http://{cfg.host}:{cfg.port}/a2a",
            "chat": f"http://{cfg.host}:{cfg.port}/chat",
            "registry": f"http://{cfg.host}:{cfg.port}/registry/agents",
        }

    async def setup(self) -> None:
        # soc-agent 自身持有 Registry（在 base class 调 _register_to_registry 之前先建好）
        if self.registry is None:
            from aisec.core.registry import AgentRegistry
            self.registry = AgentRegistry(self.settings)
            self.registry.init_schema()
        logger.info(f"[{self.agent_id}] setup done (registry ready)")

        # 注册 SMR 业务工具
        from aisec.scanners import skill_scanner, mcp_scanner

        self.tools.register(
            "scan_skill",
            skill_scanner.scan_skill_async,
            "扫描单个 Skill 文件并返回风险评分（0-100）",
        )
        self.tools.register(
            "scan_mcp",
            mcp_scanner.scan_mcp_async,
            "扫描单个 MCP server 配置并返回风险评分",
        )

        # 注册跨 Agent 工具
        self.tools.register(
            "call_probe_tool",
            self._tool_call_probe,
            "通过 A2A 调 probe-agent 的工具",
        )
        self.tools.register(
            "call_gateway_tool",
            self._tool_call_gateway,
            "通过 A2A 调 gateway-agent 的工具",
        )

    async def main_loop(self) -> None:
        """主循环：心跳 + 定期 sweep offline + 处理控制消息。"""
        hb_task = asyncio.create_task(self.heartbeat_loop(), name="soc-heartbeat")
        sweep_task = asyncio.create_task(self._sweep_loop(), name="soc-sweep")
        try:
            while not self._stop_event.is_set():
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=10)
                    break
                except asyncio.TimeoutError:
                    pass
        finally:
            hb_task.cancel()
            sweep_task.cancel()

    async def _sweep_loop(self) -> None:
        """每 30s 扫一次 offline Agent + 动态零信任评分。"""
        from aisec.core.trust import TrustEngine
        trust_engine = TrustEngine(self.settings)

        while not self._stop_event.is_set():
            try:
                assert self.registry is not None
                offline = await self.registry.sweep_offline()
                if offline:
                    await self.event_bus.append(Event(
                        type="agent_offline",
                        source=self.agent_id,
                        payload={"agents": offline},
                    ))
            except Exception as e:
                logger.warning(f"sweep failed: {e}")

            # 动态零信任评分：读取最近事件，更新 trust_score
            try:
                recent = await self.event_bus.tail(n=200)
                events_dicts = [e.to_dict() for e in recent]
                changes = await trust_engine.evaluate_all(events_dicts)
                if changes:
                    await self.event_bus.append(Event(
                        type="trust_score_updated",
                        source=self.agent_id,
                        payload={"changes": changes},
                    ))
            except Exception as e:
                logger.warning(f"trust evaluation failed: {e}")

            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=30)
                break
            except asyncio.TimeoutError:
                pass

    # ---------- 业务工具 ----------

    async def _tool_call_probe(self, tool_name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        """通过 HTTP 直接调 probe-agent 的工具（更轻量）。"""
        cfg = self.settings.agents.probe_agent
        url = f"http://{cfg.host}:{cfg.port}/tools/{tool_name}"
        import httpx
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(url, json={"args": args or {}})
                return resp.json()
        except Exception as e:
            return {"ok": False, "error": str(e)}

    async def _tool_call_gateway(self, tool_name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        cfg = self.settings.agents.gateway_agent
        url = f"http://{cfg.host}:{cfg.port}/tools/{tool_name}"
        import httpx
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(url, json={"args": args or {}})
                return resp.json()
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ---------- Chat 入口（唯一调 LLM） ----------

    async def handle_chat(self, query: str, body: dict[str, Any]) -> dict[str, Any]:
        """处理自然语言查询。

        简单实现：直接走 LLM。可在此处预编排（Rule + LLM 混合）。
        Sprint 1 不做复杂 ReAct，由后续 Sprint 引入。
        """
        if not query:
            return {"ok": False, "reply": "empty query"}

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT_SOC},
            {"role": "user", "content": query},
        ]
        try:
            # 整体超时 90s：与 LLM 内部 65s 硬超时 + max_retries(2) 匹配
            reply = await asyncio.wait_for(
                self.llm.chat(messages), timeout=90.0
            )
        except asyncio.TimeoutError:
            logger.error(f"chat hard-timeout (90s) for query: {query[:100]}")
            return {"ok": False, "reply": "chat hard-timeout (90s)"}
        except Exception as e:
            logger.exception("LLM call failed")
            return {"ok": False, "reply": f"LLM error: {e}"}

        await self.event_bus.append(Event(
            type="chat",
            source=self.agent_id,
            payload={"query": query, "reply": reply[:500]},
        ))

        return {"ok": True, "agent_id": self.agent_id, "reply": reply, "mock_mode": self.llm.mock_mode}

    # ---------- 注册 Registry 路由（由 build_app 之后挂载） ----------

    def build_app(self):
        app = super().build_app()
        assert self.registry is not None

        @app.post("/registry/agents")
        async def register_agent(request: Request):
            body = await request.json()
            agent_id = body.get("agent_id", "")
            if not agent_id:
                raise HTTPException(400, "agent_id required")
            token = await self.registry.upsert(body)
            await self.event_bus.append(Event(
                type="agent_registered",
                source=self.agent_id,
                payload={"agent_id": agent_id, "name": body.get("name")},
            ))
            return {"ok": True, "agent_id": agent_id, "agent_token": token}

        @app.post("/registry/agents/{agent_id}/heartbeat")
        async def heartbeat(agent_id: str, request: Request):
            body = await request.json()
            trust = body.get("trust_score")
            token = body.get("token")
            ok = await self.registry.heartbeat(
                agent_id,
                trust_score=int(trust) if trust is not None else None,
                token=token,
            )
            if not ok:
                raise HTTPException(404, f"agent '{agent_id}' not registered or token mismatch")
            return {"ok": True, "agent_id": agent_id, "ts": time.time()}

        @app.get("/registry/agents/{agent_id}")
        async def get_agent(agent_id: str):
            row = await self.registry.get(agent_id)
            if not row:
                raise HTTPException(404, f"agent '{agent_id}' not found")
            # agent_card 是 JSON 字符串
            if "agent_card" in row and row["agent_card"]:
                import json
                try:
                    row["agent_card"] = json.loads(row["agent_card"])
                except Exception:
                    pass
            return row

        @app.get("/registry/agents")
        async def list_agents(status: str | None = None):
            return await self.registry.list(status=status)

        @app.get("/events")
        async def list_events(limit: int = 100):
            evs = await self.event_bus.tail(n=limit)
            return {"events": [e.to_dict() for e in evs]}

        # ---------- AISOC Web 控制台 ----------
        from fastapi.responses import HTMLResponse
        from aisec.web import DASHBOARD_HTML

        @app.get("/dashboard", response_class=HTMLResponse)
        async def dashboard_page():
            return DASHBOARD_HTML

        @app.get("/", response_class=HTMLResponse)
        async def root_page():
            return DASHBOARD_HTML

        # ---------- 黑白名单 & 告警 API ----------
        from pathlib import Path as _Path
        from aisec.scanners.list_archive import ListArchive
        from aisec.scanners.alert_generator import AlertGenerator

        _archive = ListArchive(_Path(self.settings.data_dir))
        _alert_gen = AlertGenerator(_Path(self.settings.data_dir))

        @app.get("/whitelist")
        async def list_whitelist():
            return {"items": _archive.list_whitelist()}

        @app.get("/blacklist")
        async def list_blacklist():
            return {"items": _archive.list_blacklist()}

        @app.post("/whitelist/{sha256}/remove")
        async def remove_whitelist(sha256: str):
            ok = _archive.remove_from_whitelist(sha256)
            return {"ok": ok}

        @app.post("/blacklist/{sha256}/remove")
        async def remove_blacklist(sha256: str):
            ok = _archive.remove_from_blacklist(sha256)
            return {"ok": ok}

        @app.get("/alerts")
        async def list_alerts():
            alerts_dir = _Path(self.settings.data_dir) / "alerts"
            if not alerts_dir.exists():
                return {"items": []}
            items = sorted(alerts_dir.glob("*.md"), reverse=True)[:50]
            return {"items": [f.name for f in items]}

        @app.get("/alerts/{filename}")
        async def get_alert(filename: str):
            from fastapi.responses import PlainTextResponse
            alerts_dir = _Path(self.settings.data_dir) / "alerts"
            path = alerts_dir / filename
            if not path.exists() or not filename.endswith(".md"):
                raise HTTPException(404, "alert not found")
            return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown")

        # ---------- MSP 模型熔断 API ----------
        from aisec.core.circuit_breaker import get_breaker_status, reset_breaker as _reset_breaker

        @app.get("/model-breaker")
        async def model_breaker_status():
            """查询模型熔断器状态。"""
            return get_breaker_status(self.settings)

        @app.post("/model-breaker/reset")
        async def model_breaker_reset():
            """重置模型熔断器（恢复模型服务）。"""
            ok = _reset_breaker(self.settings)
            if ok:
                await self.event_bus.append(Event(
                    type="model_circuit_breaker_reset",
                    source=self.agent_id,
                    payload={"action": "reset"},
                ))
            return {"ok": ok}

        # ---------- 动态零信任评分 API ----------
        from aisec.core.trust import TrustEngine
        _trust_engine = TrustEngine(self.settings)

        @app.get("/trust")
        async def trust_summary():
            """获取所有 Agent 的动态信任分摘要。"""
            return {"agents": await _trust_engine.get_trust_summary()}

        return app


def main() -> None:
    """soc-agent 进程入口。"""
    import asyncio
    import logging
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout,
    )
    settings = get_settings()
    cfg = settings.agents.soc_agent
    agent = SOCAgent(settings)
    print(f"[soc-agent] starting on {cfg.host}:{cfg.port}", flush=True)
    asyncio.run(agent.run(host=cfg.host, port=cfg.port))


if __name__ == "__main__":
    main()
