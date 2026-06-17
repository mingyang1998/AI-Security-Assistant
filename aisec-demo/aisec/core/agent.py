"""Agent 基类（V0.4 Multi-Agent 体系核心）。

设计要点：
- Agent 既是进程也是 Agent（V0.4 决策 17）
- 每个 Agent 暴露：/health, /tools, /a2a, /chat, /card
- soc-agent 为主-从模式编排者（V0.4 决策 21）
- Probe/Gateway 热路径不调 LLM（V0.4 决策 22）
"""
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from aisec.core.a2a import A2AMessage, A2AResponse
from aisec.core.config import Settings, get_settings
from aisec.core.event_bus import Event, EventBus
from aisec.core.registry import AgentRegistry
from aisec.core.tools import ToolRegistry

logger = logging.getLogger(__name__)


class AgentRole(str, Enum):
    """Agent 角色分类。"""

    SHADOW_AGENT_DETECTOR = "shadow_agent_detector"  # probe
    TRAFFIC_INTERCEPTOR = "traffic_interceptor"        # gateway
    SOC_OPERATOR = "soc_operator"                      # soc
    CUSTOM = "custom"


@dataclass
class AgentCard:
    """Agent 自我介绍（V0.4 决策）。"""

    agent_id: str
    name: str
    version: str
    role: AgentRole
    owner: str = "aisec"
    trust_score: int = 100
    capabilities: list[dict[str, str]] = field(default_factory=list)
    endpoints: dict[str, str] = field(default_factory=dict)
    registered_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = {
            "agent_id": self.agent_id,
            "name": self.name,
            "version": self.version,
            "role": self.role.value,
            "owner": self.owner,
            "trust_score": self.trust_score,
            "capabilities": self.capabilities,
            "endpoints": self.endpoints,
            "registered_at": self.registered_at,
        }
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AgentCard":
        d = dict(d)
        d["role"] = AgentRole(d.get("role", "custom"))
        d.pop("endpoints", None)  # 启动时重新填充
        return cls(**d)


class Agent(ABC):
    """所有 Agent 的基类。

    子类需实现：
        - agent_id / name / role
        - setup(): 初始化资源（探针、网关、DB 等）
        - main_loop() 异步主循环
    """

    # ---------- 子类需重写 ----------

    @property
    @abstractmethod
    def agent_id(self) -> str:
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        ...

    @property
    @abstractmethod
    def role(self) -> AgentRole:
        ...

    @abstractmethod
    async def setup(self) -> None:
        """初始化资源（DB 连接、探针、网关等）。"""
        ...

    @abstractmethod
    async def main_loop(self) -> None:
        """异步主循环。子类应实现为长跑任务。"""
        ...

    # ---------- 框架提供 ----------

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.tools = ToolRegistry()
        self.event_bus = EventBus(self.settings)
        self.registry: AgentRegistry | None = None  # 仅 soc-agent 持有真实 Registry
        self.app: FastAPI | None = None
        self._server: Any = None  # uvicorn.Server
        self._stop_event: asyncio.Event | None = None  # 懒创建（绑定到 run() 时的 loop）
        self._agent_token: str | None = None  # 注册后由 soc-agent 分配的身份令牌
        self._register_default_tools()

    # ---------- 工具注册 ----------

    def _register_default_tools(self) -> None:
        """注册每个 Agent 都有的基础工具。"""
        self.tools.register("get_alerts", self._tool_get_alerts, "获取最近的告警事件")
        self.tools.register("get_status", self._tool_get_status, "获取 Agent 自身状态")

    async def _tool_get_alerts(self, limit: int = 20) -> dict[str, Any]:
        evs = await self.event_bus.tail(n=limit)
        return {"events": [e.to_dict() for e in evs]}

    async def _tool_get_status(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "version": self.version,
            "role": self.role.value,
            "trust_score": self.card().trust_score,
            "uptime_sec": int(time.time() - self._started_at),
        }

    # ---------- Agent Card ----------

    def card(self) -> AgentCard:
        from datetime import datetime

        return AgentCard(
            agent_id=self.agent_id,
            name=self.name,
            version=self.version,
            role=self.role,
            capabilities=[
                {"tool": name, "desc": spec.get("desc", "")}
                for name, spec in self.tools.list().items()
            ],
            endpoints=self._endpoints(),
            registered_at=datetime.now().isoformat(timespec="seconds"),
        )

    def _endpoints(self) -> dict[str, str]:
        """子类按需 override，返回自身 HTTP 端点。"""
        return {}

    # ---------- FastAPI 应用 ----------

    def build_app(self) -> FastAPI:
        """构造 FastAPI 应用，暴露标准 Agent 端点。"""
        self.app = FastAPI(title=f"aisec-{self.agent_id}", version=self.version)
        self._register_routes()
        return self.app

    def _register_routes(self) -> None:
        assert self.app is not None

        @self.app.get("/health")
        async def health():
            return {"ok": True, "agent_id": self.agent_id, "ts": time.time()}

        @self.app.get("/card")
        async def card():
            return self.card().to_dict()

        @self.app.get("/tools")
        async def list_tools():
            return self.tools.describe()

        @self.app.post("/tools/{name}")
        async def call_tool(name: str, request: Request):
            if name not in self.tools.list():
                raise HTTPException(404, f"tool '{name}' not found")
            body = await request.json() if (await request.body()) else {}
            args = body.get("args", {})
            trace_id = body.get("trace_id")
            try:
                result = await self.tools.call(name, **args)
                return {"ok": True, "result": result, "trace_id": trace_id}
            except Exception as e:
                logger.exception(f"tool {name} failed")
                return JSONResponse(
                    status_code=500,
                    content={"ok": False, "error": str(e), "trace_id": trace_id},
                )

        @self.app.post("/a2a")
        async def a2a_endpoint(request: Request):
            body = await request.json()
            try:
                msg = A2AMessage.from_dict(body)
            except Exception as e:
                raise HTTPException(400, f"invalid A2A message: {e}")
            t0 = time.perf_counter()
            try:
                resp = await self.handle_a2a(msg)
            except Exception as e:
                logger.exception(f"A2A handler error: {e}")
                resp = A2AResponse(
                    from_=self.agent_id,
                    to=msg.from_,
                    trace_id=msg.trace_id,
                    decision="error",
                    action="no_op",
                    reason=str(e),
                    elapsed_ms=int((time.perf_counter() - t0) * 1000),
                    error=str(e),
                )
            resp.elapsed_ms = int((time.perf_counter() - t0) * 1000)
            return resp.to_dict()

        @self.app.post("/chat")
        async def chat(request: Request):
            """自然语言入口（仅 soc-agent 真正实现 LLM 推理）。"""
            body = await request.json()
            query = body.get("query", "")
            return await self.handle_chat(query, body)

    # ---------- A2A 处理（子类 override） ----------

    async def handle_a2a(self, msg: A2AMessage) -> A2AResponse:
        """默认 A2A 处理器：echo + 自身状态。"""
        return A2AResponse(
            from_=self.agent_id,
            to=msg.from_,
            trace_id=msg.trace_id,
            decision="ok",
            action="echo",
            reason=f"{self.agent_id} received {msg.intent}",
            result={"status": await self._tool_get_status()},
        )

    # ---------- Chat（仅 soc-agent 真正实现） ----------

    async def handle_chat(self, query: str, body: dict[str, Any]) -> dict[str, Any]:
        """默认 Chat：返回 'not implemented'。子类（soc-agent）override。"""
        return {
            "ok": False,
            "agent_id": self.agent_id,
            "reply": f"chat not implemented on {self.agent_id}",
        }

    # ---------- 生命周期 ----------

    _started_at: float = 0.0

    async def run(self, host: str = "127.0.0.1", port: int = 0) -> None:
        """启动 Agent：setup -> 注册路由 -> 启动 HTTP -> 跑主循环。"""
        self._started_at = time.time()
        # 在当前 event loop 上创建 stop_event（避免 __init__ 时无 loop 的问题）
        if self._stop_event is None:
            self._stop_event = asyncio.Event()
        await self.setup()
        app = self.build_app()
        # 注册到 soc-agent Registry（如果有）
        await self._register_to_registry()

        # 后台跑主循环
        loop_task = asyncio.create_task(self.main_loop(), name=f"loop-{self.agent_id}")

        # 启动 HTTP（uvicorn）
        import uvicorn

        config = uvicorn.Config(
            app, host=host, port=port, log_level="warning", access_log=False
        )
        self._server = uvicorn.Server(config)
        server_task = asyncio.create_task(self._server.serve(), name=f"http-{self.agent_id}")

        logger.info(f"[{self.agent_id}] started at {host}:{port}")
        try:
            await self._stop_event.wait()
        finally:
            self._server.should_exit = True
            await asyncio.gather(server_task, loop_task, return_exceptions=True)
            logger.info(f"[{self.agent_id}] stopped")

    async def stop(self) -> None:
        """优雅停止。"""
        self._stop_event.set()

    async def _register_to_registry(self) -> None:
        """向 soc-agent 注册（best-effort，失败不致命）。注册成功后保存 token。"""
        if self.agent_id == "soc-agent":
            # soc-agent 自身初始化 Registry
            from aisec.core.registry import AgentRegistry

            self.registry = AgentRegistry(self.settings)
            self.registry.init_schema()
            return
        try:
            soc_url = f"http://{self.settings.agents.soc_agent.host}:{self.settings.agents.soc_agent.port}"
            async with httpx.AsyncClient(timeout=2.0) as client:
                r = await client.post(f"{soc_url}/registry/agents", json=self.card().to_dict())
                if r.status_code == 200:
                    data = r.json()
                    self._agent_token = data.get("agent_token")
                    logger.info(f"[{self.agent_id}] registered to soc-agent (token={'***' if self._agent_token else 'N/A'})")
        except Exception as e:
            logger.warning(f"[{self.agent_id}] register to soc-agent failed (will retry via heartbeat): {e}")

    async def heartbeat_loop(self) -> None:
        """周期向 soc-agent 发送心跳；如果未注册成功，先重试注册。"""
        soc_url = f"http://{self.settings.agents.soc_agent.host}:{self.settings.agents.soc_agent.port}"
        interval = self.settings.heartbeat.interval_sec
        registered = False
        async with httpx.AsyncClient(timeout=2.0) as client:
            while not self._stop_event.is_set():
                if not registered:
                    try:
                        r = await client.post(
                            f"{soc_url}/registry/agents",
                            json=self.card().to_dict(),
                        )
                        if r.status_code == 200:
                            data = r.json()
                            self._agent_token = data.get("agent_token")
                            registered = True
                            logger.info(f"[{self.agent_id}] registered to soc-agent")
                    except Exception:
                        pass
                if registered:
                    try:
                        payload: dict[str, Any] = {"ts": time.time(), "trust_score": self.card().trust_score}
                        if self._agent_token:
                            payload["token"] = self._agent_token
                        await client.post(
                            f"{soc_url}/registry/agents/{self.agent_id}/heartbeat",
                            json=payload,
                        )
                    except Exception as e:
                        logger.debug(f"heartbeat failed: {e}")
                        registered = False  # 下个循环重新尝试注册
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=interval)
                    break
                except asyncio.TimeoutError:
                    pass
