"""A2A-Lite 协议实现（V0.4 决策）。

消息格式（JSON over 本机 HTTP）：
    请求：
        { "from", "to", "intent", "trace_id", "context", "deadline_ms", "retry" }
    响应：
        { "from", "to", "trace_id", "decision", "action", "reason", "elapsed_ms" }

约束：
- 走 127.0.0.1:<port>/a2a
- deadline_ms 默认 100ms；超时 fail-closed
- 所有消息落 JSONL 事件流（如果开启了 a2a.log_to_events）
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx

from aisec.core.config import Settings, get_settings

logger = logging.getLogger(__name__)


# ---------- 消息模型 ----------


@dataclass
class A2AMessage:
    """A2A-Lite 请求消息。"""

    from_: str
    to: str
    intent: str
    context: dict[str, Any] = field(default_factory=dict)
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    deadline_ms: int = 100
    retry: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["from"] = d.pop("from_")
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "A2AMessage":
        d = dict(data)
        d["from_"] = d.pop("from")
        return cls(**d)


@dataclass
class A2AResponse:
    """A2A-Lite 响应消息。"""

    from_: str
    to: str
    trace_id: str
    decision: str = "unknown"             # allow / deny / unknown / error
    action: str = "no_op"
    reason: str = ""
    result: dict[str, Any] = field(default_factory=dict)
    elapsed_ms: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["from"] = d.pop("from_")
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "A2AResponse":
        d = dict(data)
        d["from_"] = d.pop("from")
        return cls(**d)


# ---------- 异常 ----------


class A2AError(Exception):
    """A2A 调用失败（超时、连接错误、返回 error）。"""


# ---------- 客户端 ----------


class A2AClient:
    """A2A-Lite HTTP 客户端。

    使用示例：
        client = A2AClient()
        resp = await client.request(
            "soc-agent", "http://127.0.0.1:8000/a2a",
            intent="verify_identity",
            context={"fingerprint": "langchain-0.3"},
        )
    """

    def __init__(self, settings: Settings | None = None, from_id: str = "unknown"):
        self.settings = settings or get_settings()
        self.from_id = from_id
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(2.0))
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def request(
        self,
        to_agent: str,
        endpoint: str,
        intent: str,
        context: dict[str, Any] | None = None,
        trace_id: str | None = None,
        deadline_ms: int | None = None,
    ) -> A2AResponse:
        """发送 A2A 请求并等待响应。"""
        deadline = (
            deadline_ms if deadline_ms is not None else self.settings.a2a.default_deadline_ms
        )
        msg = A2AMessage(
            from_=self.from_id,
            to=to_agent,
            intent=intent,
            context=context or {},
            trace_id=trace_id or str(uuid.uuid4())[:12],
            deadline_ms=deadline,
        )

        # 审计：请求消息落 JSONL（如果开启）
        if self.settings.a2a.log_to_events:
            self._log_event("a2a_request", msg.to_dict())

        # deadline 转换为 httpx 超时（秒，向上取整 + 余量）
        timeout_sec = max(0.05, deadline / 1000.0)
        t0 = time.perf_counter()
        try:
            client = await self._get_client()
            resp = await client.post(endpoint, json=msg.to_dict(), timeout=timeout_sec)
            resp.raise_for_status()
            data = resp.json()
        except httpx.TimeoutException as e:
            elapsed = int((time.perf_counter() - t0) * 1000)
            logger.warning(f"A2A timeout to {to_agent} ({elapsed}ms): {e}")
            # fail-closed
            fail_resp = A2AResponse(
                from_=to_agent,
                to=self.from_id,
                trace_id=msg.trace_id,
                decision="deny",
                action="block",
                reason=f"A2A timeout after {elapsed}ms (fail-closed)",
                elapsed_ms=elapsed,
                error=str(e),
            )
            if self.settings.a2a.log_to_events:
                self._log_event("a2a_response", fail_resp.to_dict())
            return fail_resp
        except Exception as e:
            elapsed = int((time.perf_counter() - t0) * 1000)
            logger.error(f"A2A error to {to_agent}: {e}")
            fail_resp = A2AResponse(
                from_=to_agent,
                to=self.from_id,
                trace_id=msg.trace_id,
                decision="error",
                action="no_op",
                reason=f"A2A transport error: {e}",
                elapsed_ms=elapsed,
                error=str(e),
            )
            if self.settings.a2a.log_to_events:
                self._log_event("a2a_response", fail_resp.to_dict())
            return fail_resp

        elapsed = int((time.perf_counter() - t0) * 1000)
        ar = A2AResponse.from_dict(data)
        ar.elapsed_ms = elapsed

        if self.settings.a2a.log_to_events:
            self._log_event("a2a_response", ar.to_dict())
        return ar

    def _log_event(self, event_type: str, payload: dict[str, Any]) -> None:
        """同步落盘 JSONL 事件（用于 A2A 审计）。"""
        try:
            from aisec.core.event_bus import EventBus  # 局部避免循环

            bus = EventBus(self.settings)
            bus.append_nowait_safe(event_type, payload)
        except Exception as e:  # 审计失败不影响主流程
            logger.debug(f"A2A audit log failed (non-fatal): {e}")
