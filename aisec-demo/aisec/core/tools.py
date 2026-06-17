"""Tool 注册与调度（V0.4 决策 20 - 仿 MCP 风格）。

每个 Agent 暴露：
    GET  /tools            - 工具清单
    POST /tools/{name}     - 调用工具（body: {"args": {...}, "trace_id": "..."}）
"""
from __future__ import annotations

import asyncio
import inspect
import logging
from functools import wraps
from typing import Any, Callable

logger = logging.getLogger(__name__)


def tool(name: str | None = None, desc: str = ""):
    """Tool 装饰器。

    使用：
        @tool(desc="列出进程")
        async def list_processes(name: str = "") -> dict: ...
    """

    def deco(fn: Callable) -> Callable:
        actual_name = name or fn.__name__
        sig = inspect.signature(fn)

        @wraps(fn)
        async def wrapper(*args, **kwargs):
            return await fn(*args, **kwargs)

        wrapper.__tool_name__ = actual_name  # type: ignore[attr-defined]
        wrapper.__tool_desc__ = desc or fn.__doc__ or ""  # type: ignore[attr-defined]
        wrapper.__tool_sig__ = str(sig)  # type: ignore[attr-defined]
        return wrapper

    return deco


class ToolRegistry:
    """Agent 内部工具注册表。"""

    def __init__(self):
        self._tools: dict[str, Callable] = {}

    def register(self, name: str, fn: Callable, desc: str = "") -> None:
        self._tools[name] = fn
        if desc:
            try:
                fn.__tool_desc__ = desc  # type: ignore[attr-defined]
            except Exception:
                pass

    def list(self) -> dict[str, dict[str, str]]:
        return {
            name: {
                "desc": getattr(fn, "__tool_desc__", "") or (fn.__doc__ or ""),
                "sig": str(getattr(fn, "__tool_sig__", "") or ""),
            }
            for name, fn in self._tools.items()
        }

    def describe(self) -> list[dict[str, str]]:
        return [
            {"name": name, "desc": spec["desc"], "signature": spec["sig"]}
            for name, spec in self.list().items()
        ]

    async def call(self, name: str, *args, **kwargs) -> Any:
        if name not in self._tools:
            raise KeyError(f"tool '{name}' not found")
        fn = self._tools[name]
        if not asyncio.iscoroutinefunction(fn):
            return fn(*args, **kwargs)
        return await fn(*args, **kwargs)
