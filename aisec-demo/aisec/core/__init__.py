"""核心框架：配置加载、Agent 基类、A2A-Lite、Event Bus、Registry、工具装饰器。

所有导出为惰性（通过 __getattr__），避免启动时拉起未使用的依赖。
"""
from __future__ import annotations

__all__ = [
    "Settings",
    "get_settings",
    "load_config",
    "A2AMessage",
    "A2AResponse",
    "A2AClient",
    "A2AError",
    "Agent",
    "AgentCard",
    "AgentRole",
    "EventBus",
    "Event",
    "AgentRegistry",
    "tool",
    "ToolRegistry",
]


_LAZY_MAP = {
    "Settings": ("aisec.core.config", "Settings"),
    "get_settings": ("aisec.core.config", "get_settings"),
    "load_config": ("aisec.core.config", "load_config"),
    "A2AMessage": ("aisec.core.a2a", "A2AMessage"),
    "A2AResponse": ("aisec.core.a2a", "A2AResponse"),
    "A2AClient": ("aisec.core.a2a", "A2AClient"),
    "A2AError": ("aisec.core.a2a", "A2AError"),
    "Agent": ("aisec.core.agent", "Agent"),
    "AgentCard": ("aisec.core.agent", "AgentCard"),
    "AgentRole": ("aisec.core.agent", "AgentRole"),
    "EventBus": ("aisec.core.event_bus", "EventBus"),
    "Event": ("aisec.core.event_bus", "Event"),
    "AgentRegistry": ("aisec.core.registry", "AgentRegistry"),
    "tool": ("aisec.core.tools", "tool"),
    "ToolRegistry": ("aisec.core.tools", "ToolRegistry"),
}


def __getattr__(name: str):
    if name in _LAZY_MAP:
        mod_name, attr = _LAZY_MAP[name]
        import importlib

        mod = importlib.import_module(mod_name)
        return getattr(mod, attr)
    raise AttributeError(f"module 'aisec.core' has no attribute {name!r}")
