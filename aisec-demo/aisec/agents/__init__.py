"""三个常驻 Agent：probe / gateway / soc。

每个 Agent 进程即一个 Agent 实体（V0.4 决策 17）。
soc-agent 为唯一编排者（V0.4 决策 21）。
probe / gateway 不主动调 LLM（V0.4 决策 22）。

注意：这里采用**惰性导入**（lazy import），避免启动任意一个 Agent
时把另外两个 Agent 一并拉起（连带它们各自的依赖）。
"""

_LAZY_MAP = {
    "ProbeAgent": ("aisec.agents.probe", "ProbeAgent"),
    "GatewayAgent": ("aisec.agents.gateway", "GatewayAgent"),
    "SOCAgent": ("aisec.agents.soc", "SOCAgent"),
}


def __getattr__(name: str):
    if name in _LAZY_MAP:
        import importlib

        mod_name, attr = _LAZY_MAP[name]
        mod = importlib.import_module(mod_name)
        return getattr(mod, attr)
    raise AttributeError(f"module 'aisec.agents' has no attribute {name!r}")


__all__ = ["ProbeAgent", "GatewayAgent", "SOCAgent"]
