"""Sprint 1: SMR (Skills/MCP Review) - Skills/MCP 审查模块。

子模块（延迟导入，避免启动期硬依赖）：
- skill_scanner  : 扫描 Python Skill 文件
- mcp_scanner    : 扫描 MCP server 配置
- static_analyzer: 静态特征匹配（危险 API/命令/外连）
- semantic_analyzer: 用 LLM 评估自然语言意图
- sandbox       : RestrictedPython 沙箱执行观察
- risk_scorer   : 加权汇总 0-100
- hasher        : 内容指纹去重
"""
from __future__ import annotations

__all__ = [
    "RiskScorer",
    "RiskLevel",
    "file_hash",
    "skill_scanner",
    "mcp_scanner",
]


def __getattr__(name: str):
    """延迟导入：避免启动时拉起未使用/有问题的依赖。"""
    import importlib

    if name == "RiskScorer":
        return importlib.import_module("aisec.scanners.risk_scorer").RiskScorer
    if name == "RiskLevel":
        return importlib.import_module("aisec.scanners.risk_scorer").RiskLevel
    if name == "file_hash":
        return importlib.import_module("aisec.scanners.hasher").file_hash
    if name == "skill_scanner":
        return importlib.import_module("aisec.scanners.skill_scanner")
    if name == "mcp_scanner":
        return importlib.import_module("aisec.scanners.mcp_scanner")
    raise AttributeError(f"module 'aisec.scanners' has no attribute {name!r}")
