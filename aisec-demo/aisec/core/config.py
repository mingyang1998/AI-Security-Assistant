"""配置加载。

约定：
- 默认配置文件：<project_root>/config/default.yaml
- 环境变量 DASHSCOPE_API_KEY 覆盖 llm.api_key
- Settings 为 pydantic 模型，类型安全
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


# ---------- 子模型 ----------


class LLMConfig(BaseModel):
    provider: str = "qwen"
    base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    api_key: str = "sk-770a9633accb4adea2880523e53d89ba"
    model: str = "qwen3.6-max-preview"
    timeout: int = 30
    max_retries: int = 2


class AgentPortConfig(BaseModel):
    port: int
    host: str = "127.0.0.1"


class AgentsConfig(BaseModel):
    soc_agent: AgentPortConfig
    probe_agent: AgentPortConfig
    gateway_agent: AgentPortConfig


class HeartbeatConfig(BaseModel):
    interval_sec: int = 5
    timeout_sec: int = 15


class A2AConfig(BaseModel):
    default_deadline_ms: int = 100
    max_retries: int = 1
    log_to_events: bool = True


class SandboxConfig(BaseModel):
    cpu_sec: int = 5
    mem_mb: int = 256
    temp_dir: str = "data/sandbox"


class SMRConfig(BaseModel):
    static_weight: float = 0.30
    semantic_weight: float = 0.30
    behavior_weight: float = 0.40
    thresholds: dict[str, int] = Field(default_factory=lambda: {"safe": 30, "suspicious": 60})


class AlertsConfig(BaseModel):
    dir: str = "alerts"
    format: str = "markdown"


class AuditConfig(BaseModel):
    events_dir: str = "data/events"
    db_path: str = "data/aisec.db"


class WhitelistConfig(BaseModel):
    builtin_skills: list[str] = Field(default_factory=list)
    builtin_mcps: list[str] = Field(default_factory=list)


class ProjectConfig(BaseModel):
    name: str = "aisec-demo"
    version: str = "0.1.0"
    root: str = "."


# ---------- 主配置 ----------


class Settings(BaseModel):
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    agents: AgentsConfig
    heartbeat: HeartbeatConfig = Field(default_factory=HeartbeatConfig)
    a2a: A2AConfig = Field(default_factory=A2AConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    smr: SMRConfig = Field(default_factory=SMRConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    whitelist: WhitelistConfig = Field(default_factory=WhitelistConfig)

    # ---------- 路径解析 ----------

    @property
    def root_path(self) -> Path:
        """项目根目录绝对路径。"""
        p = Path(self.project.root).resolve()
        return p

    def abs(self, rel: str) -> Path:
        """将相对项目根的路径解析为绝对路径。"""
        return (self.root_path / rel).resolve()

    # ---------- LLM Key ----------

    @property
    def effective_llm_api_key(self) -> str:
        """优先环境变量，其次配置。"""
        env = os.environ.get("DASHSCOPE_API_KEY", "")
        return env or self.llm.api_key

    @property
    def data_dir(self) -> str:
        """数据根目录（绝对路径字符串）。"""
        return str(self.abs("data"))


# ---------- 加载器 ----------


_cached: Settings | None = None


def load_config(path: str | Path | None = None) -> Settings:
    """从 YAML 文件加载配置。

    参数：
        path: 配置文件路径；None 时使用 config/default.yaml（相对调用方 cwd 或回溯查找）。
    """
    global _cached
    if path is None:
        path = _find_default_config()
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"配置文件不存在: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw: dict[str, Any] = yaml.safe_load(f) or {}

    settings = Settings(**raw)
    _cached = settings
    return settings


def get_settings() -> Settings:
    """获取已缓存的 settings；未加载则尝试默认位置加载。"""
    global _cached
    if _cached is None:
        _cached = load_config()
    return _cached


def reset_settings_cache() -> None:
    """测试或热重载时清空缓存。"""
    global _cached
    _cached = None


def _find_default_config() -> Path:
    """查找 config/default.yaml。

    查找顺序：
    1. CWD 及其所有父目录
    2. aisec 包所在目录的同级 config/ 目录
    3. 兜底返回 CWD 下的 config/default.yaml（让 load_config 报错）
    """
    here = Path.cwd()
    for cand in [here, *here.parents]:
        p = cand / "config" / "default.yaml"
        if p.exists():
            return p
    # 兜底 2：aisec 包同级目录的 config/（不依赖 CWD）
    pkg_root = Path(__file__).resolve().parent.parent.parent  # .../aisec-demo
    fallback = pkg_root / "config" / "default.yaml"
    if fallback.exists():
        return fallback
    return here / "config" / "default.yaml"
