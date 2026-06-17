"""AISOC 单页控制台 (Plan V0.4 §7.2 Sprint 4 关键交付)。

极简单页：Agent 列表 / 告警列表 / 事件检索 / MSP 报告。
技术栈：FastAPI + Jinja2 + 原生 CSS（不引入 React/Vue/Tailwind/Streamlit）。
启动：python -m aisec web
"""
from __future__ import annotations

from .app import build_app, main
from .dashboard import DASHBOARD_HTML  # 兼容 soc-agent 老路由

__all__ = ["build_app", "main", "DASHBOARD_HTML"]
