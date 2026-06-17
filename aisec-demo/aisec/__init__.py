"""AI 安全助手 Demo - 多 Agent 安全运营框架。

Plan 文档：见 ../AI安全助手_Plan.md（v0.4）
模块：
    core      - A2A-Lite 协议、Agent 基类、Event Bus、Registry
    agents    - 三个常驻 Agent（probe / gateway / soc）
    scanners  - SMR（Skills/MCP 审查，Sprint 1 优先）
    llm       - 千问 LLM 客户端
    cli       - python -m aisec start/stop/status
"""

__version__ = "0.1.0"
