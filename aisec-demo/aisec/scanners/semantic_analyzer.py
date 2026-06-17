"""语义分析器：调用 LLM 评估 Skill 的自然语言描述与意图。

输入：Skill 的文档字符串（docstring / README / 元信息）
输出：0-100 风险分 + 风险描述

无 API Key 时降级为基于关键词的轻量规则。
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from aisec.llm import LLMClient
from aisec.core.config import get_settings

logger = logging.getLogger(__name__)


# 描述文本的危险关键词（无 LLM 时使用）
SEMANTIC_BAD_KEYWORDS = [
    "bypass", "绕过", "规避", "越权", "privilege", "escalation",
    "stealth", "隐蔽", "silent", "无痕",
    "exfiltrate", "extract data", "upload", "外传", "回传",
    "phishing", "钓鱼", "social engineering",
    "dropper", "payload", "shellcode",
    "credential", "凭据", "密码", "token", "key", "secret",
    "DLP bypass", "audit disable", "审计关闭", "日志清除", "log clean",
]

SEMANTIC_SYSTEM = """你是 AI 安全助手 Demo 的语义分析器。
请评估以下 Skill / MCP 工具的"自然语言描述"，输出 0-100 的风险分（越高越可疑）和 1-3 句解释。

评估维度：
1. 是否声称"绕过"、"规避"、"越权"、"隐蔽"、"无痕"等
2. 是否涉及"外传"、"回传"、"上传用户数据"到外部
3. 是否承诺"凭据/Token/密钥"的访问
4. 是否在描述中"关闭/清理"审计与日志
5. 描述与 Skill 实际能力的差异

只输出 JSON：
{"score": <0-100>, "reason": "..."}
"""


def _extract_docstring(path: Path) -> str:
    """从 .py 文件提取模块顶部 docstring；否则读全文前 2KB。"""
    try:
        src = path.read_text(encoding="utf-8")
    except Exception:
        return ""
    # 尝试提取第一个 docstring
    import ast
    try:
        tree = ast.parse(src)
        return ast.get_docstring(tree) or src[:2000]
    except SyntaxError:
        return src[:2000]


async def analyze_semantic(path: str | Path) -> dict[str, Any]:
    """语义分析（异步；可被同步上下文用 .result() 取值）。"""
    p = Path(path)
    if not p.exists():
        return {"score": 0, "reason": f"file not found: {path}"}
    text = _extract_docstring(p)
    if not text.strip():
        return {"score": 0, "reason": "no docstring/content"}

    llm = LLMClient(get_settings())
    if llm.mock_mode:
        # 降级：关键词匹配
        text_low = text.lower()
        hits = [k for k in SEMANTIC_BAD_KEYWORDS if k.lower() in text_low]
        if not hits:
            return {"score": 5, "reason": "mock-mode: no suspicious keyword"}
        score = min(80, 30 + 15 * len(hits))
        return {"score": score, "reason": f"mock-mode: 命中关键词 {hits}"}

    # LLM 评估
    try:
        content = await llm.chat(
            messages=[
                {"role": "system", "content": SEMANTIC_SYSTEM},
                {"role": "user", "content": f"Skill 路径: {p}\n描述/源码片段:\n```\n{text[:1500]}\n```"},
            ],
            temperature=0.1,
        )
        import json
        # 容错提取 JSON
        m = re.search(r"\{.*\}", content, re.S)
        if m:
            data = json.loads(m.group(0))
            return {
                "score": int(data.get("score", 0)),
                "reason": data.get("reason", ""),
                "raw": content,
            }
        return {"score": 0, "reason": f"LLM 未返回 JSON: {content[:100]}", "raw": content}
    except Exception as e:
        logger.warning(f"semantic analyze failed: {e}")
        return {"score": 0, "reason": f"LLM error: {e}"}
