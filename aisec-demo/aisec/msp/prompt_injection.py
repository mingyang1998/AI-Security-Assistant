"""Prompt 注入检测（输入侧）。

零 LLM 成本，纯正则 + 关键词，启发式打分。
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from .attack_corpus import INJECTION_PATTERNS, RISKY_INJECTION_KEYWORDS

logger = logging.getLogger(__name__)


@dataclass
class InjectionFinding:
    pattern: str
    matched_text: str
    category: str  # instruction_override / role_override / prompt_leak / tool_spoof / data_exfil
    weight: int = 10


@dataclass
class PromptInjectionDetector:
    """轻量 Prompt 注入检测器。

    命中一条 INJECTION_PATTERNS 加 10 分，命中 RISKY_INJECTION_KEYWORDS 关键词加 3 分。
    阈值：>=30 -> dangerous / 15-29 -> suspicious / <15 -> safe。
    """

    threshold_dangerous: int = 30
    threshold_suspicious: int = 15
    _compiled: list[tuple[re.Pattern, str]] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self._compiled = [
            (re.compile(pat, re.IGNORECASE | re.MULTILINE), "instruction_override" if "忽略" in pat or "ignore" in pat.lower() or "disregard" in pat.lower() or "forget" in pat.lower() else
             "role_override" if "act as" in pat.lower() or "you are now" in pat.lower() or "扮演" in pat or "你现在是" in pat else
             "prompt_leak" if "reveal" in pat.lower() or "输出" in pat or "print" in pat.lower() or "重复" in pat else
             "tool_spoof" if "<|" in pat or "[INST]" in pat or "SYS" in pat or "system" in pat.lower() else
             "data_exfil" if "exfiltrate" in pat.lower() or "发" in pat or "post" in pat.lower() else
             "jailbreak" if "DAN" in pat or "jailbreak" in pat.lower() or "developer mode" in pat.lower() else
             "other")
            for pat in INJECTION_PATTERNS
        ]

    def detect(self, prompt: str) -> dict[str, Any]:
        """返回 {score, level, findings, red_flags}。"""
        if not prompt:
            return {"score": 0, "level": "safe", "findings": [], "red_flags": []}

        findings: list[InjectionFinding] = []
        red_flags: list[str] = []
        text = prompt
        for rx, category in self._compiled:
            m = rx.search(text)
            if m:
                findings.append(InjectionFinding(
                    pattern=rx.pattern,
                    matched_text=m.group(0)[:80],
                    category=category,
                    weight=10,
                ))
                red_flags.append(f"[{category}] {m.group(0)[:40]}")

        # 关键词加权（轻量）
        text_lower = text.lower()
        kw_hits = [k for k in RISKY_INJECTION_KEYWORDS if k.lower() in text_lower]
        kw_score = min(20, len(kw_hits) * 3)
        if kw_hits and not findings:
            red_flags.extend([f"[kw] {k}" for k in kw_hits[:5]])

        score = min(100, len(findings) * 10 + kw_score)

        if score >= self.threshold_dangerous:
            level = "dangerous"
        elif score >= self.threshold_suspicious:
            level = "suspicious"
        else:
            level = "safe"

        return {
            "score": score,
            "level": level,
            "findings": [
                {
                    "pattern": f.pattern,
                    "matched_text": f.matched_text,
                    "category": f.category,
                }
                for f in findings
            ],
            "red_flags": red_flags,
            "kw_hits": kw_hits,
        }


def scan_prompt(prompt: str) -> dict[str, Any]:
    """便捷函数：扫描单个 prompt。"""
    return PromptInjectionDetector().detect(prompt)
