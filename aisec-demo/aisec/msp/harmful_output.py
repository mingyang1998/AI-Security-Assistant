"""有害输出检测（输出侧）。

零 LLM 成本（demo 阶段），纯正则 + 关键词匹配。
生产可替换为 LLM-as-judge（用千问做 moderator）。
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from .attack_corpus import HARMFUL_OUTPUT_PATTERNS

logger = logging.getLogger(__name__)


@dataclass
class HarmFinding:
    pattern: str
    matched_text: str
    category: str  # malicious_code / pii_leak / jailbreak_success / dangerous_knowledge
    weight: int = 15


@dataclass
class HarmClassifier:
    """轻量有害输出分类器。"""

    threshold_dangerous: int = 30
    threshold_suspicious: int = 15
    _compiled: list[tuple[re.Pattern, str]] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self._compiled = [
            (re.compile(pat, re.IGNORECASE | re.MULTILINE),
             "malicious_code" if "os.system" in pat or "subprocess" in pat or "eval" in pat or "rm -rf" in pat or "fork" in pat.lower() else
             "pii_leak" if "AKIA" in pat or "sk-" in pat or "PRIVATE KEY" in pat or "ghp_" in pat else
             "jailbreak_success" if "DAN" in pat or "jailbreak" in pat.lower() or "I have been freed" in pat else
             "dangerous_knowledge" if "毒品" in pat or "drug" in pat.lower() or "explosive" in pat.lower() or "malware" in pat.lower() else
             "other")
            for pat in HARMFUL_OUTPUT_PATTERNS
        ]

    def classify(self, text: str) -> dict[str, Any]:
        """返回 {score, level, findings, categories}。"""
        if not text:
            return {"score": 0, "level": "safe", "findings": [], "categories": []}

        findings: list[HarmFinding] = []
        for rx, category in self._compiled:
            m = rx.search(text)
            if m:
                findings.append(HarmFinding(
                    pattern=rx.pattern,
                    matched_text=m.group(0)[:80],
                    category=category,
                ))

        score = min(100, len(findings) * 15)
        categories = sorted({f.category for f in findings})

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
            "categories": categories,
        }


def classify_output(text: str) -> dict[str, Any]:
    """便捷函数：分类单个 LLM 输出。"""
    return HarmClassifier().classify(text)
