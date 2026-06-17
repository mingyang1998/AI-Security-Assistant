"""风险评分器。

输入：static_score / semantic_score / behavior_score（各 0-100）
输出：weighted_score（0-100）+ RiskLevel

权重（可在 config 中覆盖）：
    static=0.30, semantic=0.30, behavior=0.40
阈值（默认）：safe<30, suspicious<60, dangerous>=60
"""
from __future__ import annotations

import enum
from dataclasses import dataclass


class RiskLevel(str, enum.Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"


@dataclass
class RiskScore:
    static: float
    semantic: float
    behavior: float
    weighted: float
    level: RiskLevel
    reasons: list[str]

    def to_dict(self) -> dict:
        return {
            "static": round(self.static, 2),
            "semantic": round(self.semantic, 2),
            "behavior": round(self.behavior, 2),
            "weighted": round(self.weighted, 2),
            "level": self.level.value,
            "reasons": self.reasons,
        }


class RiskScorer:
    """加权求和 + 阈值分级。"""

    def __init__(self, w_static: float = 0.30, w_semantic: float = 0.30, w_behavior: float = 0.40,
                 t_safe: int = 30, t_suspicious: int = 60):
        self.w_static = w_static
        self.w_semantic = w_semantic
        self.w_behavior = w_behavior
        self.t_safe = t_safe
        self.t_suspicious = t_suspicious

    def score(self, static: float, semantic: float, behavior: float, reasons: list[str] | None = None) -> RiskScore:
        reasons = reasons or []
        weighted = static * self.w_static + semantic * self.w_semantic + behavior * self.w_behavior
        if weighted >= self.t_suspicious:
            level = RiskLevel.DANGEROUS
        elif weighted >= self.t_safe:
            level = RiskLevel.SUSPICIOUS
        else:
            level = RiskLevel.SAFE
        return RiskScore(static, semantic, behavior, weighted, level, reasons)

    @classmethod
    def score_for_kind(cls, kind: str, static: float, semantic: float, behavior: float,
                       reasons: list[str] | None = None) -> RiskScore:
        """按 kind 选权重：
        - skill: 0.3 / 0.3 / 0.4（行为探测很重要）
        - mcp:   0.6 / 0.2 / 0.2（没代码可跑，行为探测恒 0，把权重给静态）
        """
        if kind == "mcp":
            return cls(w_static=0.6, w_semantic=0.2, w_behavior=0.2).score(
                static, semantic, behavior, reasons)
        return cls().score(static, semantic, behavior, reasons)
