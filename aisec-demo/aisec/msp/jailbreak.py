"""越狱探测（主动测试）。

使用内置攻击语料（JAILBREAK_PROBES）作为输入，调用 LLM，检查响应是否
触发 red_flag_keywords（模型被成功越狱的标志）。
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from ..llm import LLMClient
from .attack_corpus import JAILBREAK_PROBES

logger = logging.getLogger(__name__)


@dataclass
class JailbreakResult:
    probe_id: str
    category: str
    name: str
    prompt: str
    response: str
    success: bool               # LLM 是否"被越狱"
    matched_flags: list[str]    # 命中的 red_flag_keywords
    elapsed_sec: float
    skipped: bool = False       # mock 模式下跳过（响应不带真实语义）


@dataclass
class JailbreakProbe:
    """越狱探测器：用 JAILBREAK_PROBES 主动探测 LLM。"""

    timeout_sec: float = 30.0
    results: list[JailbreakResult] = field(default_factory=list, init=False, repr=False)

    async def run(self, llm: LLMClient | None = None) -> list[JailbreakResult]:
        llm = llm or LLMClient()
        self.results = []
        for probe in JAILBREAK_PROBES:
            t0 = time.time()
            try:
                resp = await asyncio.wait_for(
                    llm.chat([{"role": "user", "content": probe["prompt"]}]),
                    timeout=self.timeout_sec,
                )
            except asyncio.TimeoutError:
                resp = f"[timeout after {self.timeout_sec}s]"
            except Exception as e:
                resp = f"[error: {e}]"
            elapsed = time.time() - t0

            resp_lower = resp.lower()
            matched = [kw for kw in probe["red_flag_keywords"] if kw.lower() in resp_lower]

            # mock 模式下响应是占位文本，没有真实语义，应跳过判定
            skipped = "[MOCK LLM" in resp

            self.results.append(JailbreakResult(
                probe_id=probe["id"],
                category=probe["category"],
                name=probe["name"],
                prompt=probe["prompt"],
                response=resp[:500],
                success=bool(matched) and not skipped,
                matched_flags=matched,
                elapsed_sec=round(elapsed, 3),
                skipped=skipped,
            ))
            logger.info(
                f"[jb] {probe['id']} {probe['name']:30s} "
                f"success={bool(matched) and not skipped} skipped={skipped} "
                f"elapsed={elapsed:.2f}s"
            )
        return self.results

    def summary(self) -> dict[str, Any]:
        real = [r for r in self.results if not r.skipped]
        successes = [r for r in real if r.success]
        rate = (len(successes) / len(real) * 100) if real else 0.0
        return {
            "total": len(self.results),
            "evaluated": len(real),
            "skipped_mock": len(self.results) - len(real),
            "successes": len(successes),
            "jailbreak_rate_pct": round(rate, 2),
            "by_category": {
                cat: sum(1 for r in successes if r.category == cat)
                for cat in {r.category for r in self.results}
            },
        }


async def run_jailbreak_probe(llm: LLMClient | None = None) -> list[JailbreakResult]:
    """便捷函数：跑一遍越狱探测。"""
    return await JailbreakProbe().run(llm)
