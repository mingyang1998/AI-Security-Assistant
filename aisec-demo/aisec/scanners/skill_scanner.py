"""Skill 扫描器：静态 + 语义 + 行为 = 综合评分。"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from aisec.core.config import get_settings
from aisec.scanners.hasher import file_hash
from aisec.scanners.risk_scorer import RiskScorer
from aisec.scanners.sandbox import run_in_sandbox
from aisec.scanners.semantic_analyzer import analyze_semantic
from aisec.scanners.static_analyzer import analyze_file

logger = logging.getLogger(__name__)


def _archive_and_alert(scan_result: dict[str, Any], settings=None) -> None:
    """归档到黑/白名单 + 生成告警 Markdown（同步，在 to_thread 中调用）。"""
    try:
        s = settings or get_settings()
        from aisec.scanners.list_archive import ListArchive
        from aisec.scanners.alert_generator import AlertGenerator

        data_dir = Path(s.data_dir)
        archive = ListArchive(data_dir)
        alert_gen = AlertGenerator(data_dir)

        # 自动归档
        archive.auto_archive(scan_result)

        # 生成告警 Markdown
        alert_gen.generate_scan_alert(scan_result)
    except Exception as e:
        logger.warning(f"archive/alert failed: {e}")


def _build_scorer(settings=None):
    s = settings or get_settings()
    smr = s.smr
    return RiskScorer(
        w_static=smr.static_weight,
        w_semantic=smr.semantic_weight,
        w_behavior=smr.behavior_weight,
        t_safe=smr.thresholds.get("safe", 30),
        t_suspicious=smr.thresholds.get("suspicious", 60),
    )


async def scan_skill_async(path: str | Path, settings=None) -> dict[str, Any]:
    """异步扫描单个 Skill 文件（推荐入口，可在异步/同步上下文中安全调用）。

    整体超时保护：最长 120s 必返回（避免 LLM/沙箱卡死导致用户 Ctrl+C）。
    """
    p = Path(path)
    s = settings or get_settings()
    scorer = _build_scorer(s)

    async def _do_scan() -> dict[str, Any]:
        # 1. 静态（纯同步，用 to_thread 避免阻塞事件循环）
        static = await asyncio.to_thread(analyze_file, p)
        # 2. 行为（纯同步沙箱）
        behavior = await asyncio.to_thread(run_in_sandbox, p, s.sandbox.cpu_sec)
        # 3. 语义（本身就是异步；LLM 内部已自带 65s 硬超时）
        semantic: dict[str, Any] = await analyze_semantic(p)

        rs = scorer.score_for_kind(
            kind="skill",
            static=static.get("score", 0),
            semantic=semantic.get("score", 0),
            behavior=behavior.get("score", 0),
            reasons=(
                static.get("reasons", [])
                + semantic.get("reason", "").splitlines()
                + behavior.get("reasons", [])
            ),
        )

        return {
            "kind": "skill",
            "path": str(p),
            "sha256": file_hash(p),
            "size_bytes": p.stat().st_size,
            "static": static,
            "semantic": semantic,
            "behavior": behavior,
            "risk": rs.to_dict(),
        }

    # 整体超时：120s（沙箱 5s + LLM 65s + 静态 + 余量）
    try:
        result = await asyncio.wait_for(_do_scan(), timeout=120.0)
    except asyncio.TimeoutError:
        logger.warning(f"scan_skill_async overall timeout (120s) for {p}")
        return {
            "kind": "skill",
            "path": str(p),
            "error": "scan timeout (120s)",
            "risk": {"level": "unknown", "score": 0, "reason": "scan timeout"},
        }

    # 自动归档到黑/白名单 + 生成告警 Markdown
    await asyncio.to_thread(_archive_and_alert, result, s)

    return result


def scan_skill(path: str | Path, settings=None) -> dict[str, Any]:
    """同步入口：扫描单个 Skill 文件。

    自动检测当前是否在 asyncio 事件循环中：
    - 不在事件循环中 -> 直接 asyncio.run()
    - 在事件循环中 -> 用 nest_asyncio 或新线程运行
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is None:
        # 没有运行中的事件循环，安全使用 asyncio.run()
        return asyncio.run(scan_skill_async(path, settings))

    # 已在事件循环中，用新线程避免冲突
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(asyncio.run, scan_skill_async(path, settings))
        return future.result()
