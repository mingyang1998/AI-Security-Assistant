"""模型熔断器（MSP 及时响应）。

当 MSP 扫描发现模型安全等级为 dangerous 时，写入熔断标记文件。
gateway-agent 代理请求前检查熔断状态，若已熔断则返回 503。

熔断标记文件：data/model_circuit_breaker.json
格式：
{
    "tripped": true,
    "model": "qwen3.7-max-preview",
    "level": "dangerous",
    "score": 65,
    "reason": "MSP scan detected dangerous vulnerability",
    "tripped_at": "2026-06-15T10:00:00Z",
    "report_path": "data/msp/msp_20260615T100000Z.json"
}
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from aisec.core.config import Settings, get_settings

logger = logging.getLogger(__name__)

BREAKER_FILENAME = "model_circuit_breaker.json"


def _breaker_path(settings: Settings | None = None) -> Path:
    s = settings or get_settings()
    p = s.abs("data") / BREAKER_FILENAME
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def trip_breaker(
    model: str,
    level: str,
    score: int,
    reason: str = "",
    report_path: str = "",
    settings: Settings | None = None,
) -> Path:
    """触发模型熔断。写入熔断标记文件。"""
    path = _breaker_path(settings)
    record: dict[str, Any] = {
        "tripped": True,
        "model": model,
        "level": level,
        "score": score,
        "reason": reason or f"MSP scan detected {level} vulnerability (score={score})",
        "tripped_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "report_path": report_path,
    }
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.warning(f"[circuit_breaker] TRIPPED: model={model} level={level} score={score}")
    return path


def reset_breaker(settings: Settings | None = None) -> bool:
    """重置熔断（恢复模型服务）。"""
    path = _breaker_path(settings)
    if not path.exists():
        return False
    record = json.loads(path.read_text(encoding="utf-8"))
    record["tripped"] = False
    record["reset_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info(f"[circuit_breaker] RESET: model={record.get('model', '?')}")
    return True


def is_tripped(settings: Settings | None = None) -> dict[str, Any]:
    """查询熔断状态。返回熔断记录 dict；未熔断时 tripped=False。"""
    path = _breaker_path(settings)
    if not path.exists():
        return {"tripped": False}
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        return record
    except Exception:
        return {"tripped": False}


def get_breaker_status(settings: Settings | None = None) -> dict[str, Any]:
    """获取熔断器完整状态（供 API 使用）。"""
    return is_tripped(settings)
