"""Event Bus - append-only JSONL 事件流（V0.4 黑板通信）。

事件格式：
    { "ts": ISO8601, "type": "shadow_agent_detected", "source": "probe-agent", "payload": {...} }

文件命名：<root>/data/events/<YYYY-MM-DD>.jsonl
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import aiofiles

from aisec.core.config import Settings, get_settings

logger = logging.getLogger(__name__)


@dataclass
class Event:
    """事件数据类。"""

    type: str
    source: str
    payload: dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=lambda: datetime.now().isoformat(timespec="milliseconds"))
    trace_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EventBus:
    """JSONL 事件流写入器。

    线程/进程安全：
    - 同一进程内：asyncio.Lock 串行化写入
    - 跨进程：依赖文件系统（追加写 + 单行 JSON 天然原子）
    - 写入失败非致命（审计不应阻断主流程）
    """

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.events_dir: Path = self.settings.abs(self.settings.audit.events_dir)
        self.events_dir.mkdir(parents=True, exist_ok=True)
        # 延迟创建 asyncio.Lock：ProactorEventLoop 下，主线程同步构造时无 event loop 会抛错
        self._lock: asyncio.Lock | None = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def _file_for(self, date: datetime | None = None) -> Path:
        d = date or datetime.now()
        return self.events_dir / f"{d.strftime('%Y-%m-%d')}.jsonl"

    async def append(self, event: Event) -> None:
        """异步追加事件。"""
        line = json.dumps(event.to_dict(), ensure_ascii=False)
        path = self._file_for()
        async with self._get_lock():
            try:
                async with aiofiles.open(path, "a", encoding="utf-8") as f:
                    await f.write(line + "\n")
            except Exception as e:
                logger.error(f"EventBus append failed: {e}")

    def append_nowait_safe(self, event_type: str, payload: dict[str, Any], source: str = "unknown") -> None:
        """同步追加（用于 A2A 审计等非异步上下文，失败不抛）。"""
        try:
            evt = Event(type=event_type, source=source, payload=payload)
            line = json.dumps(evt.to_dict(), ensure_ascii=False)
            path = self._file_for()
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception as e:
            logger.debug(f"append_nowait_safe failed (ignored): {e}")

    async def tail(self, n: int = 100, date: datetime | None = None) -> list[Event]:
        """读取最近 n 条事件。"""
        path = self._file_for(date)
        if not path.exists():
            return []
        events: list[Event] = []
        try:
            async with aiofiles.open(path, "r", encoding="utf-8") as f:
                lines = await f.readlines()
        except Exception as e:
            logger.error(f"EventBus tail failed: {e}")
            return []
        for line in lines[-n:]:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                events.append(Event(**data))
            except Exception as e:
                logger.warning(f"skip malformed event: {e}")
        return events

    def tail_sync(self, n: int = 100, date: datetime | None = None) -> list[Event]:
        """同步 tail（供 CLI 使用）。"""
        path = self._file_for(date)
        if not path.exists():
            return []
        events: list[Event] = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"EventBus tail_sync failed: {e}")
            return []
        for line in lines[-n:]:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                events.append(Event(**data))
            except Exception:
                pass
        return events
