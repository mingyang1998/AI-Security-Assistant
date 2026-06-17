"""Agent Registry - 由 soc-agent 维护（V0.4 决策 19）。

存储：SQLite 单文件（<root>/data/aisec.db）
表结构见 Plan 2.1.2 §(4)。
心跳：每 5s 一次，超过 15s 未心跳 -> offline。

注意：aiosqlite 仅在调用异步方法时才导入；同步 init_schema
使用 sqlite3 标准库。这避免 aiosqlite 缺失时整个模块无法导入。
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from aisec.core.config import Settings, get_settings

logger = logging.getLogger(__name__)


SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id        TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    role            TEXT NOT NULL,
    endpoint_a2a    TEXT,
    endpoint_chat   TEXT,
    status          TEXT NOT NULL DEFAULT 'offline',
    last_heartbeat  INTEGER,
    trust_score     INTEGER DEFAULT 100,
    registered_at   TEXT,
    agent_card      TEXT,
    agent_token     TEXT
);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
"""


class AgentRegistry:
    """Agent 注册中心（soc-agent 专用）。"""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.db_path: Path = self.settings.abs(self.settings.audit.db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def init_schema(self) -> None:
        """同步初始化 schema（启动时调用）。含迁移：为旧表添加 agent_token 列。"""
        import sqlite3

        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(SCHEMA)
            # 迁移：若旧表缺少 agent_token 列，则添加
            try:
                conn.execute("SELECT agent_token FROM agents LIMIT 1")
            except sqlite3.OperationalError:
                conn.execute("ALTER TABLE agents ADD COLUMN agent_token TEXT")
                conn.commit()
                logger.info("[registry] migrated: added agent_token column")
            conn.commit()
        logger.info(f"[registry] schema initialized at {self.db_path}")

    async def upsert(self, agent_card: dict[str, Any], endpoint_a2a: str = "", endpoint_chat: str = "") -> str:
        """注册或更新一个 Agent。返回 agent_token。"""
        import aiosqlite
        import uuid

        now = int(time.time())
        token = agent_card.get("agent_token") or str(uuid.uuid4())
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO agents(agent_id, name, role, endpoint_a2a, endpoint_chat, status, last_heartbeat, trust_score, registered_at, agent_card, agent_token)
                VALUES(?, ?, ?, ?, ?, 'online', ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    name=excluded.name,
                    role=excluded.role,
                    endpoint_a2a=excluded.endpoint_a2a,
                    endpoint_chat=excluded.endpoint_chat,
                    status='online',
                    last_heartbeat=excluded.last_heartbeat,
                    trust_score=excluded.trust_score,
                    agent_card=excluded.agent_card
                """,
                (
                    agent_card["agent_id"],
                    agent_card["name"],
                    agent_card.get("role", "custom"),
                    endpoint_a2a,
                    endpoint_chat,
                    now,
                    agent_card.get("trust_score", 100),
                    agent_card.get("registered_at", ""),
                    json.dumps(agent_card, ensure_ascii=False),
                    token,
                ),
            )
            await db.commit()
            # 读取数据库中实际存储的 token（ON CONFLICT 不更新 agent_token，需回读）
            cur = await db.execute("SELECT agent_token FROM agents WHERE agent_id=?", (agent_card["agent_id"],))
            row = await cur.fetchone()
            actual_token = row[0] if row else token
        logger.info(f"[registry] upsert {agent_card['agent_id']}")
        return actual_token

    async def heartbeat(self, agent_id: str, trust_score: int | None = None, token: str | None = None) -> bool:
        """更新心跳时间戳。若提供 token 则先验证。返回是否成功。"""
        import aiosqlite

        now = int(time.time())
        async with aiosqlite.connect(self.db_path) as db:
            # 若提供了 token，先验证
            if token:
                db.row_factory = aiosqlite.Row
                cur = await db.execute("SELECT agent_token FROM agents WHERE agent_id=?", (agent_id,))
                row = await cur.fetchone()
                if not row or row["agent_token"] != token:
                    logger.warning(f"[registry] heartbeat token mismatch for {agent_id}")
                    return False

            if trust_score is not None:
                await db.execute(
                    "UPDATE agents SET last_heartbeat=?, status='online', trust_score=? WHERE agent_id=?",
                    (now, trust_score, agent_id),
                )
            else:
                await db.execute(
                    "UPDATE agents SET last_heartbeat=?, status='online' WHERE agent_id=?",
                    (now, agent_id),
                )
            await db.commit()
            cur = await db.execute("SELECT changes()", )
            row = await cur.fetchone()
            return (row[0] if row else 0) > 0

    async def get(self, agent_id: str) -> dict[str, Any] | None:
        import aiosqlite

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,))
            row = await cur.fetchone()
            return dict(row) if row else None

    async def verify_token(self, agent_id: str, token: str) -> bool:
        """验证 agent_id + token 是否匹配。"""
        import aiosqlite

        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                "SELECT agent_token FROM agents WHERE agent_id=?", (agent_id,)
            )
            row = await cur.fetchone()
            if not row:
                return False
            return row[0] == token

    async def list(self, status: str | None = None) -> list[dict[str, Any]]:
        import aiosqlite

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if status:
                cur = await db.execute("SELECT * FROM agents WHERE status=?", (status,))
            else:
                cur = await db.execute("SELECT * FROM agents ORDER BY registered_at")
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def sweep_offline(self) -> list[str]:
        """将超时未心跳的 Agent 标记为 offline，返回被改写的 agent_id 列表。"""
        import aiosqlite

        timeout = self.settings.heartbeat.timeout_sec
        cutoff = int(time.time()) - timeout
        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                "SELECT agent_id FROM agents WHERE status='online' AND (last_heartbeat IS NULL OR last_heartbeat<?)",
                (cutoff,),
            )
            rows = await cur.fetchall()
            ids = [r[0] for r in rows]
            for aid in ids:
                await db.execute("UPDATE agents SET status='offline' WHERE agent_id=?", (aid,))
            await db.commit()
        if ids:
            logger.warning(f"[registry] marked offline: {ids}")
        return ids
