"""动态零信任评分引擎。

根据 Agent 行为事件动态调整 trust_score：
- 触发 shadow_agent_detected → 该 agent trust_score -20
- 触发 request_blocked → 该 agent trust_score -15
- 触发 anomalous_egress_detected → 该 agent trust_score -25
- 触发 model_circuit_breaker_tripped → 该 agent trust_score -30
- 正常运行满一个评估周期无告警 → trust_score +5（上限 100）

评分范围：0-100
- 80-100：可信（allow）
- 30-79：可疑（rate_limit / monitor）
- 0-29：不可信（deny）

调用方式：soc-agent 的 _sweep_loop 每 30s 调用一次 evaluate_all()
"""
from __future__ import annotations

import logging
from typing import Any

from aisec.core.config import Settings, get_settings
from aisec.core.registry import AgentRegistry

logger = logging.getLogger(__name__)

# 事件类型 → 信任分扣减映射
PENALTY_MAP: dict[str, int] = {
    "shadow_agent_detected": -20,
    "request_blocked": -15,
    "anomalous_egress_detected": -25,
    "model_circuit_breaker_tripped": -30,
}

# 每个评估周期无告警的奖励
GOOD_BEHAVIOR_BONUS = 5

# trust_score 边界
TRUST_MIN = 0
TRUST_MAX = 100


class TrustEngine:
    """动态零信任评分引擎。"""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()

    async def evaluate_all(self, recent_events: list[dict[str, Any]]) -> dict[str, int]:
        """根据最近事件批量更新所有 Agent 的 trust_score。

        参数：
            recent_events: 最近一个评估周期内的事件列表

        返回：
            {agent_id: new_trust_score} 变更映射（仅包含分数有变化的）
        """
        registry = AgentRegistry(self.settings)

        # 1. 统计每个 agent 的扣分
        penalties: dict[str, int] = {}
        for ev in recent_events:
            ev_type = ev.get("type", "")
            penalty = PENALTY_MAP.get(ev_type, 0)
            if penalty == 0:
                continue
            # 从 payload 中提取 agent_id
            payload = ev.get("payload", {})
            agent_id = payload.get("agent_id", "")
            if not agent_id or agent_id in ("anonymous", "unknown"):
                continue
            penalties[agent_id] = penalties.get(agent_id, 0) + penalty

        # 2. 遍历所有已注册 Agent，更新 trust_score
        changes: dict[str, int] = {}
        try:
            agents = await registry.list()
        except Exception as e:
            logger.warning(f"trust engine: list agents failed: {e}")
            return changes

        for agent in agents:
            aid = agent.get("agent_id", "")
            old_score = agent.get("trust_score", 100)
            delta = penalties.get(aid, 0)

            # 无扣分 → 奖励（但不超过上限）
            if delta == 0 and old_score < TRUST_MAX:
                delta = GOOD_BEHAVIOR_BONUS

            new_score = max(TRUST_MIN, min(TRUST_MAX, old_score + delta))

            if new_score != old_score:
                try:
                    await registry.heartbeat(aid, trust_score=new_score)
                    changes[aid] = new_score
                    direction = "+" if new_score > old_score else ""
                    logger.info(
                        f"[trust] {aid}: {old_score} -> {new_score} ({direction}{delta})"
                    )
                except Exception as e:
                    logger.warning(f"trust engine: update {aid} failed: {e}")

        return changes

    async def get_trust_summary(self) -> list[dict[str, Any]]:
        """获取所有 Agent 的信任分摘要。"""
        registry = AgentRegistry(self.settings)
        try:
            agents = await registry.list()
        except Exception:
            return []
        summary = []
        for a in agents:
            score = a.get("trust_score", 100)
            if score >= 80:
                level = "trusted"
            elif score >= 30:
                level = "suspicious"
            else:
                level = "untrusted"
            summary.append({
                "agent_id": a.get("agent_id", ""),
                "name": a.get("name", ""),
                "trust_score": score,
                "trust_level": level,
                "status": a.get("status", "unknown"),
            })
        return summary
