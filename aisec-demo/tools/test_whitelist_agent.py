"""测试白名单 Agent 通过 Gateway 并触发 SOC 审批流程。"""
import httpx
import json
import time

GATEWAY = "http://127.0.0.1:8002"
SOC = "http://127.0.0.1:8000"

time.sleep(2)

# ---- 前置：注册一个高信任分的白名单 Agent ----
print("=" * 60)
print("前置: 注册白名单 Agent (whitelisted-agent, trust_score=95)")
print("=" * 60)
try:
    r = httpx.post(
        f"{SOC}/registry/agents",
        json={
            "agent_id": "whitelisted-agent",
            "name": "白名单合规 Agent",
            "role": "compliant_worker",
            "trust_score": 95,
            "agent_card": json.dumps({
                "description": "已通过安全审查的合规 Agent",
                "capabilities": ["data_query", "report_generation"],
                "whitelisted": True,
            }),
        },
        timeout=5,
    )
    print(f"  注册结果: {r.status_code} -> {r.json()}")
except Exception as e:
    print(f"  注册失败(可能已存在): {e}")

# 心跳确认在线
try:
    r = httpx.post(
        f"{SOC}/registry/agents/whitelisted-agent/heartbeat",
        json={"trust_score": 95},
        timeout=5,
    )
    print(f"  心跳结果: {r.status_code}")
except Exception as e:
    print(f"  心跳失败: {e}")

print()

# ---- 测试1: 白名单 Agent 正常请求 -> 应被 allow ----
print("=" * 60)
print("测试1: 白名单 Agent 正常请求 (L0) -> 应被 allow")
print("=" * 60)
try:
    r = httpx.post(
        f"{GATEWAY}/v1/chat/completions",
        headers={
            "X-Agent-ID": "whitelisted-agent",
            "X-Data-Sensitivity": "L0",
            "Content-Type": "application/json",
        },
        json={
            "model": "qwen3.6-max-preview",
            "messages": [{"role": "user", "content": "生成一份安全报告摘要"}],
        },
        timeout=30,
    )
    decision = r.headers.get("x-gateway-decision", "N/A")
    trace_id = r.headers.get("x-trace-id", "N/A")
    print(f"  HTTP Status: {r.status_code}")
    print(f"  Gateway Decision: {decision}")
    print(f"  Trace ID: {trace_id}")
    assert decision == "allow", f"Expected allow, got {decision}"
    print("  [PASS] 白名单 Agent 正常放行!")
except Exception as e:
    print(f"  [FAIL] Error: {e}")

print()

# ---- 测试2: 白名单 Agent + L3 敏感数据 -> 应触发 soc_approval ----
print("=" * 60)
print("测试2: 白名单 Agent + L3 敏感数据 -> 应触发 soc_approval")
print("=" * 60)
try:
    r = httpx.post(
        f"{GATEWAY}/v1/chat/completions",
        headers={
            "X-Agent-ID": "whitelisted-agent",
            "X-Data-Sensitivity": "L3",
            "Content-Type": "application/json",
        },
        json={
            "model": "qwen3.6-max-preview",
            "messages": [{"role": "user", "content": "查询用户个人数据"}],
        },
        timeout=30,
    )
    decision = r.headers.get("x-gateway-decision", "N/A")
    trace_id = r.headers.get("x-trace-id", "N/A")
    print(f"  HTTP Status: {r.status_code}")
    print(f"  Gateway Decision: {decision}")
    print(f"  Trace ID: {trace_id}")
    assert decision == "soc_approval", f"Expected soc_approval, got {decision}"
    print("  [PASS] SOC 审批流程触发!")
except Exception as e:
    print(f"  [FAIL] Error: {e}")

print()

# ---- 测试3: 白名单 Agent + L4 最高敏感 -> 应触发 soc_approval ----
print("=" * 60)
print("测试3: 白名单 Agent + L4 最高敏感数据 -> 应触发 soc_approval")
print("=" * 60)
try:
    r = httpx.post(
        f"{GATEWAY}/v1/chat/completions",
        headers={
            "X-Agent-ID": "whitelisted-agent",
            "X-Data-Sensitivity": "L4",
            "Content-Type": "application/json",
        },
        json={
            "model": "qwen3.6-max-preview",
            "messages": [{"role": "user", "content": "导出财务核心数据"}],
        },
        timeout=30,
    )
    decision = r.headers.get("x-gateway-decision", "N/A")
    trace_id = r.headers.get("x-trace-id", "N/A")
    print(f"  HTTP Status: {r.status_code}")
    print(f"  Gateway Decision: {decision}")
    print(f"  Trace ID: {trace_id}")
    assert decision == "soc_approval", f"Expected soc_approval, got {decision}"
    print("  [PASS] L4 敏感数据 SOC 审批触发!")
except Exception as e:
    print(f"  [FAIL] Error: {e}")

print()

# ---- 测试4: 验证 SOC 事件流中的审批事件 ----
print("=" * 60)
print("测试4: SOC 事件流中的审批记录")
print("=" * 60)
try:
    r = httpx.get(f"{SOC}/events?limit=100", timeout=5)
    events = r.json().get("events", [])

    approval_events = [e for e in events if e.get("type") == "request_pending_approval"]
    blocked_events = [e for e in events if e.get("type") == "request_blocked"]
    proxied_events = [e for e in events if e.get("type") in ("request_proxied", "request_proxied_stream")]

    print(f"  总事件数: {len(events)}")
    print(f"  SOC 审批事件 (request_pending_approval): {len(approval_events)}")
    for e in approval_events:
        p = e.get("payload", {})
        print(f"    - agent={p.get('agent_id')} path={p.get('path')} "
              f"sensitivity={p.get('data_sensitivity')} decision={p.get('decision')} "
              f"trace_id={p.get('trace_id')}")

    print(f"  拦截事件 (request_blocked): {len(blocked_events)}")
    print(f"  代理放行事件 (request_proxied): {len(proxied_events)}")

    assert len(approval_events) >= 2, "应有至少 2 条 SOC 审批事件"
    print("  [PASS] SOC 审批事件记录完整!")
except Exception as e:
    print(f"  [FAIL] Error: {e}")

print()

# ---- 测试5: 验证白名单 Agent 信息在 Registry 中 ----
print("=" * 60)
print("测试5: 验证白名单 Agent 在 Registry 中的状态")
print("=" * 60)
try:
    r = httpx.get(f"{SOC}/registry/agents/whitelisted-agent", timeout=5)
    agent = r.json()
    print(f"  Agent ID: {agent.get('agent_id')}")
    print(f"  名称: {agent.get('name')}")
    print(f"  角色: {agent.get('role')}")
    print(f"  信任分: {agent.get('trust_score')}")
    print(f"  状态: {agent.get('status')}")
    card = agent.get("agent_card", {})
    if isinstance(card, str):
        card = json.loads(card)
    print(f"  Agent Card: {json.dumps(card, ensure_ascii=False)}")
    assert agent.get("status") == "online", "Agent 应在线"
    assert agent.get("trust_score") >= 90, "信任分应 >= 90"
    print("  [PASS] 白名单 Agent 状态正常!")
except Exception as e:
    print(f"  [FAIL] Error: {e}")

print()

# ---- 测试6: 对比 - 低信任分 Agent 应被 rate_limit ----
print("=" * 60)
print("测试6: 对比 - 注册低信任分 Agent (trust_score=20) -> 应被 rate_limit")
print("=" * 60)
try:
    # 注册低信任分 Agent
    httpx.post(
        f"{SOC}/registry/agents",
        json={
            "agent_id": "low-trust-agent",
            "name": "低信任 Agent",
            "role": "unverified",
            "trust_score": 20,
        },
        timeout=5,
    )
    httpx.post(
        f"{SOC}/registry/agents/low-trust-agent/heartbeat",
        json={"trust_score": 20},
        timeout=5,
    )

    r = httpx.post(
        f"{GATEWAY}/v1/chat/completions",
        headers={
            "X-Agent-ID": "low-trust-agent",
            "X-Data-Sensitivity": "L0",
            "Content-Type": "application/json",
        },
        json={
            "model": "qwen3.6-max-preview",
            "messages": [{"role": "user", "content": "hello"}],
        },
        timeout=30,
    )
    decision = r.headers.get("x-gateway-decision", "N/A")
    print(f"  HTTP Status: {r.status_code}")
    print(f"  Gateway Decision: {decision}")
    assert decision == "rate_limit", f"Expected rate_limit, got {decision}"
    print("  [PASS] 低信任分 Agent 被限流!")
except Exception as e:
    print(f"  [FAIL] Error: {e}")

print()

# ---- 测试7: 查看 Gateway 统计 ----
print("=" * 60)
print("测试7: Gateway 代理统计汇总")
print("=" * 60)
try:
    r = httpx.get(f"{GATEWAY}/proxy-stats", timeout=5)
    stats = r.json()
    print(f"  {json.dumps(stats, ensure_ascii=False, indent=2)}")
    print("  [PASS] 统计正常!")
except Exception as e:
    print(f"  [FAIL] Error: {e}")

print()
print("=" * 60)
print("所有测试完成!")
print("=" * 60)
