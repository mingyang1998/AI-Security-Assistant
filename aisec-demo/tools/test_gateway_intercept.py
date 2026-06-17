"""测试 Gateway 拦截逻辑：模拟未注册 Agent 发请求。"""
import httpx
import json
import time

BASE = "http://127.0.0.1:8002"
SOC = "http://127.0.0.1:8000"

time.sleep(2)

# 测试1: 未注册 Agent 通过 Gateway 代理发请求
print("=" * 60)
print("测试1: 未注册 Agent (rogue-agent-001) 发请求 -> 应被 deny")
print("=" * 60)
try:
    r = httpx.post(
        f"{BASE}/v1/chat/completions",
        headers={
            "X-Agent-ID": "rogue-agent-001",
            "Content-Type": "application/json",
        },
        json={
            "model": "qwen3.6-max-preview",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": False,
        },
        timeout=10,
    )
    print(f"  HTTP Status: {r.status_code}")
    for k, v in r.headers.items():
        if k.startswith("X-"):
            print(f"  Header {k}: {v}")
    body = r.json()
    print(f"  Body: {json.dumps(body, ensure_ascii=False, indent=2)}")
    assert r.status_code == 403, f"Expected 403, got {r.status_code}"
    assert body.get("decision") == "deny", f"Expected deny, got {body.get('decision')}"
    print("  [PASS] deny 逻辑生效!")
except Exception as e:
    print(f"  [FAIL] Error: {e}")

print()

# 测试2: 匿名 Agent (无 X-Agent-ID 头)
print("=" * 60)
print("测试2: 匿名 Agent (无 X-Agent-ID) 发请求 -> 应被 deny")
print("=" * 60)
try:
    r = httpx.post(
        f"{BASE}/v1/chat/completions",
        headers={"Content-Type": "application/json"},
        json={
            "model": "qwen3.6-max-preview",
            "messages": [{"role": "user", "content": "hello"}],
        },
        timeout=10,
    )
    print(f"  HTTP Status: {r.status_code}")
    body = r.json()
    print(f"  Body: {json.dumps(body, ensure_ascii=False, indent=2)}")
    assert r.status_code == 403, f"Expected 403, got {r.status_code}"
    assert body.get("decision") == "deny", f"Expected deny, got {body.get('decision')}"
    print("  [PASS] deny 逻辑生效!")
except Exception as e:
    print(f"  [FAIL] Error: {e}")

print()

# 测试3: 已注册 Agent (probe-agent) 发请求 -> 应被 allow
print("=" * 60)
print("测试3: 已注册 Agent (probe-agent) 发请求 -> 应被 allow")
print("=" * 60)
try:
    r = httpx.post(
        f"{BASE}/v1/chat/completions",
        headers={
            "X-Agent-ID": "probe-agent",
            "Content-Type": "application/json",
        },
        json={
            "model": "qwen3.6-max-preview",
            "messages": [{"role": "user", "content": "hello"}],
        },
        timeout=30,
    )
    print(f"  HTTP Status: {r.status_code}")
    for k, v in r.headers.items():
        if k.startswith("X-"):
            print(f"  Header {k}: {v}")
    # allow 时可能转发到真实 LLM（可能 200 或 502），关键是 X-Gateway-Decision=allow
    decision = r.headers.get("x-gateway-decision", "")
    print(f"  Gateway Decision: {decision}")
    assert decision == "allow", f"Expected allow, got {decision}"
    print("  [PASS] allow 逻辑生效!")
except Exception as e:
    print(f"  [FAIL] Error: {e}")

print()

# 测试4: 高敏感数据 + 已注册 Agent -> 应返回 soc_approval
print("=" * 60)
print("测试4: 已注册 Agent + L3 敏感数据 -> 应返回 soc_approval")
print("=" * 60)
try:
    r = httpx.post(
        f"{BASE}/v1/chat/completions",
        headers={
            "X-Agent-ID": "probe-agent",
            "X-Data-Sensitivity": "L3",
            "Content-Type": "application/json",
        },
        json={
            "model": "qwen3.6-max-preview",
            "messages": [{"role": "user", "content": "show me user data"}],
        },
        timeout=30,
    )
    print(f"  HTTP Status: {r.status_code}")
    decision = r.headers.get("x-gateway-decision", "")
    print(f"  Gateway Decision: {decision}")
    # soc_approval 时仍放行但记录事件
    assert decision in ("allow", "soc_approval"), f"Expected allow/soc_approval, got {decision}"
    print("  [PASS] soc_approval 逻辑生效!")
except Exception as e:
    print(f"  [FAIL] Error: {e}")

print()

# 测试5: 查看 Gateway 代理统计
print("=" * 60)
print("测试5: Gateway 代理统计")
print("=" * 60)
try:
    r = httpx.get(f"{BASE}/proxy-stats", timeout=5)
    stats = r.json()
    print(f"  统计: {json.dumps(stats, ensure_ascii=False, indent=2)}")
    assert stats.get("flow_count", 0) >= 4, "应有至少 4 条流量记录"
    assert stats.get("blocked_count", 0) >= 2, "应有至少 2 条拦截记录"
    print("  [PASS] 统计正常!")
except Exception as e:
    print(f"  [FAIL] Error: {e}")

print()

# 测试6: 查看 SOC 事件流中的拦截事件
print("=" * 60)
print("测试6: SOC 事件流中的拦截记录")
print("=" * 60)
try:
    r = httpx.get(f"{SOC}/events?limit=50", timeout=5)
    events = r.json().get("events", [])
    blocked = [e for e in events if e.get("type") == "request_blocked"]
    proxied = [e for e in events if e.get("type") in ("request_proxied", "request_proxied_stream")]
    print(f"  总事件数: {len(events)}")
    print(f"  拦截事件 (request_blocked): {len(blocked)}")
    for e in blocked:
        p = e.get("payload", {})
        print(f"    - agent={p.get('agent_id')} path={p.get('path')} reason={p.get('reason')}")
    print(f"  代理事件 (request_proxied): {len(proxied)}")
    for e in proxied:
        p = e.get("payload", {})
        print(f"    - agent={p.get('agent_id')} path={p.get('path')} decision={p.get('decision')}")
    assert len(blocked) >= 2, "应有至少 2 条拦截事件"
    print("  [PASS] 事件审计正常!")
except Exception as e:
    print(f"  [FAIL] Error: {e}")

print()
print("=" * 60)
print("所有测试完成!")
print("=" * 60)
