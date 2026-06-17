import httpx
import json

r = httpx.post(
    "http://127.0.0.1:8000/registry/agents",
    json={
        "agent_id": "test-agent",
        "name": "Test",
        "version": "0.1.0",
        "role": "custom",
        "trust_score": 100,
        "capabilities": [],
        "endpoints": {},
        "registered_at": "2026-06-11T17:00:00",
    },
    timeout=5,
)
print("status:", r.status_code)
print("body:", r.text[:500])
