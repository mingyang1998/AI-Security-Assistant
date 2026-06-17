"""示例：模拟 LangChain Agent 通过 Gateway 调用 LLM。

演示场景（Sprint 2）：
- 启动三个 Agent（soc/probe/gateway）
- 运行本脚本，模拟一个"用 LangChain 实现的 Agent"通过 gateway 调用千问
- gateway 验证身份（X-Agent-ID: probe-agent）后放行/代理
- soc-agent 记录 request_proxied 事件 + 响应

运行：
    python -m aisec start   # 先启动三个 Agent
    python examples/demo_langchain_agent.py

期望：
- HTTP 200，返回 LLM 真实响应（或 mock 错误信息）
- 事件流中出现 type=request_proxied, agent_id=probe-agent
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# 确保可作为脚本直接跑（python examples/demo_langchain_agent.py）
sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx  # noqa: E402

GATEWAY_URL = "http://127.0.0.1:8002/v1/chat/completions"
AGENT_ID = "probe-agent"  # 已注册 Agent，会被放行
MODEL = "qwen3.6-max-preview"


def simulate_langchain_call(query: str) -> dict:
    """模拟 LangChain Agent 内部的 LLM 调用（OpenAI 兼容协议）。"""
    # LangChain 内部其实就是这样：构造 ChatCompletion 请求 -> 发到 base_url
    # base_url 指向 gateway -> gateway 校验身份 + 决策 + 转发到真实 LLM
    body = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": query},
        ],
        "max_tokens": 200,
    }
    headers = {
        "Content-Type": "application/json",
        "X-Agent-ID": AGENT_ID,           # gateway 据此查身份
        "X-Data-Sensitivity": "L1",        # 内部数据，较低敏感
    }
    print(f"[demo_langchain_agent] POST {GATEWAY_URL}")
    print(f"[demo_langchain_agent]   X-Agent-ID = {AGENT_ID}")
    print(f"[demo_langchain_agent]   query = {query!r}")
    t0 = time.time()
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(GATEWAY_URL, headers=headers, json=body)
    except httpx.ConnectError as e:
        return {"ok": False, "error": f"gateway unreachable: {e}"}
    elapsed = time.time() - t0
    print(f"[demo_langchain_agent] <- HTTP {resp.status_code} ({elapsed:.2f}s)")
    print(f"[demo_langchain_agent]   X-Gateway-Decision = {resp.headers.get('X-Gateway-Decision', '?')}")
    print(f"[demo_langchain_agent]   X-Trace-ID = {resp.headers.get('X-Trace-ID', '?')}")
    try:
        data = resp.json()
    except json.JSONDecodeError:
        data = {"raw": resp.text[:300]}
    return {
        "ok": resp.status_code == 200,
        "status": resp.status_code,
        "elapsed_sec": round(elapsed, 3),
        "decision": resp.headers.get("X-Gateway-Decision"),
        "trace_id": resp.headers.get("X-Trace-ID"),
        "response": data,
    }


def main() -> int:
    q = sys.argv[1] if len(sys.argv) > 1 else "用一句话介绍千问模型"
    print("=" * 70)
    print("Demo 1: LangChain Agent 调 LLM（应被 gateway 放行）")
    print("=" * 70)
    result = simulate_langchain_call(q)
    print()
    print("Result:")
    print(json.dumps(result, ensure_ascii=False, indent=2)[:800])
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
