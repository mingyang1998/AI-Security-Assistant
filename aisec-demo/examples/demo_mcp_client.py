"""示例：模拟 MCP 客户端通过 Gateway 调用 MCP 工具。

演示场景（Sprint 2 补完）：
- 启动三个 Agent 后，运行本脚本
- 脚本以 JSON-RPC 2.0 格式向 gateway 的 /mcp 路径发 tools/call
- gateway 解析 JSON-RPC，识别 method=tools/call / tool_name
  - 若 tool_name 在 MCP_SAFE_TOOLS 中 -> allow
  - 若 tool_name 不在白名单（如 "drop_table"） -> soc_approval（demo 中放行但记录）

运行：
    python -m aisec start
    python examples/demo_mcp_client.py
"""
from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx  # noqa: E402

GATEWAY_MCP_URL = "http://127.0.0.1:8002/mcp"
AGENT_ID = "probe-agent"  # 已注册


def _jsonrpc(method: str, params: dict | None = None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4())[:8],
        "method": method,
        "params": params or {},
    }


def call_mcp(label: str, method: str, params: dict, tool_name: str = "") -> dict:
    body = _jsonrpc(method, params)
    headers = {
        "Content-Type": "application/json",
        "X-Agent-ID": AGENT_ID,
    }
    print(f"\n[demo_mcp_client] === {label} ===")
    print(f"[demo_mcp_client]   method = {method}, tool = {tool_name or '-'}")
    print(f"[demo_mcp_client]   body   = {json.dumps(body, ensure_ascii=False)[:200]}")
    t0 = time.time()
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(GATEWAY_MCP_URL, headers=headers, json=body)
    except httpx.ConnectError as e:
        return {"ok": False, "error": f"gateway unreachable: {e}"}
    elapsed = time.time() - t0
    print(f"[demo_mcp_client] <- HTTP {resp.status_code} ({elapsed:.2f}s)")
    print(f"[demo_mcp_client]   X-Gateway-Decision = {resp.headers.get('X-Gateway-Decision', '?')}")
    try:
        data = resp.json()
    except json.JSONDecodeError:
        data = {"raw": resp.text[:200]}
    return {
        "ok": resp.status_code == 200,
        "status": resp.status_code,
        "decision": resp.headers.get("X-Gateway-Decision"),
        "response": data,
    }


def main() -> int:
    print("=" * 70)
    print("Demo 3: MCP 客户端通过 Gateway 调工具（JSON-RPC 2.0）")
    print("=" * 70)
    results = []

    # 3a) 列出工具（安全方法，不在危险方法列表中 -> allow）
    results.append(("tools/list", call_mcp(
        "MCP 3a: tools/list", "tools/list", {}
    )))

    # 3b) 调用白名单内的工具（read_file 在 MCP_SAFE_TOOLS -> allow）
    results.append(("read_file", call_mcp(
        "MCP 3b: tools/call read_file (白名单内)",
        "tools/call", {"name": "read_file", "arguments": {"path": "/etc/hostname"}},
        tool_name="read_file",
    )))

    # 3c) 调用非白名单的危险工具（drop_table -> soc_approval 记录但放行）
    results.append(("drop_table", call_mcp(
        "MCP 3c: tools/call drop_table (非白名单 -> 需 SOC 审批)",
        "tools/call", {"name": "drop_table", "arguments": {"table": "users"}},
        tool_name="drop_table",
    )))

    print()
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    for name, r in results:
        print(f"  {name:20s} -> HTTP {r.get('status', '?')}  decision={r.get('decision', '?')}")

    # 预期：
    # - tools/list   -> 200 allow
    # - read_file    -> 200 allow
    # - drop_table   -> 200 soc_approval （demo 中放行但记录）
    return 0


if __name__ == "__main__":
    sys.exit(main())
