"""gateway-agent（流量拦截 Agent）。

职责（V0.4 Plan §2.1.2）：
- 作为 HTTP 反向代理拦截 Agent 对 LLM/外部 API 的调用
- 验证 Agent 身份（白名单 + 信任分）
- 决定 allow / deny / 限流
- 留痕（input / output / trace_id）

实现方式：FastAPI 反向代理 + 策略决策。
客户端将 LLM API 请求发到 gateway（如 http://127.0.0.1:8002/v1/chat/completions），
gateway 验证身份后转发到真实的 LLM API，或拒绝请求。
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any

import httpx
from aisec.core.agent import Agent, AgentRole
from aisec.core.a2a import A2AClient
from aisec.core.config import get_settings
from aisec.core.event_bus import Event
from aisec.core.tools import tool
from fastapi import Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

logger = logging.getLogger(__name__)

# 需要代理的 LLM API 路径前缀
PROXIED_PATHS = ("/v1/", "/api/", "/chat/", "/completions", "/embeddings")

# MCP（Model Context Protocol）HTTP 路径：JSON-RPC 2.0 over HTTP
MCP_PATHS = ("/mcp", "/mcp/", "/jsonrpc", "/rpc")

# 默认不代理的路径（Agent 自身端点）
AGENT_PATHS = ("/health", "/card", "/tools", "/a2a", "/chat", "/intercept", "/proxy-stats", "/docs", "/openapi", "/redoc")

# MCP 危险方法（这些方法触发实际副作用，需更严格策略）
MCP_DANGEROUS_METHODS = ("tools/call", "resources/read", "prompts/get")

# MCP 内置工具白名单（默认可放行的常见工具）
MCP_SAFE_TOOLS = frozenset({
    "echo", "list_files", "read_file", "search",
    "web_search", "fetch_url", "summarize",
})


def _is_mcp_request(path: str, content_type: str = "") -> bool:
    """判断请求是否携带 MCP JSON-RPC 2.0 消息。"""
    if path in MCP_PATHS or any(path.startswith(p + "/") for p in MCP_PATHS):
        return True
    if content_type and "application/json" in content_type.lower() and path.endswith("/mcp"):
        return True
    return False


def _parse_mcp_jsonrpc(body: bytes | str | None) -> dict[str, Any]:
    """解析 JSON-RPC 2.0 格式的 MCP 消息。

    返回 dict：{jsonrpc, id, method, params, tool_name, server_id, raw}；
    非 JSON-RPC 时返回空 dict。
    """
    if not body:
        return {}
    if isinstance(body, bytes):
        try:
            obj = json.loads(body.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
    elif isinstance(body, str):
        try:
            obj = json.loads(body)
        except json.JSONDecodeError:
            return {}
    else:
        return {}
    if not isinstance(obj, dict) or obj.get("jsonrpc") != "2.0":
        return {}
    method = obj.get("method", "")
    params = obj.get("params") or {}
    tool_name = ""
    server_id = ""
    if method == "tools/call" and isinstance(params, dict):
        tool_name = params.get("name", "")
    if method == "resources/read" and isinstance(params, dict):
        uri = params.get("uri", "")
        if isinstance(uri, str) and "://" in uri:
            server_id = uri.split("://", 1)[0]
    return {
        "jsonrpc": "2.0",
        "id": obj.get("id"),
        "method": method,
        "params": params if isinstance(params, dict) else {},
        "tool_name": tool_name,
        "server_id": server_id,
        "raw": obj,
    }


class GatewayAgent(Agent):
    """流量拦截 Agent（含 HTTP 反向代理）。"""

    def __init__(self, settings=None):
        super().__init__(settings)
        self._flow_count = 0
        self._blocked_count = 0
        self._allowed_count = 0
        self._proxy_client: httpx.AsyncClient | None = None

    @property
    def agent_id(self) -> str:
        return "gateway-agent"

    @property
    def name(self) -> str:
        return "流量拦截 Agent"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def role(self) -> AgentRole:
        return AgentRole.TRAFFIC_INTERCEPTOR

    def _endpoints(self) -> dict[str, str]:
        cfg = self.settings.agents.gateway_agent
        return {
            "a2a": f"http://{cfg.host}:{cfg.port}/a2a",
            "intercept": f"http://{cfg.host}:{cfg.port}/intercept",
            "proxy_stats": f"http://{cfg.host}:{cfg.port}/proxy-stats",
        }

    async def setup(self) -> None:
        logger.info(f"[{self.agent_id}] setup done")
        self._proxy_client = httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=10.0),
            follow_redirects=False,
        )
        self.tools.register("parse_request", self._tool_parse_request, "解析并校验一个 Agent 请求")
        self.tools.register("decide_action", self._tool_decide_action, "对请求做放行/拒绝决策")
        self.tools.register("query_identity", self._tool_query_identity, "查询 Agent 身份/信任分")
        self.tools.register("get_flow_stats", self._tool_get_flow_stats, "获取流量统计")
        self.tools.register("get_proxy_stats", self._tool_get_flow_stats, "获取代理统计")
        self.tools.register("parse_mcp_request", self._tool_parse_mcp, "解析 MCP JSON-RPC 请求")

    async def main_loop(self) -> None:
        """主循环：心跳 + 定时清理过期流。"""
        hb_task = asyncio.create_task(self.heartbeat_loop(), name="gw-heartbeat")
        try:
            while not self._stop_event.is_set():
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=30)
                    break
                except asyncio.TimeoutError:
                    pass
        finally:
            hb_task.cancel()
            if self._proxy_client:
                await self._proxy_client.aclose()

    # ---------- 业务工具 ----------

    async def _tool_parse_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """解析请求体，提取关键字段。"""
        return {
            "agent_id": request.get("agent_id", "unknown"),
            "endpoint": request.get("endpoint", ""),
            "method": request.get("method", "POST"),
            "data_sensitivity": request.get("data_sensitivity", "L0"),
            "intent": request.get("intent", ""),
        }

    async def _tool_query_identity(self, agent_id: str) -> dict[str, Any]:
        """通过 A2A 向 soc-agent 询问 Agent 身份（实际是查 Registry）。"""
        soc_url = f"http://{self.settings.agents.soc_agent.host}:{self.settings.agents.soc_agent.port}"
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{soc_url}/registry/agents/{agent_id}")
                if resp.status_code == 200:
                    return resp.json()
        except Exception as e:
            logger.warning(f"query_identity failed: {e}")
        return {"agent_id": agent_id, "status": "unknown", "trust_score": 0}

    async def _tool_decide_action(self, request: dict[str, Any]) -> dict[str, Any]:
        """决策放行/拒绝。返回 {decision, reason}。

        规则（V0.4 Demo 简化）：
        1. agent_id 未注册 -> deny
        2. trust_score < 30 -> rate_limit
        3. data_sensitivity >= L3 -> soc_approval
        4. MCP tools/call 调用的工具不在 MCP_SAFE_TOOLS 中 -> soc_approval（需人工审查）
        5. 否则 allow
        """
        agent_id = request.get("agent_id", "unknown")
        sens = request.get("data_sensitivity", "L0")
        identity = await self._tool_query_identity(agent_id)
        if identity.get("status") == "offline" or (identity.get("status") == "unknown" and not identity.get("trust_score")):
            return {"decision": "deny", "reason": f"agent '{agent_id}' not in registry"}
        trust = identity.get("trust_score", 0)
        if trust < 30:
            return {"decision": "rate_limit", "reason": f"trust_score={trust} too low", "trust_score": trust}
        if sens in ("L3", "L4"):
            return {"decision": "soc_approval", "reason": f"data_sensitivity={sens} requires approval"}
        # MCP 危险方法 + 未知工具 -> soc_approval
        mcp_method = request.get("mcp_method", "")
        mcp_tool = request.get("mcp_tool_name", "")
        if mcp_method in MCP_DANGEROUS_METHODS and mcp_tool and mcp_tool not in MCP_SAFE_TOOLS:
            return {
                "decision": "soc_approval",
                "reason": f"MCP {mcp_method} calls non-whitelisted tool '{mcp_tool}'",
                "trust_score": trust,
            }
        return {"decision": "allow", "reason": "all checks passed", "trust_score": trust}

    async def _tool_get_flow_stats(self) -> dict[str, Any]:
        return {
            "flow_count": self._flow_count,
            "blocked_count": self._blocked_count,
            "allowed_count": self._allowed_count,
        }

    async def _tool_parse_mcp(self, body: str = "", content_type: str = "") -> dict[str, Any]:
        """工具方法：解析 MCP JSON-RPC 2.0 消息并返回结构化字段。

        入参 body 可为 str（已 decode）或 hex/base64（这里仅支持 str）。
        非 MCP 消息时 is_mcp=False。
        """
        msg = _parse_mcp_jsonrpc(body) if body else {}
        if not msg:
            return {"is_mcp": False, "reason": "not a JSON-RPC 2.0 message"}
        method = msg.get("method", "")
        tool_name = msg.get("tool_name", "")
        server_id = msg.get("server_id", "")
        is_dangerous = method in MCP_DANGEROUS_METHODS
        is_safe_tool = tool_name in MCP_SAFE_TOOLS
        return {
            "is_mcp": True,
            "method": method,
            "tool_name": tool_name,
            "server_id": server_id,
            "is_dangerous": is_dangerous,
            "is_safe_tool": is_safe_tool,
            "jsonrpc_id": msg.get("id"),
            "raw": msg.get("raw"),
        }

    # ---------- 反向代理核心 ----------

    def _extract_agent_id(self, request: Request) -> str:
        """从请求头中提取 agent_id。

        约定：客户端在请求头中携带 X-Agent-ID 标识自己。
        若未携带，尝试从 Authorization header 或回退为 "anonymous"。
        """
        agent_id = request.headers.get("X-Agent-ID", "")
        if not agent_id:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                agent_id = f"token:{auth[7:20]}..."
        return agent_id or "anonymous"

    def _extract_agent_token(self, request: Request) -> str:
        """从请求头中提取 agent_token。

        约定：客户端在请求头中携带 X-Agent-Token 进行身份验证。
        若未携带，返回空字符串。
        """
        return request.headers.get("X-Agent-Token", "")

    def _extract_data_sensitivity(self, request: Request) -> str:
        """从请求头中提取数据敏感级别。"""
        return request.headers.get("X-Data-Sensitivity", "L0")

    async def _intercept_and_proxy(self, request: Request) -> Response:
        """拦截请求 -> 身份验证 -> 策略决策 -> 转发或拒绝。"""
        trace_id = str(uuid.uuid4())[:12]
        path = request.url.path
        method = request.method
        agent_id = self._extract_agent_id(request)
        agent_token = self._extract_agent_token(request)
        data_sens = self._extract_data_sensitivity(request)
        content_type = request.headers.get("content-type", "")

        self._flow_count += 1

        # 0.5 身份认证：若 agent_id 不是 anonymous，验证 token
        if agent_id != "anonymous" and agent_token:
            from aisec.core.registry import AgentRegistry
            registry = AgentRegistry(self.settings)
            token_valid = await registry.verify_token(agent_id, agent_token)
            if not token_valid:
                self._blocked_count += 1
                await self.event_bus.append(Event(
                    type="identity_verification_failed",
                    source=self.agent_id,
                    payload={"trace_id": trace_id, "agent_id": agent_id, "reason": "token_mismatch"},
                ))
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "identity_verification_failed",
                        "detail": f"Agent '{agent_id}' token 验证失败。请检查 X-Agent-Token 请求头。",
                        "trace_id": trace_id,
                        "gateway": self.agent_id,
                    },
                )

        # 0. 预读 body + 解析 MCP JSON-RPC（若有）
        mcp_info: dict[str, Any] = {}
        is_mcp = _is_mcp_request(path, content_type)
        body_bytes = await request.body()
        if is_mcp:
            mcp_info = _parse_mcp_jsonrpc(body_bytes)

        # 1. 策略决策
        decision_input: dict[str, Any] = {
            "agent_id": agent_id,
            "endpoint": path,
            "method": method,
            "data_sensitivity": data_sens,
        }
        if mcp_info:
            decision_input["mcp_method"] = mcp_info.get("method", "")
            decision_input["mcp_tool_name"] = mcp_info.get("tool_name", "")
            decision_input["mcp_server_id"] = mcp_info.get("server_id", "")
        decision_result = await self._tool_decide_action(decision_input)
        decision = decision_result["decision"]

        # 2. 记录事件
        event_payload: dict[str, Any] = {
            "trace_id": trace_id,
            "agent_id": agent_id,
            "method": method,
            "path": path,
            "decision": decision,
            "reason": decision_result.get("reason", ""),
            "data_sensitivity": data_sens,
        }
        if mcp_info:
            event_payload["mcp"] = {
                "method": mcp_info.get("method", ""),
                "tool_name": mcp_info.get("tool_name", ""),
                "server_id": mcp_info.get("server_id", ""),
                "jsonrpc_id": mcp_info.get("id"),
            }
            # MCP 工具调用使用专用事件类型，便于审计筛选
            await self.event_bus.append(Event(
                type="mcp_request_observed",
                source=self.agent_id,
                payload=event_payload,
            ))

        # 3. 拒绝
        if decision == "deny":
            self._blocked_count += 1
            await self.event_bus.append(Event(
                type="request_blocked",
                source=self.agent_id,
                payload=event_payload,
            ))
            return JSONResponse(
                status_code=403,
                content={
                    "error": "request_blocked",
                    "decision": decision,
                    "reason": decision_result.get("reason", ""),
                    "trace_id": trace_id,
                    "gateway": self.agent_id,
                },
            )

        # 4. 限流（Demo 简化：仍放行但加警告头）
        if decision == "rate_limit":
            await self.event_bus.append(Event(
                type="request_rate_limited",
                source=self.agent_id,
                payload=event_payload,
            ))

        # 5. 需 SOC 审批（Demo 简化：记录但放行）
        if decision == "soc_approval":
            await self.event_bus.append(Event(
                type="request_pending_approval",
                source=self.agent_id,
                payload=event_payload,
            ))

        # 5.5 MSP 模型熔断检查：若模型被标记为 dangerous/suspicious，拒绝请求
        from aisec.core.circuit_breaker import is_tripped
        breaker = is_tripped(self.settings)
        if breaker.get("tripped"):
            self._blocked_count += 1
            event_payload["breaker"] = breaker
            await self.event_bus.append(Event(
                type="model_circuit_breaker_tripped",
                source=self.agent_id,
                payload=event_payload,
            ))
            return JSONResponse(
                status_code=503,
                content={
                    "error": "model_circuit_breaker_tripped",
                    "detail": (
                        f"模型 '{breaker.get('model', '?')}' 已被熔断。"
                        f"原因: {breaker.get('reason', 'MSP scan detected vulnerability')}。"
                        f"请联系 SOC 运营人员处理。"
                    ),
                    "trace_id": trace_id,
                    "gateway": self.agent_id,
                    "breaker": breaker,
                },
            )

        # 6. 转发请求到真实 LLM API
        self._allowed_count += 1
        target_url = str(request.url)

        # 如果请求是发到 gateway 自身的，需要替换为目标 LLM API
        # 约定：客户端将 LLM API 的 base_url 设为 gateway 地址
        # gateway 根据路径转发到配置的 LLM API
        # 注意：避免 base_url 末尾的 /v1 与 path 前缀 /v1/ 重复拼接
        llm_base = self.settings.llm.base_url.rstrip("/")
        if llm_base.endswith("/v1") and path.startswith("/v1/"):
            effective_base = llm_base[:-3].rstrip("/")
            target_url = f"{effective_base}{path}"
        elif path.startswith("/v1/") or path.startswith("/api/"):
            target_url = f"{llm_base}{path}"
        if request.url.query:
            target_url += f"?{request.url.query}"

        # 6.1 MCP 请求：demo 阶段不依赖真实 MCP server，解析 + 决策后返回 mock 响应
        if mcp_info and path in MCP_PATHS or any(path.startswith(p + "/") for p in MCP_PATHS):
            mock_response: dict[str, Any] = {
                "jsonrpc": "2.0",
                "id": mcp_info.get("id"),
                "result": {
                    "decision": decision,
                    "trace_id": trace_id,
                    "method": mcp_info.get("method", ""),
                    "tool_name": mcp_info.get("tool_name", ""),
                    "server_id": mcp_info.get("server_id", ""),
                    "executed": decision in ("allow", "soc_approval"),
                    "message": (
                        "mock MCP response (no real MCP backend in demo)"
                    ),
                },
            }
            event_payload["status_code"] = 200
            event_payload["response_size"] = len(json.dumps(mock_response))
            event_payload["target"] = "mock://mcp"
            await self.event_bus.append(Event(
                type="mcp_request_mocked",
                source=self.agent_id,
                payload=event_payload,
            ))
            return JSONResponse(
                status_code=200,
                content=mock_response,
                headers={
                    "X-Trace-ID": trace_id,
                    "X-Gateway-Decision": decision,
                },
            )

        try:
            # body 已在函数开头预读（MCP 解析用），此处复用
            body = body_bytes
            # 构建转发请求头（去掉 host 和 agent 自定义头）
            fwd_headers = dict(request.headers)
            fwd_headers.pop("host", None)
            fwd_headers.pop("x-agent-id", None)
            fwd_headers.pop("x-data-sensitivity", None)
            # 确保有 Authorization
            if "authorization" not in {k.lower() for k in fwd_headers} and self.settings.effective_llm_api_key:
                fwd_headers["Authorization"] = f"Bearer {self.settings.effective_llm_api_key}"

            # 判断是否流式请求
            is_stream = False
            if body:
                try:
                    body_json = json.loads(body)
                    is_stream = body_json.get("stream", False)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

            if is_stream:
                # 流式转发
                return await self._proxy_stream(request, target_url, fwd_headers, body, event_payload, trace_id)

            # 非流式转发
            resp = await self._proxy_client.request(
                method=method,
                url=target_url,
                headers=fwd_headers,
                content=body,
            )

            # 记录成功事件
            event_payload["status_code"] = resp.status_code
            event_payload["response_size"] = len(resp.content)
            await self.event_bus.append(Event(
                type="request_proxied",
                source=self.agent_id,
                payload=event_payload,
            ))

            # 返回代理响应
            resp_headers = dict(resp.headers)
            resp_headers.pop("transfer-encoding", None)
            resp_headers["X-Trace-ID"] = trace_id
            resp_headers["X-Gateway-Decision"] = decision

            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers={k: v for k, v in resp_headers.items()
                         if k.lower() not in ("content-encoding", "content-length")},
                media_type=resp_headers.get("content-type"),
            )

        except httpx.ConnectError as e:
            self._blocked_count += 1
            await self.event_bus.append(Event(
                type="proxy_error",
                source=self.agent_id,
                payload={**event_payload, "error": str(e)},
            ))
            return JSONResponse(
                status_code=502,
                content={"error": "upstream_connect_error", "detail": str(e), "trace_id": trace_id},
            )
        except Exception as e:
            logger.exception(f"proxy error: {e}")
            await self.event_bus.append(Event(
                type="proxy_error",
                source=self.agent_id,
                payload={**event_payload, "error": str(e)},
            ))
            return JSONResponse(
                status_code=502,
                content={"error": "proxy_error", "detail": str(e), "trace_id": trace_id},
            )

    async def _proxy_stream(
        self, request: Request, target_url: str, headers: dict, body: bytes,
        event_payload: dict, trace_id: str,
    ) -> StreamingResponse:
        """流式代理转发（SSE / chunked）。

        改进点：
        - 透传上游 status_code 和 content-type
        - 流结束后记录响应大小事件
        - 异常时发送 SSE 格式错误帧
        """
        resp_status = 200
        resp_content_type = "text/event-stream"

        async def stream_generator():
            nonlocal resp_status, resp_content_type
            total_bytes = 0
            try:
                async with self._proxy_client.stream(
                    method=request.method,
                    url=target_url,
                    headers=headers,
                    content=body,
                ) as resp:
                    resp_status = resp.status_code
                    resp_content_type = resp.headers.get("content-type", "text/event-stream")
                    async for chunk in resp.aiter_bytes():
                        total_bytes += len(chunk)
                        yield chunk
            except Exception as e:
                logger.error(f"stream proxy error: {e}")
                # SSE 格式错误帧，方便客户端感知
                yield f'data: {{"error": "{str(e)}", "trace_id": "{trace_id}"}}\n\n'.encode()
            finally:
                # 流结束后记录事件（在 generator 完成时执行）
                await self.event_bus.append(Event(
                    type="request_proxied_stream",
                    source=self.agent_id,
                    payload={**event_payload, "stream": True, "response_bytes": total_bytes},
                ))

        return StreamingResponse(
            stream_generator(),
            status_code=resp_status,
            media_type=resp_content_type,
            headers={"X-Trace-ID": trace_id, "X-Gateway-Decision": "allow"},
        )

    # ---------- 注册代理路由 ----------

    def build_app(self):
        app = super().build_app()

        @app.get("/proxy-stats")
        async def proxy_stats():
            return await self._tool_get_flow_stats()

        @app.post("/intercept")
        async def intercept_endpoint(request: Request):
            """手动提交请求进行拦截决策（不代理，仅返回决策结果）。"""
            body = await request.json()
            result = await self._tool_decide_action(body)
            return {"ok": True, "result": result}

        # 通配代理路由：匹配所有未被 Agent 自身端点处理的路径
        @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
        async def proxy_catchall(request: Request, path: str):
            """反向代理：拦截所有非 Agent 自身端点的请求。"""
            # 跳过 Agent 自身端点（已由 FastAPI 路由处理）
            if any(request.url.path.startswith(p) for p in AGENT_PATHS):
                return JSONResponse(status_code=404, content={"error": "not found"})
            return await self._intercept_and_proxy(request)

        return app

    # ---------- A2A 处理 ----------

    async def handle_a2a(self, msg):
        """收到 verify_identity / intercept_request 等意图时处理。"""
        intent = msg.intent
        if intent == "verify_identity":
            agent_id = msg.context.get("agent_id", "")
            ident = await self._tool_query_identity(agent_id)
            from aisec.core.a2a import A2AResponse

            decision = "allow" if ident.get("status") == "online" else "deny"
            return A2AResponse(
                from_=self.agent_id,
                to=msg.from_,
                trace_id=msg.trace_id,
                decision=decision,
                action="verify_identity",
                reason=f"trust_score={ident.get('trust_score', 0)}",
                result=ident,
            )
        if intent == "decide_intercept":
            decision = await self._tool_decide_action(msg.context)
            from aisec.core.a2a import A2AResponse

            return A2AResponse(
                from_=self.agent_id,
                to=msg.from_,
                trace_id=msg.trace_id,
                decision=decision["decision"],
                action=decision["decision"],
                reason=decision["reason"],
                result=decision,
            )
        return await super().handle_a2a(msg)


def main() -> None:
    """gateway-agent 进程入口。"""
    import asyncio
    import logging
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout,
    )
    settings = get_settings()
    cfg = settings.agents.gateway_agent
    agent = GatewayAgent(settings)
    print(f"[gateway-agent] starting on {cfg.host}:{cfg.port}", flush=True)
    asyncio.run(agent.run(host=cfg.host, port=cfg.port))


if __name__ == "__main__":
    main()
