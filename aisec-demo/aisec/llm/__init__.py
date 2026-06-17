"""LLM 客户端（千问 OpenAI 兼容）+ Mock 模式。

API Key 优先：环境变量 DASHSCOPE_API_KEY > 配置文件 llm.api_key
若均空：LLM 走 mock 模式（返回占位响应），方便 Demo 离线开发。
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from aisec.core.config import Settings, get_settings

logger = logging.getLogger(__name__)


class LLMClient:
    """千问 LLM 客户端。"""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self._client: Any = None

    @property
    def api_key(self) -> str:
        return self.settings.effective_llm_api_key

    @property
    def mock_mode(self) -> bool:
        return not self.api_key

    def _ensure_client(self) -> Any:
        if self.mock_mode:
            return None
        if self._client is None:
            try:
                from openai import AsyncOpenAI
            except ImportError as e:
                raise RuntimeError("openai package not installed") from e
            self._client = AsyncOpenAI(
                api_key=self.api_key,
                base_url=self.settings.llm.base_url,
                timeout=self.settings.llm.timeout,
                max_retries=self.settings.llm.max_retries,
            )
        return self._client

    async def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.3,
        **kwargs: Any,
    ) -> str:
        """Chat completion。返回纯文本。

        messages: [{"role": "system|user|assistant", "content": "..."}]

        内置 asyncio.wait_for 强制超时上限，避免在 Anaconda Windows 环境下
        httpx 异步连接因 ProactorEventLoop 边缘情况而无限挂起。
        """
        if self.mock_mode:
            return self._mock_response(messages)
        client = self._ensure_client()

        async def _do_call() -> str:
            resp = await client.chat.completions.create(
                model=self.settings.llm.model,
                messages=messages,
                temperature=temperature,
                **kwargs,
            )
            return resp.choices[0].message.content or ""

        # 硬超时：timeout(秒) + 5s buffer + 1次重试
        hard_timeout = self.settings.llm.timeout + 5
        try:
            return await asyncio.wait_for(_do_call(), timeout=hard_timeout)
        except asyncio.TimeoutError:
            logger.warning(f"LLM call hard-timeout after {hard_timeout}s")
            raise

    def _mock_response(self, messages: list[dict[str, str]]) -> str:
        """Mock 模式：返回结构化的占位响应，避免阻塞 Demo。"""
        last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        return (
            "[MOCK LLM - 未配置 DASHSCOPE_API_KEY]\n"
            f"收到 prompt: {last_user[:200]}...\n"
            "回复: 这是占位响应，请配置 DASHSCOPE_API_KEY 启用真实 LLM。"
        )
