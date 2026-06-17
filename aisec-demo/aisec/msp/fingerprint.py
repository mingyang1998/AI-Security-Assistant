"""模型指纹：用于"可复现"（Plan §7.2 Sprint 4 关键交付）。

每次 LLM 调用绑定：
- model name（基座模型）
- base_url host（API 端点）
- api_key 后 4 位（凭证尾号，便于追踪泄漏源）
- timestamp + sha256 hash（指纹本体）

不存明文 API key，避免泄漏。
"""
from __future__ import annotations

import hashlib
import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from ..core.config import Settings, get_settings


@dataclass
class ModelFingerprint:
    """LLM 模型指纹快照。"""

    model: str
    provider: str
    base_url: str
    api_key_tail: str         # 末 4 位（不存全 key）
    host: str                 # base_url 主机部分
    timestamp: str            # ISO8601
    fingerprint: str          # sha256(model + host + api_key_tail + ts)
    mock_mode: bool = False   # 是否 mock 模式

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def short(self) -> str:
        """短展示形式：fingerprint 前 12 字符 + model。"""
        return f"{self.fingerprint[:12]}  model={self.model}  host={self.host}"


def fingerprint_model(
    settings: Settings | None = None,
    when: datetime | None = None,
) -> ModelFingerprint:
    """生成一次 LLM 调用的指纹快照。"""
    s = settings or get_settings()
    when = when or datetime.utcnow()

    api_key = s.effective_llm_api_key
    api_key_tail = api_key[-4:] if api_key and len(api_key) >= 4 else ("(empty)" if not api_key else "(short)")
    mock_mode = not api_key

    base_url = s.llm.base_url
    parsed = urlparse(base_url)
    host = parsed.netloc or "(unknown)"

    # 主机 IP（最佳努力，可能失败）
    try:
        host_ip = socket.gethostbyname(host.split(":")[0])
    except (socket.gaierror, OSError):
        host_ip = "(unresolvable)"

    ts = when.isoformat(timespec="milliseconds")
    raw = f"{s.llm.model}|{host}|{api_key_tail}|{ts}".encode("utf-8")
    fp = hashlib.sha256(raw).hexdigest()

    return ModelFingerprint(
        model=s.llm.model,
        provider=s.llm.provider,
        base_url=base_url,
        api_key_tail=api_key_tail,
        host=f"{host} (ip={host_ip})",
        timestamp=ts,
        fingerprint=fp,
        mock_mode=mock_mode,
    )
