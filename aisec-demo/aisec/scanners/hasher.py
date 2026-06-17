"""文件/内容指纹（SHA256）。"""
from __future__ import annotations

import hashlib
from pathlib import Path


def file_hash(path: str | Path) -> str:
    """计算文件 SHA256（十六进制）。"""
    p = Path(path)
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
