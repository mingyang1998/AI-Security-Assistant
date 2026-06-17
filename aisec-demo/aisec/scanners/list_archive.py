"""黑白名单归档管理。

基于 SHA256 哈希指纹的黑白名单：
- whitelist/：安全 Skill/MCP 的哈希归档
- blacklist/：危险 Skill/MCP 的哈希归档

每个归档条目是一个 JSON 文件，文件名为 <sha256>.json。
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _ensure_dir(base_dir: Path, subdir: str) -> Path:
    d = base_dir / subdir
    d.mkdir(parents=True, exist_ok=True)
    return d


class ListArchive:
    """黑白名单归档管理器。"""

    def __init__(self, data_dir: str | Path):
        self.data_dir = Path(data_dir)
        self.whitelist_dir = _ensure_dir(self.data_dir, "whitelist")
        self.blacklist_dir = _ensure_dir(self.data_dir, "blacklist")

    def _archive_path(self, sha256: str, is_whitelist: bool) -> Path:
        d = self.whitelist_dir if is_whitelist else self.blacklist_dir
        return d / f"{sha256}.json"

    def add_to_whitelist(self, record: dict[str, Any]) -> Path:
        """将扫描结果归档到白名单。record 须包含 sha256 字段。"""
        sha256 = record.get("sha256", "")
        if not sha256:
            raise ValueError("record must contain 'sha256'")
        record["archived_at"] = datetime.now().isoformat(timespec="seconds")
        record["list_type"] = "whitelist"
        path = self._archive_path(sha256, True)
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info(f"archived to whitelist: {sha256[:16]}...")
        return path

    def add_to_blacklist(self, record: dict[str, Any]) -> Path:
        """将扫描结果归档到黑名单。record 须包含 sha256 字段。"""
        sha256 = record.get("sha256", "")
        if not sha256:
            raise ValueError("record must contain 'sha256'")
        record["archived_at"] = datetime.now().isoformat(timespec="seconds")
        record["list_type"] = "blacklist"
        path = self._archive_path(sha256, False)
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info(f"archived to blacklist: {sha256[:16]}...")
        return path

    def auto_archive(self, scan_result: dict[str, Any]) -> Path | None:
        """根据扫描结果的风险等级自动归档到黑/白名单。

        - safe -> 白名单
        - suspicious/dangerous -> 黑名单
        """
        risk = scan_result.get("risk", {})
        level = risk.get("level", "")
        if level == "safe":
            return self.add_to_whitelist(scan_result)
        elif level in ("suspicious", "dangerous"):
            return self.add_to_blacklist(scan_result)
        return None

    def is_in_whitelist(self, sha256: str) -> bool:
        return self._archive_path(sha256, True).exists()

    def is_in_blacklist(self, sha256: str) -> bool:
        return self._archive_path(sha256, False).exists()

    def get_from_whitelist(self, sha256: str) -> dict[str, Any] | None:
        path = self._archive_path(sha256, True)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def get_from_blacklist(self, sha256: str) -> dict[str, Any] | None:
        path = self._archive_path(sha256, False)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def list_whitelist(self) -> list[dict[str, Any]]:
        results = []
        for f in sorted(self.whitelist_dir.glob("*.json")):
            try:
                results.append(json.loads(f.read_text(encoding="utf-8")))
            except Exception:
                pass
        return results

    def list_blacklist(self) -> list[dict[str, Any]]:
        results = []
        for f in sorted(self.blacklist_dir.glob("*.json")):
            try:
                results.append(json.loads(f.read_text(encoding="utf-8")))
            except Exception:
                pass
        return results

    def remove_from_whitelist(self, sha256: str) -> bool:
        path = self._archive_path(sha256, True)
        if path.exists():
            path.unlink()
            return True
        return False

    def remove_from_blacklist(self, sha256: str) -> bool:
        path = self._archive_path(sha256, False)
        if path.exists():
            path.unlink()
            return True
        return False
