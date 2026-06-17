"""沙箱：RestrictedPython 包装 + 超时/资源监控。

Demo 阶段目标：
- 让 Skill 的"声明函数"在一个受限环境里跑一遍
- 观察其尝试访问的属性/调用，标记异常行为
- 不真正执行用户数据访问（危险函数会被禁止）

替代方案：subprocess 跑用户脚本 + 资源限制（subprocess.Popen + psutil 监控）。
Demo 默认采用 RestrictedPython（更轻量、不依赖系统能力）。
"""
from __future__ import annotations

import logging
import multiprocessing as mp
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# 试图访问这些属性 -> 风险加分
DANGEROUS_ATTR_HITS = (
    "os", "subprocess", "sys", "socket", "urllib", "requests",
    "eval", "exec", "compile", "__import__", "__builtins__",
    "open", "file", "input", "globals", "locals",
)


def _observe_in_subproc(code_str: str, q) -> None:
    """子进程执行：探测尝试访问的危险属性。"""
    hits: list[str] = []
    exec_errors: list[str] = []
    try:
        from RestrictedPython import compile_restricted
        # RestrictedPython 6.x 移除了 safe_locals；保留 safe_globals 即可
        from RestrictedPython.Guards import safe_globals
        # 预清理：RestrictedPython 6 拒绝任何以 _ 开头的标识符，
        # 并且会把 import 语句静态改写（不真正走 __import__）。
        # 这里用 AST 把 import 直接替换为对 _guarded_import 的显式调用。
        import ast
        import re

        code_str = re.sub(
            r"if\s+__name__\s*==\s*[\"']__main__[\"']\s*:",
            "if False:",
            code_str,
        )
        code_str = re.sub(r"__name__", "name_", code_str)

        class _ImportSpy(ast.NodeTransformer):
            def visit_Import(self, node):
                names = [n.name for n in node.names]
                # 在 AST 阶段就记录 dangerous import（RP6 拒绝 eval 时
                # 整个 module 不会执行，这里必须提前记录）
                for n in names:
                    if any(d == n.split(".")[0] for d in DANGEROUS_ATTR_HITS):
                        hits.append(f"import: {n}")
                return ast.Expr(value=ast.Call(
                    func=ast.Name(id="gimport", ctx=ast.Load()),