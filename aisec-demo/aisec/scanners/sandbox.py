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
                    args=[ast.Constant(value=f"import {','.join(names)}")],
                    keywords=[],
                ))

            def visit_ImportFrom(self, node):
                mod = node.module or ""
                names = [n.name for n in node.names]
                if any(d == mod.split(".")[0] for d in DANGEROUS_ATTR_HITS):
                    hits.append(f"from {mod} import {','.join(names)}")
                return ast.Expr(value=ast.Call(
                    func=ast.Name(id="gimport", ctx=ast.Load()),
                    args=[ast.Constant(value=f"from {mod} import {','.join(names)}")],
                    keywords=[],
                ))

        tree = ast.parse(code_str)
        _ImportSpy().visit(tree)
        ast.fix_missing_locations(tree)
        code_str = ast.unparse(tree)
        try:
            code = compile_restricted(code_str, "<skill>", "exec")
        except SyntaxError as e:
            # 编译时拒绝（如 eval/exec 关键字）—— AST 阶段记录的 hits 一并返回
            q.put(("ok", hits, [f"compile: {e}"]))
            return
        # 包装 globals：拦截属性访问
        class Guarded:
            def __init__(self, name=""):
                self._name = name

            def __getattr__(self, item):
                if item in DANGEROUS_ATTR_HITS:
                    hits.append(f"access: {self._name}.{item}")
                return Guarded(f"{self._name}.{item}")

            def __call__(self, *args, **kwargs):
                return None

        glb = {"_getattr_": lambda obj, name, default=None: None, "_iter_unpack_sequence_": lambda x: x, "_getitem_": lambda obj, idx: None}
        glb.update(safe_globals)
        glb["_"] = Guarded("_")
        # RP6 默认会注入 '_print = _print_(_getattr_)' 形式的 print 转换代码，
        # 需要在 globals 里提供这些 helper，否则 print() 会直接抛 NameError，
        # 进而阻断后续 gimport 的执行。
        class _NoopPrint:
            def _call_print(self, *args, **kwargs):
                return None
        glb["_print_"] = lambda _getattr_: _NoopPrint()
        # AST 注入后，被测代码中所有 import 都变成对 gimport 的调用
        class _DummyMod:
            """被测代码如果真的用了导入的模块，返回一个静默 dummy 避免 NameError 传播。"""
            def __getattr__(self, item):
                if item in DANGEROUS_ATTR_HITS:
                    hits.append(f"access: {item}")
                return _DummyMod()
            def __call__(self, *args, **kwargs):
                return None
        def gimport(spec: str, *args, **kwargs):
            spec_l = spec.lower()
            for d in DANGEROUS_ATTR_HITS:
                if d in spec_l:
                    hits.append(f"import: {spec}")
                    break
            return _DummyMod()  # 不抛，让后续 import 也能继续被探测
        glb["gimport"] = gimport
        glb["__import__"] = gimport  # 兼容手写 import
        try:
            exec(code, glb)
        except Exception as e:
            exec_errors.append(f"{type(e).__name__}: {e}")
    except Exception as e:
        q.put(("error", [f"sandbox init: {e}"]))
        return
    q.put(("ok", hits, exec_errors))


def run_in_sandbox(path: str | Path, timeout_sec: int = 5) -> dict[str, Any]:
    """在子进程中跑 Skill 源码，收集尝试访问的危险属性。

    Windows 上 spawn 子进程容易卡死/拿不到 queue；为最大兼容性，
    优先在子进程中跑，失败时回退到当前进程内（in-process）执行。
    """
    import sys as _sys
    p = Path(path)
    if not p.exists():
        return {"score": 0, "reasons": [f"file not found: {path}"]}
    code = p.read_text(encoding="utf-8")

    def _run_inproc() -> tuple[list, list, float]:
        """不开子进程，直接调 _observe_in_subproc 的等价逻辑。"""
        import queue as _queue
        q: Any = _queue.Queue()
        t0 = time.time()
        try:
            _observe_in_subproc(code, q)
        except Exception as e:
            return [], [f"inproc error: {e}"], time.time() - t0
        elapsed = time.time() - t0
        try:
            item = q.get_nowait()
        except Exception:
            return [], ["sandbox no result"], elapsed
        # 兼容 2-tuple 错误路径 ("error", [msg]) 和 3-tuple 成功路径
        if isinstance(item, tuple) and len(item) == 2:
            _, msgs = item
            return [], list(msgs) if isinstance(msgs, list) else [str(msgs)], elapsed
        if isinstance(item, tuple) and len(item) == 3:
            status, hits, exec_errors = item
            return (hits if isinstance(hits, list) else []), \
                   (exec_errors if isinstance(exec_errors, list) else []), elapsed
        return [], ["sandbox unknown result"], elapsed

    if _sys.platform == "win32":
        # Windows: 直接 in-process 跑（spawn 子进程在 Win 上常被 Anaconda 防火墙拦）
        hits, exec_errors, elapsed = _run_inproc()
        # RP6 静态拒绝的语法（如 eval、exec 关键字）也算"危险信号"
        if exec_errors and any("Eval" in e or "exec" in e.lower() or "not allowed" in e for e in exec_errors):
            hits = list(hits) + [f"compile-time block: {e.split(':')[-1].strip()}" for e in exec_errors]
        if hits or exec_errors:
            score = min(100, len(hits) * 15)
            reasons = list(hits) + [f"sandbox-exec: {e}" for e in exec_errors if e not in str(hits)]
            return {"score": score, "reasons": reasons, "elapsed_sec": elapsed, "status": "ok"}
        return {"score": 0, "reasons": ["sandbox no result"], "elapsed_sec": elapsed}

    # 非 Windows 平台保持原 spawn 逻辑
    ctx = mp.get_context("spawn")
    q: Any = ctx.Queue()
    proc = ctx.Process(target=_observe_in_subproc, args=(code, q), daemon=True)
    t0 = time.time()
    proc.start()
    proc.join(timeout=timeout_sec)
    elapsed = time.time() - t0
    if proc.is_alive():
        proc.terminate()
        proc.join(1)
        return {"score": 50, "reasons": [f"sandbox timeout ({timeout_sec}s)"], "elapsed_sec": elapsed}
    if proc.exitcode != 0:
        return {"score": 30, "reasons": [f"sandbox crashed (exit={proc.exitcode})"], "elapsed_sec": elapsed}
    try:
        status, hits, exec_errors = q.get_nowait()
    except Exception:
        return {"score": 0, "reasons": ["sandbox no result"], "elapsed_sec": elapsed}

    risk_hits = [h for h in hits] if isinstance(hits, list) else []
    score = min(100, len(risk_hits) * 15)
    reasons = risk_hits + [f"sandbox-exec: {e}" for e in exec_errors]
    return {"score": score, "reasons": reasons, "elapsed_sec": elapsed, "status": status}
