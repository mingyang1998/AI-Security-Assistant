"""静态特征分析器：AST + 正则匹配。

检测维度：
1. 危险 import（os.system, subprocess, eval, exec, socket, requests 等）
2. 危险调用（shell=True, eval, exec, __import__）
3. 外连域名（http://, https://）
4. 文件系统越界（/etc/, C:\\Windows\\, ../）
5. 环境变量读取（os.environ）
6. 反序列化（pickle, marshal）
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any


# 危险模块/包名（Dangerous imports）
DANGEROUS_IMPORTS = {
    # 进程 / shell
    "os.system", "os.popen", "os.exec", "os.execv", "os.execvp",
    "subprocess", "subprocess.Popen", "subprocess.run", "subprocess.call",
    "commands",  # py2
    # 代码执行
    "eval", "exec", "compile", "code", "codeop",
    "__import__",
    # 反序列化
    "pickle", "pickle.loads", "cPickle", "marshal",
    "shelve",  # 底层用 pickle
    "yaml.load",  # 不带 safe_loader 危险
    # 网络
    "socket", "socketserver",
    "urllib.request", "urllib.urlopen",
    "httplib", "http.client",
    "requests", "urllib3", "httpx", "aiohttp", "pycurl",
    # 系统信息/凭据
    "os.environ", "os.getenv", "os.path.expanduser",
    # 动态代码
    "importlib", "importlib.import_module",
    # C 扩展
    "ctypes", "cffi",
}

# 危险函数调用（关键字）
DANGEROUS_CALLS = {
    "eval", "exec", "compile",
    "system", "popen", "spawn",
    "shell=True",
    "load",  # yaml.load / pickle.load 需结合上下文
}

# 危险正则（与上下文无关，直接匹配源码）
DANGEROUS_PATTERNS = [
    (re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"), "subprocess shell=True"),
    (re.compile(r"__import__\s*\("), "dynamic __import__"),
    (re.compile(r"\beval\s*\("), "eval() call"),
    (re.compile(r"\bexec\s*\("), "exec() call"),
    (re.compile(r"base64\.(b64decode|decodebytes)"), "base64 decode"),
    (re.compile(r"requests?\.(get|post|put|delete|patch)\s*\("), "HTTP request"),
    (re.compile(r"urllib(2|3)?\.request\.urlopen"), "urlopen"),
    (re.compile(r"socket\.socket\s*\("), "raw socket"),
    (re.compile(r"open\s*\(\s*['\"]\/etc\/"), "read /etc/*"),
    (re.compile(r"open\s*\(\s*['\"]C:\\\\Windows", re.IGNORECASE), "read C:\\Windows"),
    (re.compile(r"\.ssh[/\\]"), "read .ssh/*"),
    (re.compile(r"\.aws[/\\]credentials"), "read AWS credentials"),
    (re.compile(r"\.env['\"]?"), "read .env"),
    (re.compile(r"reverse[\s_-]?shell", re.IGNORECASE), "reverse shell keyword"),
    (re.compile(r"(rm\s+-rf|del\s+/[sS])", re.IGNORECASE), "destructive delete"),
    (re.compile(r"os\.environ\[|os\.getenv\("), "read env vars"),
    (re.compile(r"keyring\.|browser_cookie|sqlite3.*Chrome|Cookies"), "browser/credential read"),
]


def analyze_source(source: str) -> dict[str, Any]:
    """AST + 正则双轨分析。返回：
        {
          "ast_imports": [...],
          "ast_calls": [...],
          "pattern_hits": [...],
          "urls": [...],
          "score": 0-100,
          "reasons": [...]
        }
    """
    reasons: list[str] = []
    ast_imports: list[str] = []
    ast_calls: list[str] = []

    # 1. AST
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return {
            "ast_imports": [],
            "ast_calls": [],
            "pattern_hits": [],
            "urls": [],
            "score": 50,
            "reasons": [f"SyntaxError: {e}"],
        }

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                full = n.name
                ast_imports.append(full)
                if full in DANGEROUS_IMPORTS or any(full.startswith(x.split(".")[0]) for x in DANGEROUS_IMPORTS if "." in x):
                    reasons.append(f"dangerous import: {full}")
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                full = f"{node.module}." + (node.names[0].name if node.names else "*")
                ast_imports.append(full)
                if full in DANGEROUS_IMPORTS or node.module in DANGEROUS_IMPORTS:
                    reasons.append(f"dangerous from-import: {full}")
        elif isinstance(node, ast.Call):
            try:
                fn = ast.unparse(node.func)
                ast_calls.append(fn)
            except Exception:
                pass

    # 2. 正则
    pattern_hits: list[str] = []
    for pat, desc in DANGEROUS_PATTERNS:
        for m in pat.finditer(source):
            pattern_hits.append(f"{desc} @ {m.start()}")
    if pattern_hits:
        reasons.extend(pattern_hits[:20])  # 截断

    # 3. 提取外连 URL
    urls = re.findall(r"https?://[^\s'\"<>]+", source)
    urls = list(dict.fromkeys(urls))[:20]
    if urls:
        reasons.append(f"外连 URL: {len(urls)} 处")

    # 4. 评分（0-100）
    score = 0
    score += min(40, len(reasons) * 8)         # 每个 reason 8 分，封顶 40
    if "subprocess" in str(ast_imports):
        score += 10
    if "os" in str(ast_imports) and ("system" in source or "popen" in source):
        score += 10
    if any("shell=True" in r for r in pattern_hits):
        score += 15
    if any(".ssh" in r or ".aws" in r for r in pattern_hits):
        score += 15
    if any("eval" in r for r in pattern_hits):
        score += 10
    score = min(100, score)

    return {
        "ast_imports": ast_imports[:50],
        "ast_calls": ast_calls[:50],
        "pattern_hits": pattern_hits,
        "urls": urls,
        "score": score,
        "reasons": reasons,
    }


def analyze_file(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {"score": 0, "reasons": [f"file not found: {path}"], "urls": [], "pattern_hits": [], "ast_imports": [], "ast_calls": []}
    try:
        src = p.read_text(encoding="utf-8")
    except Exception as e:
        return {"score": 0, "reasons": [f"read error: {e}"], "urls": [], "pattern_hits": [], "ast_imports": [], "ast_calls": []}
    return analyze_source(src)
