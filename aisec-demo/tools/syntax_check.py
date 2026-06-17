"""语法自检：解析所有 .py 文件。
"""
import ast
import sys
from pathlib import Path

files = [
    "aisec/__init__.py", "aisec/__main__.py", "aisec/cli.py",
    "aisec/core/__init__.py", "aisec/core/config.py", "aisec/core/a2a.py",
    "aisec/core/agent.py", "aisec/core/event_bus.py", "aisec/core/registry.py",
    "aisec/core/tools.py",
    "aisec/agents/__init__.py", "aisec/agents/probe.py", "aisec/agents/gateway.py",
    "aisec/agents/soc.py",
    "aisec/llm/__init__.py",
    "aisec/scanners/__init__.py", "aisec/scanners/risk_scorer.py",
    "aisec/scanners/hasher.py", "aisec/scanners/static_analyzer.py",
    "aisec/scanners/semantic_analyzer.py", "aisec/scanners/sandbox.py",
    "aisec/scanners/skill_scanner.py", "aisec/scanners/mcp_scanner.py",
    "examples/safe_skill.py", "examples/suspicious_skill.py",
    "examples/compliant_agent.py",
]
ok = 0
for f in files:
    p = Path(f)
    if not p.exists():
        print(f"  [missing] {f}")
        continue
    try:
        ast.parse(p.read_text(encoding="utf-8"), filename=f)
        print(f"  [ok]      {f}")
        ok += 1
    except SyntaxError as e:
        print(f"  [ERR]     {f}: {e}")
        sys.exit(1)
print(f"\n{ok}/{len(files)} files parsed successfully")
