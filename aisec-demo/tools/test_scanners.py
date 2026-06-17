"""不依赖外部包，测试 SMR 扫描器的纯逻辑。

策略：先注册 aisec / aisec.scanners 包为"无 __init__"的占位包，
再按文件加载子模块，使得子模块的 `from aisec.scanners.xxx import yyy` 正常工作。
"""
import importlib.util
import sys
import types
from pathlib import Path


# ---------- 包占位注册 ----------

def _register_pkg(name: str, path: str) -> types.ModuleType:
    """注册一个空包（不执行 __init__）。"""
    if name in sys.modules:
        return sys.modules[name]
    pkg = types.ModuleType(name)
    pkg.__path__ = [path]
    sys.modules[name] = pkg
    return pkg


# aisec / aisec.scanners  -> 必须在加载子模块前注册
_register_pkg("aisec", "aisec")
_register_pkg("aisec.scanners", "aisec/scanners")


def _load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------- 测试 ----------

def test_static_analyzer():
    static_mod = _load("aisec.scanners.static_analyzer", "aisec/scanners/static_analyzer.py")
    analyze_source = static_mod.analyze_source

    print("\n[Test 1] analyze_source on safe_skill.py")
    src = Path("examples/safe_skill.py").read_text(encoding="utf-8")
    res = analyze_source(src)
    print(f"  score = {res['score']}")
    print(f"  imports = {res['ast_imports']}")
    print(f"  reasons = {res['reasons']}")
    assert res["score"] < 30, f"safe skill 误报: score={res['score']}"
    print("  PASS")

    print("\n[Test 2] analyze_source on suspicious_skill.py")
    src = Path("examples/suspicious_skill.py").read_text(encoding="utf-8")
    res = analyze_source(src)
    print(f"  score = {res['score']}")
    print(f"  urls = {res['urls']}")
    print(f"  pattern_hits count = {len(res['pattern_hits'])}")
    print(f"  first 3 reasons: {res['reasons'][:3]}")
    assert res["score"] >= 60, f"suspicious skill 漏报: score={res['score']}"
    assert len(res["urls"]) >= 1, "应检测到外连 URL"
    print("  PASS")


def test_mcp_analyzer():
    _load("aisec.scanners.hasher", "aisec/scanners/hasher.py")
    _load("aisec.scanners.risk_scorer", "aisec/scanners/risk_scorer.py")
    mcp_mod = _load("aisec.scanners.mcp_scanner", "aisec/scanners/mcp_scanner.py")
    analyze_mcp_file = mcp_mod.analyze_mcp_file

    print("\n[Test 3] analyze_mcp_file on demo_mcp.json")
    res = analyze_mcp_file(Path("examples/demo_mcp.json"))
    print(f"  score = {res['score']}")
    print(f"  reasons = {res['reasons']}")
    for srv in res["servers"]:
        print(f"  - {srv['name']}: score={srv['score']}, reasons={srv['reasons'][:2]}")
    assert res["score"] >= 60, f"含 curl + 敏感 env 的 MCP 漏报: {res['score']}"
    assert any("suspicious command" in r for r in res["reasons"]), \
        "应触发 suspicious command 检测"
    assert any("AWS_SECRET" in r for r in res["reasons"]), \
        "应触发敏感环境变量检测"
    print("  PASS")


def test_risk_scorer():
    rs_mod = _load("aisec.scanners.risk_scorer", "aisec/scanners/risk_scorer.py")
    RiskScorer = rs_mod.RiskScorer
    RiskLevel = rs_mod.RiskLevel

    print("\n[Test 4] RiskScorer 阈值分级")
    rs = RiskScorer()
    r1 = rs.score(10, 10, 10)
    assert r1.level == RiskLevel.SAFE, r1
    r2 = rs.score(40, 40, 40)
    assert r2.level == RiskLevel.SUSPICIOUS, r2
    r3 = rs.score(80, 80, 80)
    assert r3.level == RiskLevel.DANGEROUS, r3
    print(f"  safe={r1.weighted}, suspicious={r2.weighted}, dangerous={r3.weighted}")
    print("  PASS")


def test_hasher():
    h_mod = _load("aisec.scanners.hasher", "aisec/scanners/hasher.py")
    print("\n[Test 5] file_hash 稳定性")
    h1 = h_mod.file_hash("examples/safe_skill.py")
    h2 = h_mod.file_hash("examples/safe_skill.py")
    assert h1 == h2
    assert len(h1) == 64  # SHA256 hex
    h3 = h_mod.file_hash("examples/suspicious_skill.py")
    assert h1 != h3
    print(f"  safe_skill: {h1[:16]}...")
    print(f"  suspicious_skill: {h3[:16]}...")
    print("  PASS")


if __name__ == "__main__":
    test_static_analyzer()
    test_mcp_analyzer()
    test_risk_scorer()
    test_hasher()
    print("\n[ALL TESTS PASSED]")
