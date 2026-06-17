"""Demo MSP #4: 完整 MSP 扫描（端到端）

跑全部 4 个 phase：
  1. fingerprint        模型指纹
  2. injection          注入检测（默认用内置 attack prompt）
  3. harmful            有害输出检测（默认用内置恶意样例）
  4. jailbreak          主动越狱探测（5 个内置 probe）

会真实调 LLM（若已配置 DASHSCOPE_API_KEY）。Mock 模式下 jailbreak 阶段
会被标注 skipped，但仍生成完整报告。
"""
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aisec.msp.runner import run_full_scan, save_report  # noqa: E402


def main() -> int:
    print("=" * 70)
    print("MSP Demo 4: Full Scan (4 phases)")
    print("=" * 70)

    report = asyncio.run(run_full_scan(do_jailbreak=True))
    paths = save_report(report, out_dir="data/msp")

    print(f"\n[fingerprint] model={report.fingerprint.model}  "
          f"host={report.fingerprint.host}  mock={report.fingerprint.mock_mode}")
    print(f"              sha256={report.fingerprint.fingerprint}")
    print(f"              key_tail=`{report.fingerprint.api_key_tail}`")

    for name, p in report.phases.items():
        if name == "jailbreak":
            print(f"\n[jailbreak]  evaluated={p['evaluated']}  "
                  f"skipped={p['skipped_mock']}  successes={p['successes']}  "
                  f"rate={p['jailbreak_rate_pct']:.1f}%")
            for r in p["results"]:
                flag = "SKIP" if r["skipped"] else ("HIT " if r["success"] else "ok  ")
                print(f"   [{flag}] {r['probe_id']:14s} {r['category']:20s} "
                      f"flags={r['matched_flags']}  t={r['elapsed_sec']}s")
        else:
            print(f"\n[{name:11s}] score={p['score']:>3}  level={p['level']:11s}")
            for f in p.get("findings", [])[:3]:
                print(f"   - [{f['category']}] {f['matched_text'][:60]}")

    print(f"\noverall_score = {report.overall_score}")
    print(f"overall_level = {report.overall_level}")
    print(f"elapsed       = {report.elapsed_sec:.2f}s")
    print(f"\nreport_json  = {paths['json']}")
    print(f"report_md    = {paths['md']}")

    print("\n" + "=" * 70)
    if report.overall_level == "safe":
        print("PASS: overall level SAFE")
        return 0
    print(f"NOTE: overall level {report.overall_level.upper()} (expected for demo, "
          "since default samples are intentionally hostile)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
