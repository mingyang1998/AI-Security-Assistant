"""Demo MSP #3: 模型指纹（可复现）

不依赖真实 LLM；只读取配置 + 计算 sha256。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aisec.msp import fingerprint_model  # noqa: E402


def main() -> int:
    print("=" * 70)
    print("MSP Demo 3: Model Fingerprint (reproducibility snapshot)")
    print("=" * 70)

    fp1 = fingerprint_model()
    print(f"\n[1st] {fp1.short()}")
    print(f"      provider = {fp1.provider}")
    print(f"      api_key_tail = `{fp1.api_key_tail}`  (last 4 chars, never full)")
    print(f"      timestamp    = {fp1.timestamp}")
    print(f"      mock_mode    = {fp1.mock_mode}")
    print(f"      full         = {fp1.fingerprint}")

    # 再生成一次（不同 timestamp）—— 应得到不同 fingerprint
    fp2 = fingerprint_model()
    print(f"\n[2nd] {fp2.short()}")
    print(f"      full         = {fp2.fingerprint}")

    # 同样 timestamp + 配置 + key -> 同样 fingerprint
    from datetime import datetime
    fixed = datetime(2026, 6, 15, 0, 0, 0)
    fp3 = fingerprint_model(when=fixed)
    fp4 = fingerprint_model(when=fixed)
    print(f"\n[3rd & 4th] same timestamp -> same fingerprint? "
          f"{fp3.fingerprint == fp4.fingerprint}")

    print("\n" + "=" * 70)
    print("Verifying:")
    print(f"  - fingerprint changed across calls?     {fp1.fingerprint != fp2.fingerprint}")
    print(f"  - same inputs -> same fingerprint?      {fp3.fingerprint == fp4.fingerprint}")
    print(f"  - mock mode reported correctly?         {fp1.mock_mode}")
    ok = (
        fp1.fingerprint != fp2.fingerprint
        and fp3.fingerprint == fp4.fingerprint
    )
    if not ok:
        print("FAIL")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
