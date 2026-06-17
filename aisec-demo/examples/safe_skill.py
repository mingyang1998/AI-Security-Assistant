"""示例：完全无害的 Skill（应当评分为 safe）。

给 LLM 提供一个简单的单位换算工具。
"""
from typing import Dict


def celsius_to_fahrenheit(c: float) -> Dict[str, float]:
    """摄氏度转华氏度。"""
    return {"celsius": c, "fahrenheit": c * 9 / 5 + 32}


def main():
    print(celsius_to_fahrenheit(25))


if __name__ == "__main__":
    main()
