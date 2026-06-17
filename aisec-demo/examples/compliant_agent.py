"""示例：合规 Agent（应能通过白名单注册）。

演示一个使用 langchain 的、行为良好的 Agent。
"""
import time
import os
import sys


def run_task(query: str) -> str:
    """简单的"查询 + 回答"Agent，不读敏感数据，不外连。"""
    time.sleep(0.1)  # 模拟思考
    return f"Echo: {query}"


if __name__ == "__main__":
    q = sys.argv[1] if len(sys.argv) > 1 else "hello"
    print(run_task(q))
