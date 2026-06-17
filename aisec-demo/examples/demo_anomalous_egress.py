"""示例：触发 probe-agent 的"异常出站连接"检测。

演示场景（Sprint 2 补完）：
- 启动 probe-agent 后，运行本脚本
- 脚本尝试连接一个**非白名单 + 高风险端口**的目的地址
- probe-agent 主循环（每 10s 一次）扫描 net_connections 时会发现这个连接
- 向 EventBus 写 anomalous_egress_detected 事件

注意：probe-agent 跑在独立进程，需要等下一次扫描周期（≤10s）。

使用 RFC 5737 TEST-NET-1 地址（192.0.2.0/24），永远不会真连上，但会产生
短时的 TCP SYN 包，从而在 net_connections 中留下记录。
"""
from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# 非白名单 + 高风险端口
TARGET = ("192.0.2.1", 4444)  # TEST-NET-1 + Metasploit default port


def main() -> int:
    print("=" * 70)
    print(f"Demo 4: 触发异常出站连接（目的 {TARGET[0]}:{TARGET[1]} 不在白名单 + 高风险端口）")
    print("=" * 70)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        print(f"[demo_anomalous_egress] connect {TARGET} ...")
        s.connect(TARGET)
    except (socket.timeout, OSError) as e:
        # 正常情况：192.0.2.1 不可达 -> 抛错，但连接尝试已发出
        print(f"[demo_anomalous_egress] connect failed (expected): {e}")
    finally:
        s.close()

    # 再开一个目标端口扫描
    print("[demo_anomalous_egress] 第二次尝试：连 192.0.2.2:31337 (高风险端口)")
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.settimeout(2.0)
    try:
        s2.connect(("192.0.2.2", 31337))
    except (socket.timeout, OSError) as e:
        print(f"[demo_anomalous_egress] connect failed (expected): {e}")
    finally:
        s2.close()

    print()
    print("[demo_anomalous_egress] 已触发两个异常出站尝试")
    print()
    print("说明：192.0.2.1 (TEST-NET-1) 是 RFC 5737 保留地址，永远不会 ACK。")
    print("SYN 包发出后会因超时关闭，net_connections 看不到 ESTABLISHED，")
    print("因此 probe-agent 不会抓到这两条。")
    print()
    print("probe-agent 会持续抓本机所有对外 ESTABLISHED 连接中的非白名单目的，")
    print("请等待 ≤10s（probe-agent 扫描周期）后查看事件：")
    print("  python -m aisec events | Select-String 'anomalous_egress'")
    print()
    print("或查看数据：")
    print("  Get-Content data/events/<今天>.jsonl | Select-String 'anomalous_egress'")
    print()
    print("（你的本机里真实非白名单出站——浏览器/IDE/系统服务等——会被立刻发现。）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
