#!/usr/bin/env python3
"""环境自检脚本：一次性打印 Python/架构/Scapy/后端/网卡信息，便于写实验报告。

用法（在仓库根目录、已激活 venv 的前提下）：
    python scripts/check_env.py
"""
import platform
import sys
from pathlib import Path

# 允许直接 `python scripts/check_env.py` 运行：把仓库根目录加入 import 路径。
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> int:
    print("=== 运行环境 ===")
    print(f"Python  : {sys.version.split()[0]} ({platform.python_implementation()})")
    print(f"架构    : {platform.machine()}")
    print(f"系统    : {platform.system()} {platform.release()}")
    print()

    from sniffer.backend import detect_backend, format_backend
    from sniffer.interfaces import format_interfaces, list_interfaces

    print(format_backend(detect_backend()))
    print()
    print(format_interfaces(list_interfaces()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
