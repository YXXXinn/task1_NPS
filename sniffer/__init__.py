"""《软件与系统安全》实验 1A —— 网络嗅探器（第一阶段：命令行最小实现）。

设计要点：本包在导入时就把 Scapy 抓包后端偏好设为 libpcap（通过环境变量
``SCAPY_USE_LIBPCAP``）。该变量必须在任何 scapy 子模块被导入之前设置，
所以集中放在包 __init__ 里，保证所有入口（python -m sniffer / 直接 import
子模块）都先经过这里。

这里只表达「优先走 libpcap」的意愿；本机是否真的启用 libpcap、还是回退到
macOS 原生 BPF，由 backend.detect_backend() 在运行时如实检测，不在此处假设结论。
"""
import os

os.environ.setdefault("SCAPY_USE_LIBPCAP", "yes")

__version__ = "0.1.0"
__all__ = ["__version__"]
