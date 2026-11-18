"""Scapy 抓包后端探测。

只做一件事：如实报告当前进程里 Scapy 实际启用的抓包后端，
区分「libpcap」与 macOS 原生「BPF」两条路径，供命令行与实验报告使用。

概念说明（答辩/报告可直接引用）：
- libpcap：跨平台抓包库；Scapy 通过 ctypes 调用它。对应 conf.use_pcap=True，
  L2 socket 为 L2pcapListenSocket / L2pcapSocket。
- 原生 BPF：macOS/BSD 内核的 Berkeley Packet Filter 设备（/dev/bpf*）。
  Scapy 自带一套直接操作 BPF 设备的实现。对应 conf.use_bpf=True，
  L2 socket 为 L2bpfListenSocket / L2bpfSocket。
- 两者底层最终都走内核 BPF；区别在于中间是否经过 libpcap 这一层库。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class BackendInfo:
    """一次后端探测的结构化结果。"""

    scapy_version: str
    use_pcap: bool
    use_bpf: bool
    l2listen: str
    l2socket: str
    backend: str          # "libpcap" / "native-bpf" / "unknown"
    libpcap_pref_env: str  # 进程里 SCAPY_USE_LIBPCAP 的取值（偏好，非结论）


def _class_name(obj) -> str:
    """conf.L2listen 等是「类」，取其 __name__；取不到则退回 str()。"""
    return getattr(obj, "__name__", None) or (str(obj) if obj is not None else "None")


def detect_backend() -> BackendInfo:
    """运行时检测 Scapy 实际启用的后端。

    通过 `from scapy.all import conf` 触发架构初始化，确保 L2 socket 已经
    绑定到具体类，再读取真实值——不预设任何结论。
    """
    import os

    import scapy
    from scapy.all import conf  # 触发 arch 初始化

    use_pcap = bool(conf.use_pcap)
    use_bpf = bool(conf.use_bpf)

    if use_pcap:
        backend = "libpcap"
    elif use_bpf:
        backend = "native-bpf"
    else:
        backend = "unknown"

    return BackendInfo(
        scapy_version=getattr(scapy, "__version__", "unknown"),
        use_pcap=use_pcap,
        use_bpf=use_bpf,
        l2listen=_class_name(conf.L2listen),
        l2socket=_class_name(conf.L2socket),
        backend=backend,
        libpcap_pref_env=os.environ.get("SCAPY_USE_LIBPCAP", "<unset>"),
    )


def format_backend(info: BackendInfo) -> str:
    """把 BackendInfo 渲染成人类可读的多行文本。"""
    if info.backend == "libpcap":
        verdict = "走 libpcap（conf.use_pcap=True）"
    elif info.backend == "native-bpf":
        verdict = "走 macOS 原生 BPF（conf.use_bpf=True，未经 libpcap 库）"
    else:
        verdict = "未能判定"

    lines = [
        "=== Scapy 抓包后端探测 ===",
        f"scapy 版本        : {info.scapy_version}",
        f"SCAPY_USE_LIBPCAP : {info.libpcap_pref_env}  (偏好，最终以下方检测为准)",
        f"conf.use_pcap     : {info.use_pcap}",
        f"conf.use_bpf      : {info.use_bpf}",
        f"L2listen 类       : {info.l2listen}",
        f"L2socket 类       : {info.l2socket}",
        f"实际后端判定      : {verdict}",
    ]
    return "\n".join(lines)
