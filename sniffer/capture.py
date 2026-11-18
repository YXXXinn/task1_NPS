"""最小抓包验证程序。

本阶段目标：证明「能在指定网卡上抓到包」，并把权限问题讲清楚。
协议解析、GUI、有界缓存等留给后续阶段。

过滤概念（务必与 GUI 显示过滤区分）：
- 这里的 ``bpf_filter`` 是 BPF 抓包过滤，内核层生效，直接传给 Scapy 的
  ``filter=`` 参数（语法同 tcpdump，如 "tcp port 80"）。不匹配的包在内核就被丢弃，
  根本不会进入用户态。
- 后续 GUI 阶段的「显示过滤」则是在「已经抓到的包」上做界面筛选，属于用户态、
  可反复开关，二者层级与时机完全不同。
"""
from __future__ import annotations

from typing import Callable, List, Optional


class CapturePermissionError(RuntimeError):
    """抓包权限不足（通常是非 root 打开 /dev/bpf* 或 pcap 句柄失败）。"""


def capture(
    iface: Optional[str] = None,
    count: int = 0,
    timeout: Optional[float] = None,
    bpf_filter: Optional[str] = None,
    prn: Optional[Callable] = None,
) -> List:
    """在指定网卡上抓包并返回包列表。

    参数
    ----
    iface      : 网卡名（如 "en0"）。None 表示交给 Scapy 选默认网卡。
    count      : 抓包数量，0 表示不限（需配合 timeout 或 Ctrl-C）。
    timeout    : 超时秒数，到点即停。
    bpf_filter : BPF 抓包过滤表达式（内核层），语法同 tcpdump。
    prn        : 每抓到一个包调用的回调，签名 prn(packet)。

    抓包需要足够权限（见下方异常处理）。本函数把常见的权限错误统一翻译成
    CapturePermissionError，并给出清晰的 sudo 提示。
    """
    from scapy.all import sniff

    try:
        packets = sniff(
            iface=iface,
            count=count,
            timeout=timeout,
            filter=bpf_filter,
            prn=prn,
            store=True,
        )
        return list(packets)
    except (PermissionError, OSError) as exc:
        # macOS 非 root 打开 BPF/pcap 句柄时，常见 errno 1 (Operation not permitted)
        # 或 errno 13 (Permission denied)。统一提示如何获得权限。
        raise CapturePermissionError(
            f"抓包失败，疑似权限不足：{exc}\n"
            f"macOS 上抓包需要访问 /dev/bpf* 设备，通常要 root 权限。\n"
            f"请用 sudo 运行，例如：\n"
            f"    sudo .venv/bin/python -m sniffer capture -i {iface or 'en0'} -c 5 -t 10\n"
            f"（注意：要用 venv 里的解释器，sudo 下系统默认 python 可能找不到 scapy）"
        ) from exc
