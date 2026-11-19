"""数据包到「展示记录」的纯逻辑转换 + 有界缓存。

本模块**不依赖 PySide6**，只依赖 scapy，方便用合成包做无头单元测试。
GUI 层（capture_worker / main_window）再在其上包一层 Qt。

协议判定原则（严格遵守实验纪律）：
- 只做链路层 / 网络层 / 传输层的基础标识（Ether/ARP/IPv4/IPv6/TCP/UDP/ICMP/ICMPv6）。
- **不**根据端口号推断应用层协议（如不把 80 端口判定为 HTTP）。应用层判定留到
  后续阶段并需结合载荷特征，届时也要标注「推测」。
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import List, Optional

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether


@dataclass
class PacketRecord:
    """一个数据包在 Packet List 里需要展示的最小字段集合。"""

    seq: int          # 序号（抓包顺序，从 1 开始）——稳定标识，用于选中行映射到包
    ts: float         # 抓包时间戳（epoch 秒）
    time_str: str     # 格式化时间 HH:MM:SS.mmm
    src: str          # 源（IP / MAC / ARP 地址）
    dst: str          # 目的
    proto: str        # 协议标识（仅链路/网络/传输层）
    length: int       # 包长度（字节）
    summary: str      # scapy summary()，调试用
    raw: bytes = b""  # 原始字节（bytes(pkt)）——供详情树/hex 视图使用
    sport: Optional[int] = None  # 源端口（TCP/UDP），供显示过滤
    dport: Optional[int] = None  # 目的端口（TCP/UDP），供显示过滤
    l3: str = ""      # 网络层族：IPv4 / IPv6 / ARP / ""，供显示过滤区分 ip/ipv6
    app: object = None  # 应用层推测 AppGuess（审慎、带依据）；None=未计算



def _fmt_time(ts: float) -> str:
    local = time.localtime(ts)
    ms = int((ts - int(ts)) * 1000)
    return f"{time.strftime('%H:%M:%S', local)}.{ms:03d}"


def classify_protocol(pkt) -> str:
    """仅依据链路/网络/传输层判定协议标识，不碰应用层、不看端口。"""
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(IP):
        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        if pkt.haslayer(ICMP):
            return "ICMP"
        return "IPv4"
    if pkt.haslayer(IPv6):
        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        # ICMPv6 有多种类型，这里统一标识为 ICMPv6
        if pkt.haslayer("ICMPv6EchoRequest") or pkt.haslayer("ICMPv6EchoReply") \
                or pkt.haslayer("ICMPv6ND_NS") or pkt.haslayer("ICMPv6ND_NA") \
                or pkt.haslayer("ICMPv6ND_RS") or pkt.haslayer("ICMPv6ND_RA"):
            return "ICMPv6"
        return "IPv6"
    if pkt.haslayer(Ether):
        return "Ether"
    return pkt.__class__.__name__ or "Other"


def _src_dst(pkt):
    """按层次取源/目的地址：IP 优先，其次 ARP，再次链路层 MAC。"""
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    if pkt.haslayer(ARP):
        return pkt[ARP].psrc, pkt[ARP].pdst
    if pkt.haslayer(Ether):
        return pkt[Ether].src, pkt[Ether].dst
    return "-", "-"


def _l3_family(pkt) -> str:
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(IP):
        return "IPv4"
    if pkt.haslayer(IPv6):
        return "IPv6"
    return ""


def _ports(pkt):
    if pkt.haslayer(TCP):
        return int(pkt[TCP].sport), int(pkt[TCP].dport)
    if pkt.haslayer(UDP):
        return int(pkt[UDP].sport), int(pkt[UDP].dport)
    return None, None


def packet_to_record(pkt, seq: int) -> PacketRecord:
    """把一个 scapy 包转换成 PacketRecord（纯函数，便于单测）。

    连同原始字节 raw=bytes(pkt) 一起保存，供详情树/hex 视图使用。raw 的内存随
    PacketRecord 一起被有界结构（缓冲 maxlen / 表格行上限）约束，淘汰即释放。

    同时在子线程里一次性算好 sport/dport/l3（供显示过滤）与 app 应用层推测
    （审慎、带依据），列表列与详情节点复用，避免主线程重复解析。
    """
    from sniffer.gui.appid import identify_app

    ts = float(getattr(pkt, "time", None) or time.time())
    src, dst = _src_dst(pkt)
    try:
        summary = pkt.summary()
    except Exception:
        summary = pkt.__class__.__name__
    try:
        raw = bytes(pkt)
    except Exception:
        raw = b""
    sport, dport = _ports(pkt)
    try:
        app = identify_app(pkt)
    except Exception:
        app = None
    return PacketRecord(
        seq=seq,
        ts=ts,
        time_str=_fmt_time(ts),
        src=str(src),
        dst=str(dst),
        proto=classify_protocol(pkt),
        length=len(pkt),
        summary=summary,
        raw=raw,
        sport=sport,
        dport=dport,
        l3=_l3_family(pkt),
        app=app,
    )


class BoundedPacketBuffer:
    """有界缓存：满了丢最旧（drop-oldest），并统计丢弃数。

    不依赖 Qt。子线程把包 append 进来，GUI 定时 drain 批量取走。
    append/drain 都是 O(1)/O(k)，依赖 CPython GIL 保证 deque 操作的原子性。
    """

    def __init__(self, maxlen: int = 10000) -> None:
        self._buf: deque = deque()
        self._maxlen = maxlen
        self._dropped = 0

    def append(self, record: PacketRecord) -> None:
        if len(self._buf) >= self._maxlen:
            self._buf.popleft()
            self._dropped += 1
        self._buf.append(record)

    def drain(self) -> List[PacketRecord]:
        """取出当前所有缓存并清空，返回按时间顺序的列表。"""
        out: List[PacketRecord] = []
        buf = self._buf
        while buf:
            out.append(buf.popleft())
        return out

    @property
    def dropped(self) -> int:
        return self._dropped

    def __len__(self) -> int:
        return len(self._buf)
