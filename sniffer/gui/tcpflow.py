"""基于 IP + Port 的 TCP 流追踪（Follow TCP Stream）——纯逻辑，**不依赖 PySide6**。

范围：只按 {IP, Port} 两端做**方向无关**的会话归并；**不做按进程归流**。

设计：
- flow_key(rec)：把一个 TCP 记录映射到**规范化会话键**——取两端 (ip, port) 排序，
  A→B 与 B→A 归为同一键；非 TCP / 缺端口 → None。
- FlowIndex：会话键→流ID、流ID→该流的包序号(seq)列表 + 双向计数。**内存有界**：
  流数量上限（超限淘汰最久未活跃的流 LRU）、每条流只存最近 N 个 seq（deque maxlen），
  且只存 int(seq) 与计数，不持有大对象 —— 与 PacketTableModel 的 _all 有界缓存协调。
- reassemble/format_stream：把一条流的 TCP 载荷按方向、按抓包顺序拼接展示（从简但正确）。

写成纯函数 + 轻量状态类，便于无头单元测试。
"""
from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

Endpoint = Tuple[str, int]
FlowKey = Tuple[Endpoint, Endpoint]


def flow_key(rec) -> Optional[FlowKey]:
    """TCP 记录 → 规范化会话键（方向无关）；非 TCP 或缺端口 → None。"""
    if getattr(rec, "proto", None) != "TCP":
        return None
    sp, dp = getattr(rec, "sport", None), getattr(rec, "dport", None)
    if sp is None or dp is None:
        return None
    a: Endpoint = (str(rec.src), int(sp))
    b: Endpoint = (str(rec.dst), int(dp))
    return tuple(sorted((a, b)))  # 排序 → 两个方向得到同一键


@dataclass
class Flow:
    id: int
    key: FlowKey
    endpoints: FlowKey                     # == key，(A, B)，A=较小端点
    seqs: deque = field(default_factory=deque)  # 该流的包序号（最近 N 个，有界）
    pkts_ab: int = 0
    pkts_ba: int = 0
    bytes_ab: int = 0
    bytes_ba: int = 0

    @property
    def total_pkts(self) -> int:
        return self.pkts_ab + self.pkts_ba


class FlowIndex:
    """有界的 TCP 流索引。

    - max_flows：最多同时跟踪的流数；超限按 LRU 淘汰最久未活跃的流。
    - max_pkts_per_flow：每条流最多保留的 seq 数（deque maxlen，超限丢最旧的 seq）。
      注意：pkts_*/bytes_* 计数反映**全部**出现过的包；seqs 只保留最近的一段样本。
    """

    def __init__(self, max_flows: int = 4096, max_pkts_per_flow: int = 10000) -> None:
        self._key_to_id: dict = {}
        self._flows: "OrderedDict[int, Flow]" = OrderedDict()
        self._next_id = 1
        self._max_flows = max_flows
        self._max_pkts = max_pkts_per_flow

    def add(self, rec) -> Optional[int]:
        """把一个记录并入其会话；返回流ID；非 TCP 返回 None。"""
        key = flow_key(rec)
        if key is None:
            return None
        fid = self._key_to_id.get(key)
        if fid is None:
            if len(self._flows) >= self._max_flows:
                old_id, old_flow = self._flows.popitem(last=False)  # 淘汰最久未活跃
                self._key_to_id.pop(old_flow.key, None)
            fid = self._next_id
            self._next_id += 1
            flow = Flow(id=fid, key=key, endpoints=key,
                        seqs=deque(maxlen=self._max_pkts))
            self._flows[fid] = flow
            self._key_to_id[key] = fid
        else:
            flow = self._flows[fid]
            self._flows.move_to_end(fid)  # 标记为最近活跃

        flow.seqs.append(int(rec.seq))
        if (str(rec.src), int(rec.sport)) == flow.endpoints[0]:
            flow.pkts_ab += 1
            flow.bytes_ab += int(rec.length)
        else:
            flow.pkts_ba += 1
            flow.bytes_ba += int(rec.length)
        return fid

    def id_of(self, rec) -> Optional[int]:
        key = flow_key(rec)
        return self._key_to_id.get(key) if key is not None else None

    def get(self, flow_id: int) -> Optional[Flow]:
        return self._flows.get(flow_id)

    def seqs_of(self, flow_id: int) -> List[int]:
        f = self._flows.get(flow_id)
        return list(f.seqs) if f else []

    def flow_count(self) -> int:
        return len(self._flows)


def format_flow_summary(flow: Flow) -> str:
    a, b = flow.endpoints
    return (f"{a[0]}:{a[1]} ↔ {b[0]}:{b[1]}  |  包数 {flow.total_pkts}"
            f"（A→B {flow.pkts_ab} / B→A {flow.pkts_ba}）"
            f"  |  字节 A→B {flow.bytes_ab} / B→A {flow.bytes_ba}")


# ---------------- 流内容重组（从简但正确）----------------

@dataclass
class StreamSegment:
    direction: str   # "A->B" / "B->A"
    data: bytes


def _tcp_payload(raw: bytes) -> bytes:
    """从原始帧字节解析出 TCP 载荷；非 TCP / 无载荷 → b""。"""
    if not raw:
        return b""
    from scapy.layers.inet import TCP
    from scapy.layers.l2 import Ether
    try:
        pkt = Ether(raw)
    except Exception:
        return b""
    if not pkt.haslayer(TCP):
        return b""
    return bytes(pkt[TCP].payload)


def reassemble(records, endpoints: FlowKey) -> List[StreamSegment]:
    """把一条流的记录（按抓包/seq 顺序）重组为带方向的载荷段。

    从简策略：**按抓包顺序 + 方向拼接**，跳过无载荷的包（纯 ACK/握手）。
    不处理 TCP 重传/乱序/缺包补零（见 README 与报告「已知限制」）。
    """
    a = endpoints[0]
    segs: List[StreamSegment] = []
    for rec in records:
        payload = _tcp_payload(getattr(rec, "raw", b""))
        if not payload:
            continue
        direction = "A->B" if (str(rec.src), int(rec.sport)) == a else "B->A"
        segs.append(StreamSegment(direction, payload))
    return segs


def format_stream(segments: List[StreamSegment], endpoints: FlowKey, as_hex: bool = False) -> str:
    """把重组段渲染成文本：A→B / B→A 分别加前缀区分方向。"""
    a, b = endpoints
    out = [f"A = {a[0]}:{a[1]}    B = {b[0]}:{b[1]}",
           "（方向前缀：A→B / B→A；本视图按抓包顺序拼接，未做完整 TCP 重排）", ""]
    if not segments:
        out.append("<该流无应用层载荷（可能只有握手/ACK）>")
        return "\n".join(out)
    for seg in segments:
        prefix = "A→B" if seg.direction == "A->B" else "B→A"
        if as_hex:
            from sniffer.gui.dissect import format_hex_dump
            body = "\n".join("    " + ln for ln in format_hex_dump(seg.data).split("\n"))
            out.append(f"[{prefix}] ({len(seg.data)} 字节)\n{body}")
        else:
            text = seg.data.decode("utf-8", "replace")
            out.append("\n".join(f"{prefix}| {ln}" for ln in text.split("\n")))
    return "\n".join(out)

