"""无头单元测试（纯逻辑，无需 PySide6/root）：TCP 流追踪 tcpflow。

覆盖：
1. flow_key：A→B 与 B→A 归同一键；不同会话不同键；非 TCP(UDP/ICMP) → None。
2. FlowIndex：同会话同流ID、不同会话不同ID、双向计数/字节、seqs 收集。
3. 有界：max_flows 超限按 LRU 淘汰最旧流；max_pkts_per_flow 超限丢最旧 seq。
4. reassemble：双向已知载荷按方向+顺序重组正确、无载荷包跳过；format_stream 方向前缀。

运行：python tests/test_tcpflow.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from sniffer.gui.packet_model import packet_to_record
from sniffer.gui.tcpflow import (
    FlowIndex,
    flow_key,
    format_flow_summary,
    format_stream,
    reassemble,
)

_fail = 0
_E = {"src": "aa:bb:cc:dd:ee:01", "dst": "aa:bb:cc:dd:ee:02"}


def check(cond, msg):
    global _fail
    if not cond:
        _fail += 1
    print(f"[{'ok  ' if cond else 'FAIL'}] {msg}")


def rec(sip, sp, dip, dp, seq, payload=b""):
    p = Ether(**_E) / IP(src=sip, dst=dip) / TCP(sport=sp, dport=dp)
    if payload:
        p = p / Raw(load=payload)
    return packet_to_record(p, seq)


def main():
    # 1) flow_key 方向无关
    ab = rec("10.0.0.1", 1111, "10.0.0.2", 2222, 1, b"hello-from-A")
    ba = rec("10.0.0.2", 2222, "10.0.0.1", 1111, 2, b"reply-from-B")
    other = rec("10.0.0.3", 3333, "10.0.0.4", 4444, 3)
    check(flow_key(ab) == flow_key(ba), "A→B 与 B→A 归为同一会话键")
    check(flow_key(ab) != flow_key(other), "不同会话 → 不同键")

    udp = packet_to_record(Ether(**_E) / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=5, dport=53), 4)
    icmp = packet_to_record(Ether(**_E) / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(), 5)
    check(flow_key(udp) is None and flow_key(icmp) is None, "非 TCP(UDP/ICMP) → 无流键")

    # 2) FlowIndex 归并 + 双向计数
    idx = FlowIndex()
    id1 = idx.add(ab)
    id1b = idx.add(ba)
    id2 = idx.add(other)
    check(id1 == id1b and id1 != id2, "同会话同流ID、不同会话不同ID")
    check(idx.add(udp) is None, "FlowIndex.add 非 TCP 返回 None")
    flow = idx.get(id1)
    check(flow.total_pkts == 2 and flow.pkts_ab == 1 and flow.pkts_ba == 1, "双向包数统计正确")
    check(flow.bytes_ab > 0 and flow.bytes_ba > 0, "双向字节统计 > 0")
    check(sorted(idx.seqs_of(id1)) == [1, 2], f"流的 seq 收集正确: {idx.seqs_of(id1)}")
    check("10.0.0.1:1111 ↔ 10.0.0.2:2222" in format_flow_summary(flow), "流概要含两端 ip:port")

    # 3a) 有界：max_flows LRU 淘汰最旧流
    idxf = FlowIndex(max_flows=2)
    s1 = rec("10.0.0.1", 1, "10.0.0.2", 2, 10)
    s2 = rec("10.0.0.3", 3, "10.0.0.4", 4, 11)
    s3 = rec("10.0.0.5", 5, "10.0.0.6", 6, 12)
    idxf.add(s1); idxf.add(s2); idxf.add(s3)
    check(idxf.flow_count() == 2, f"max_flows=2 时流数封顶=2（实际 {idxf.flow_count()}）")
    check(idxf.id_of(s1) is None, "最旧流(s1)被 LRU 淘汰")
    check(idxf.id_of(s3) is not None, "最新流(s3)保留")

    # 3b) 有界：max_pkts_per_flow 丢最旧 seq
    idxp = FlowIndex(max_pkts_per_flow=2)
    for s in (20, 21, 22):
        idxp.add(rec("10.0.0.1", 1111, "10.0.0.2", 2222, s))
    fid = idxp.id_of(rec("10.0.0.1", 1111, "10.0.0.2", 2222, 99))
    check(idxp.seqs_of(fid) == [21, 22], f"每流 seq 上限=2，保留最近两个: {idxp.seqs_of(fid)}")
    check(idxp.get(fid).total_pkts == 3, "但总包数计数仍为 3（计数不因 seq 淘汰而减）")

    # 4) reassemble：方向 + 顺序；无载荷包跳过
    ab2 = rec("10.0.0.1", 1111, "10.0.0.2", 2222, 6, b"second-from-A")
    ack = rec("10.0.0.2", 2222, "10.0.0.1", 1111, 7)  # 无载荷
    endpoints = flow_key(ab)
    segs = reassemble([ab, ba, ab2, ack], endpoints)
    check([s.direction for s in segs] == ["A->B", "B->A", "A->B"], f"方向序列正确: {[s.direction for s in segs]}")
    check(segs[0].data == b"hello-from-A" and segs[1].data == b"reply-from-B", "各方向载荷内容正确")
    check(len(segs) == 3, "无载荷(纯 ACK)包被跳过")
    text = format_stream(segs, endpoints, as_hex=False)
    check("A→B| hello-from-A" in text and "B→A| reply-from-B" in text, "format_stream 方向前缀正确")
    hx = format_stream(segs, endpoints, as_hex=True)
    check("A→B" in hx and "68 65 6c 6c 6f" in hx, "hex 视图含方向与十六进制载荷")

    print(f"\n结果：{'全部通过' if _fail == 0 else str(_fail) + ' 项失败'}")
    return 1 if _fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
