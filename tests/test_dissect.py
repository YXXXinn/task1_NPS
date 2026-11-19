"""无头单元测试（纯逻辑，无需 PySide6/root）：协议分层解析 + hex 格式化。

覆盖：
1. dissect_layers 对 Ether/IP/TCP、IPv6/UDP、ICMP、ARP 的分层层级与关键字段；
2. 不做应用层识别：TCP 80 端口不会出现 HTTP 层，层名只在链路/网络/传输层集合内；
3. format_hex_dump 对已知字节串输出正确的偏移/hex/ASCII 对齐与不可见字符替换。

运行：python tests/test_dissect.py  （退出码 0 表示通过）
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from sniffer.gui.dissect import dissect_layers, format_hex_dump

_fail = 0


def check(cond, msg):
    global _fail
    if not cond:
        _fail += 1
    print(f"[{'ok  ' if cond else 'FAIL'}] {msg}")


def _names(pkt):
    return [l.name for l in dissect_layers(pkt)]


def _fields(pkt, layer_name):
    for l in dissect_layers(pkt):
        if l.name == layer_name:
            return dict(l.fields)
    return {}


def main():
    eth = {"src": "aa:bb:cc:dd:ee:01", "dst": "aa:bb:cc:dd:ee:02"}
    allowed = {"Ethernet", "IP", "IPv6", "TCP", "UDP", "ICMP", "ARP", "Raw", "Padding"}

    # Ether/IP/TCP
    tcp = Ether(**eth) / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=12345, dport=80, flags="S")
    names = _names(tcp)
    check(names[:3] == ["Ethernet", "IP", "TCP"], f"Ether/IP/TCP 分层顺序正确: {names}")
    check(set(names) <= allowed, f"不含应用层识别(层名在基础集合内): {names}")
    check("HTTP" not in names, "TCP 80 端口未臆断出 HTTP 层")
    ipf = _fields(tcp, "IP")
    check(ipf.get("src") == "1.1.1.1" and ipf.get("dst") == "2.2.2.2", "IP 源/目的字段正确")
    tf = _fields(tcp, "TCP")
    check(tf.get("sport") == "12345" and tf.get("dport") == "80", f"TCP 端口字段正确: {tf.get('sport')}/{tf.get('dport')}")
    check("S" in tf.get("flags", ""), f"TCP 标志位含 SYN: flags={tf.get('flags')}")

    # IPv6/UDP
    u6 = Ether(**eth) / IPv6(src="::1", dst="::2") / UDP(sport=5353, dport=53)
    n6 = _names(u6)
    check(n6[:3] == ["Ethernet", "IPv6", "UDP"], f"Ether/IPv6/UDP 分层顺序正确: {n6}")
    check(_fields(u6, "UDP").get("dport") == "53", "UDP dport 字段正确")

    # ICMP
    icmp = Ether(**eth) / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()
    check("ICMP" in _names(icmp), f"ICMP 层存在: {_names(icmp)}")

    # ARP
    arp = Ether(**eth) / ARP(psrc="10.0.0.1", pdst="10.0.0.2")
    check("ARP" in _names(arp), f"ARP 层存在: {_names(arp)}")
    af = _fields(arp, "ARP")
    check(af.get("psrc") == "10.0.0.1" and af.get("pdst") == "10.0.0.2", "ARP psrc/pdst 字段正确")

    # format_hex_dump：18 字节 -> 两行；偏移/hex/ascii 对齐
    data = bytes(range(18))  # 00..11
    dump = format_hex_dump(data, width=16)
    lines = dump.split("\n")
    check(len(lines) == 2, f"18 字节按宽 16 分 2 行: {len(lines)}")
    check(lines[0].startswith("00000000  "), "第一行偏移为 00000000")
    check(lines[0][10:10 + 47] == " ".join(f"{b:02x}" for b in range(16)), "第一行 hex 段正确")
    check(lines[0].endswith("................"), "第一行 ASCII 全为不可见→'.'")
    check(lines[1].startswith("00000010  "), "第二行偏移为 00000010")

    # 可见/不可见混合
    d2 = format_hex_dump(b"AB\x00\xff", width=16)
    check(d2.endswith("AB.."), f"可见字符保留、不可见替换为'.': {d2!r}")
    check(format_hex_dump(b"") == "", "空字节返回空串")

    print(f"\n结果：{'全部通过' if _fail == 0 else str(_fail) + ' 项失败'}")
    return 1 if _fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
