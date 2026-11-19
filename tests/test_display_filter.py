"""无头单元测试（纯逻辑，无需 PySide6/root）：显示过滤 display_filter.compile_filter。

用合成包经 packet_to_record 生成记录（同时验证 proto/l3/sport/dport 填充正确），
再断言各显示过滤表达式的筛选结果；并测试空表达式=全显示、非法表达式抛 FilterError。

运行：python tests/test_display_filter.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from sniffer.gui.display_filter import FilterError, compile_filter
from sniffer.gui.packet_model import packet_to_record

_fail = 0
_ETH = {"src": "aa:bb:cc:dd:ee:01", "dst": "aa:bb:cc:dd:ee:02"}


def check(cond, msg):
    global _fail
    if not cond:
        _fail += 1
    print(f"[{'ok  ' if cond else 'FAIL'}] {msg}")


def main():
    pkts = {
        "tcp443": Ether(**_ETH) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=443),
        "tcp80":  Ether(**_ETH) / IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=2222, dport=80),
        "udp53":  Ether(**_ETH) / IP(src="10.0.0.5", dst="10.0.0.6") / UDP(sport=3333, dport=53),
        "icmp":   Ether(**_ETH) / IP(src="10.0.0.7", dst="10.0.0.8") / ICMP(),
        "arp":    Ether(**_ETH) / ARP(psrc="10.0.0.9", pdst="10.0.0.10"),
        "tcp6":   Ether(**_ETH) / IPv6(src="::1", dst="::2") / TCP(sport=4444, dport=8080),
    }
    recs = {k: packet_to_record(p, i) for i, (k, p) in enumerate(pkts.items(), 1)}

    # 先验证字段填充
    check(recs["tcp443"].l3 == "IPv4" and recs["tcp6"].l3 == "IPv6", "l3 族填充正确(IPv4/IPv6)")
    check(recs["tcp443"].dport == 443 and recs["udp53"].dport == 53, "sport/dport 填充正确")
    check(recs["arp"].l3 == "ARP", "ARP 的 l3 正确")

    def matched(expr):
        pred = compile_filter(expr)
        return {k for k, r in recs.items() if pred(r)}

    check(matched("") == set(recs), "空表达式 → 全部显示")
    check(matched("tcp") == {"tcp443", "tcp80", "tcp6"}, "tcp → 所有 TCP")
    check(matched("udp") == {"udp53"}, "udp → UDP")
    check(matched("icmp") == {"icmp"}, "icmp → ICMP")
    check(matched("arp") == {"arp"}, "arp → ARP")
    check(matched("ip") == {"tcp443", "tcp80", "udp53", "icmp"}, "ip → 所有 IPv4（不含 IPv6/ARP）")
    check(matched("ipv6") == {"tcp6"}, "ipv6 → IPv6")
    check(matched("tcp and port 443") == {"tcp443"}, "tcp and port 443 → 仅 tcp443")
    check(matched("port 53") == {"udp53"}, "port 53 → 源或目的端口 53")
    check(matched("dport==80") == {"tcp80"}, "dport==80 → tcp80")
    check(matched("ip==10.0.0.1") == {"tcp443"}, "ip==10.0.0.1 → 源或目的匹配")
    check(matched("src==10.0.0.3") == {"tcp80"}, "src==10.0.0.3 → tcp80")
    check(matched("tcp and port 443 or udp") == {"tcp443", "udp53"},
          "优先级 and>or：(tcp&443) or udp")
    check(matched("tcp and port!=443") == {"tcp80", "tcp6"}, "port!=443 取反正确")
    check(matched("ICMP or ARP") == {"icmp", "arp"}, "大小写不敏感 + or")

    # 非法/边界
    for bad in ("tcp and", "foobar", "port abc", "== 1.2.3.4"):
        try:
            compile_filter(bad)
            check(False, f"非法表达式应抛错: {bad!r}")
        except FilterError:
            check(True, f"非法表达式正确抛 FilterError: {bad!r}")

    print(f"\n结果：{'全部通过' if _fail == 0 else str(_fail) + ' 项失败'}")
    return 1 if _fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
