"""无头单元测试：用合成数据包验证纯逻辑（不需要 root、不需要 GUI）。

覆盖：
1. classify_protocol / packet_to_record 对 TCP/UDP/ICMP/ARP/IPv6 的判定与字段提取；
2. 不根据端口推断应用层（80 端口仍判为 TCP，而非 HTTP）；
3. BoundedPacketBuffer 满了丢最旧、drain 批量聚合、dropped 计数。

运行：python tests/test_packet_model.py   （退出码 0 表示通过）
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from sniffer.gui.packet_model import (
    BoundedPacketBuffer,
    PacketRecord,
    classify_protocol,
    packet_to_record,
)

_fail = 0


def check(cond, msg):
    global _fail
    status = "ok  " if cond else "FAIL"
    if not cond:
        _fail += 1
    print(f"[{status}] {msg}")


def main():
    # 1) 协议判定（合成包）。显式给 Ether 源/目的 MAC，避免 scapy 触发 ARP 地址解析告警。
    eth = {"src": "aa:bb:cc:dd:ee:01", "dst": "aa:bb:cc:dd:ee:02"}
    tcp = Ether(**eth) / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=12345, dport=80)
    udp = Ether(**eth) / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=53, dport=53)
    icmp = Ether(**eth) / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()
    arp = Ether(**eth) / ARP(psrc="10.0.0.1", pdst="10.0.0.2")
    v6 = Ether(**eth) / IPv6(src="::1", dst="::2") / TCP(sport=1, dport=443)

    check(classify_protocol(tcp) == "TCP", "TCP 包判定为 TCP")
    check(classify_protocol(udp) == "UDP", "UDP 包判定为 UDP")
    check(classify_protocol(icmp) == "ICMP", "ICMP 包判定为 ICMP")
    check(classify_protocol(arp) == "ARP", "ARP 包判定为 ARP")
    check(classify_protocol(v6) == "TCP", "IPv6+TCP 判定为 TCP")

    # 2) 不根据端口推断应用层：80/443 端口仍是 TCP，不是 HTTP/HTTPS
    check(classify_protocol(tcp) != "HTTP", "80 端口不被臆断为 HTTP（协议判定审慎）")

    # 3) packet_to_record 字段提取
    rec = packet_to_record(tcp, seq=7)
    check(isinstance(rec, PacketRecord), "packet_to_record 返回 PacketRecord")
    check(rec.seq == 7, "序号正确")
    check(rec.src == "1.1.1.1" and rec.dst == "2.2.2.2", "源/目的 IP 正确")
    check(rec.proto == "TCP", "记录协议列为 TCP")
    check(rec.length == len(tcp), "长度等于包字节数")
    check(packet_to_record(arp, 1).src == "10.0.0.1", "ARP 取 psrc 作为源")

    # 4) 有界缓存：满丢最旧 + drain 聚合 + dropped 计数
    buf = BoundedPacketBuffer(maxlen=3)
    for i in range(1, 6):  # 放 5 个，容量 3 → 丢最旧 2 个
        buf.append(packet_to_record(tcp, seq=i))
    check(len(buf) == 3, "缓冲长度封顶为 maxlen=3")
    check(buf.dropped == 2, "丢弃计数为 2")
    drained = buf.drain()
    check([r.seq for r in drained] == [3, 4, 5], "drain 返回最新 3 个(3,4,5)，最旧(1,2)已丢")
    check(len(buf) == 0 and buf.drain() == [], "drain 后缓冲清空")

    print(f"\n结果：{'全部通过' if _fail == 0 else str(_fail) + ' 项失败'}")
    return 1 if _fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
