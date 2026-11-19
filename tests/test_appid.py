"""无头单元测试（纯逻辑，无需 PySide6/root）：应用层审慎推测 appid.identify_app。

重点验证实验纪律「端口≠应用层证据」，含**反例**：
- 80 端口真实 HTTP 请求 → 疑似 HTTP（有请求行依据）
- 443 端口 TLS ClientHello(0x16 0x03..) → 疑似 TLS
- 反例：443 端口普通字节 → 不判成 TLS（仅端口提示、载荷未证实）
- 反例：80 端口放 TLS 字节 → 按载荷判 TLS 而非 HTTP（端口不是证据）
- DNS（结构）→ 疑似 DNS
- 非 TCP/UDP → 未识别

运行：python tests/test_appid.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from sniffer.gui.appid import identify_app

_fail = 0
_ETH = {"src": "aa:bb:cc:dd:ee:01", "dst": "aa:bb:cc:dd:ee:02"}


def check(cond, msg):
    global _fail
    if not cond:
        _fail += 1
    print(f"[{'ok  ' if cond else 'FAIL'}] {msg}")


def _tcp(sport, dport, payload):
    return Ether(**_ETH) / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=sport, dport=dport) / Raw(load=payload)


def main():
    # 1) 80 端口真实 HTTP 请求
    http = _tcp(50000, 80, b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
    g = identify_app(http)
    check(g.label == "HTTP" and not g.port_hint_only, f"HTTP 请求判为 HTTP: label={g.label}")
    check(any("HTTP 请求行" in e for e in g.evidence), f"HTTP 判定有请求行依据: {g.evidence}")
    check(g.confidence == "high", "HTTP 置信度 high")

    # 2) 443 端口 TLS ClientHello
    tls = _tcp(50001, 443, bytes([0x16, 0x03, 0x01, 0x00, 0x50, 0x01]) + b"\x00" * 40)
    g = identify_app(tls)
    check(g.label == "TLS" and not g.port_hint_only, f"TLS ClientHello 判为 TLS: label={g.label}")
    check(any("TLS record" in e for e in g.evidence), f"TLS 判定有 record 头依据: {g.evidence}")

    # 3) 反例：443 端口普通字节 → 不判 TLS
    notls = _tcp(50002, 443, b"hello world, just plain text, definitely not tls")
    g = identify_app(notls)
    check(g.label != "TLS", f"443 上普通字节不被判成 TLS（label={g.label!r}）")
    check(g.port_hint_only and g.label == "", "443 普通字节：仅端口提示、未识别")
    check(any("未见其特征" in n or "未证实" in n for n in g.notes), f"标注了端口提示但未证实: {g.notes}")

    # 4) 反例：80 端口放 TLS 字节 → 按载荷判 TLS 而非 HTTP
    tls_on_80 = _tcp(50003, 80, bytes([0x16, 0x03, 0x03, 0x00, 0x30, 0x01]) + b"\x00" * 20)
    g = identify_app(tls_on_80)
    check(g.label == "TLS", f"80 端口 TLS 字节按载荷判为 TLS（非 HTTP）: label={g.label}")
    check(any("以载荷为准" in n or "载荷特征判定" in n for n in g.notes),
          f"标注端口(80)与载荷(TLS)冲突、以载荷为准: {g.notes}")

    # 5) DNS（结构）
    dns = (Ether(**_ETH) / IP(src="1.1.1.1", dst="2.2.2.2")
           / UDP(sport=50004, dport=53) / DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com")))
    g = identify_app(dns)
    check(g.label == "DNS", f"DNS 结构判为 DNS: label={g.label}")
    check(any("DNS 结构" in e for e in g.evidence), f"DNS 判定有结构依据: {g.evidence}")

    # 6) 非 TCP/UDP
    icmp = Ether(**_ETH) / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()
    g = identify_app(icmp)
    check(g.label == "" and not g.port_hint_only, "ICMP(非 TCP/UDP) → 未识别")

    # 7) display()/short() 始终带「推测」且不像确证
    g = identify_app(http)
    check("推测" in g.display(), f"display 含「推测」: {g.display()}")
    check(g.short().endswith("?"), f"short 带问号: {g.short()}")

    print(f"\n结果：{'全部通过' if _fail == 0 else str(_fail) + ' 项失败'}")
    return 1 if _fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
