"""应用层类型「审慎推测」（纯逻辑，**不依赖 PySide6**）。

核心纪律（实验第 9 页思考题考点）：
- **不得仅凭端口号断定应用层协议**。端口只能作为「提示」。
- 判定必须结合**载荷特征**（HTTP 请求行/响应行、TLS record 头、DNS 结构）。
- 所有结论都是「推测」，并记录判定依据；端口与载荷不一致时如实标注。

返回 AppGuess：{label, confidence, port_hint_only, evidence[], notes[]}，
GUI 只负责展示，判定逻辑全在这里，便于用合成包无头测试。

本阶段只做三类最具代表性的：HTTP、TLS/HTTPS 握手、DNS（结构）。识别不出就是「未识别」。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from scapy.layers.inet import TCP, UDP

# 端口只作「提示」，绝不作为判定证据。
_PORT_HINTS = {80: "HTTP", 8080: "HTTP", 443: "TLS", 8443: "TLS", 53: "DNS"}

_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                 b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT ")


@dataclass
class AppGuess:
    label: str = ""                 # "HTTP"/"TLS"/"DNS"/"" (未识别)
    confidence: str = "none"        # high(载荷证实) / low(仅端口提示) / none
    port_hint_only: bool = False    # True=只有端口提示、载荷未证实
    evidence: List[str] = field(default_factory=list)  # 载荷依据
    notes: List[str] = field(default_factory=list)     # 端口提示 / 一致性说明

    def display(self) -> str:
        """详情节点标题用的人类可读结论（始终带「推测」字样）。"""
        if self.label and not self.port_hint_only:
            return f"疑似 {self.label}（推测，依据载荷）"
        if self.port_hint_only:
            return "未识别（仅端口提示，载荷未证实）"
        return "未识别"

    def short(self) -> str:
        """列表「协议」列可选追加的简短标注；只在载荷证实时给，且带问号。"""
        if self.label and not self.port_hint_only:
            return f"疑似{self.label}?"
        return ""


def _first_line(payload: bytes) -> bytes:
    return payload.split(b"\r\n", 1)[0][:128]


def _match_tls(payload: bytes) -> bool:
    """TLS record 头：content_type ∈ {0x14..0x17} 且 version 0x03 0x0X。"""
    if len(payload) < 3:
        return False
    return (payload[0] in (0x14, 0x15, 0x16, 0x17)
            and payload[1] == 0x03
            and payload[2] in (0x00, 0x01, 0x02, 0x03, 0x04))


def _match_http_request(payload: bytes):
    head = payload[:256]
    if payload.startswith(_HTTP_METHODS) and b" HTTP/1." in head:
        return _first_line(payload)
    return None


def _match_http_response(payload: bytes):
    if payload.startswith(b"HTTP/1."):
        return _first_line(payload)
    return None


def _hint_consistent(hint: str, label: str) -> bool:
    return hint == label  # _PORT_HINTS 的取值已与 label 对齐（HTTP/TLS/DNS）


def identify_app(pkt) -> AppGuess:
    """对已解析的 scapy 包做应用层审慎推测。"""
    if pkt.haslayer(TCP):
        layer = pkt[TCP]
    elif pkt.haslayer(UDP):
        layer = pkt[UDP]
    else:
        return AppGuess(notes=["非 TCP/UDP，未做应用层推测"])

    sport, dport = int(layer.sport), int(layer.dport)
    payload = bytes(layer.payload)
    g = AppGuess()

    # 1) 先看载荷特征（载荷优先于端口）
    if _match_tls(payload):
        g.label, g.confidence = "TLS", "high"
        g.evidence.append(
            f"TLS record 头: type=0x{payload[0]:02x}, version=0x03 0x{payload[2]:02x}"
            + ("（0x16=Handshake" + ("，疑似 ClientHello)" if len(payload) > 5 and payload[5] == 0x01 else ")")
               if payload[0] == 0x16 else ")"))
    else:
        req = _match_http_request(payload)
        resp = None if req else _match_http_response(payload)
        if req is not None:
            g.label, g.confidence = "HTTP", "high"
            g.evidence.append(f"HTTP 请求行: {req!r}")
        elif resp is not None:
            g.label, g.confidence = "HTTP", "high"
            g.evidence.append(f"HTTP 响应行: {resp!r}")
        elif pkt.haslayer("DNS"):
            g.label, g.confidence = "DNS", "high"
            dns = pkt.getlayer("DNS")
            g.evidence.append(f"scapy 解析出 DNS 结构: id={getattr(dns, 'id', '?')}, "
                              f"qd={getattr(dns, 'qdcount', '?')}, an={getattr(dns, 'ancount', '?')}")

    # 2) 端口仅作提示，并标注一致/冲突
    hint = _PORT_HINTS.get(dport) or _PORT_HINTS.get(sport)
    hinted_port = dport if dport in _PORT_HINTS else (sport if sport in _PORT_HINTS else None)

    if g.label:
        if hint and _hint_consistent(hint, g.label):
            g.notes.append(f"端口 {hinted_port} 的常见用途({hint})与载荷判定一致")
        elif hint:
            g.notes.append(f"注意：端口 {hinted_port} 常见为 {hint}，但载荷特征判定为 "
                           f"{g.label} —— 以载荷为准（端口不是证据）")
        else:
            g.notes.append(f"端口非常规，纯凭载荷特征判定为 {g.label}")
    else:
        if hint:
            g.port_hint_only, g.confidence = True, "low"
            g.notes.append(f"端口提示：{hinted_port} 常见于 {hint}，但载荷未见其特征 → 不予断定")
        else:
            g.notes.append("端口与载荷均无明显特征")

    return g
