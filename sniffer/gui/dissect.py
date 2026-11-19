"""协议分层解析 + 十六进制/ASCII 格式化（纯逻辑，**不依赖 PySide6**）。

设计要点：
- 这里只「如实反映 scapy 已经解析出的层栈」，逐层列字段，**不做任何应用层识别**，
  不根据端口臆断协议（不会把 TCP:80 标成 HTTP）。显示什么层，取决于 scapy 自身的
  dissection 结果（packet 沿 .payload 链遍历）。
- 写成纯函数，便于用合成包做无头单元测试；GUI 层只负责把结果塞进 QTreeWidget / 文本框。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from scapy.packet import NoPayload, Raw

_MAX_LAYERS = 64  # 防御性上限，避免异常包导致的超长/环状遍历


@dataclass
class LayerInfo:
    """一层协议的展示信息：层名 + (字段名, 字段值字符串) 列表。"""

    name: str
    fields: List[Tuple[str, str]] = field(default_factory=list)


def _field_repr(layer, fld) -> str:
    """得到人类可读的字段值字符串。

    端口字段（sport/dport）一律显示**数字**，不走 scapy 的服务名映射
    （scapy 的 i2repr 会把 80→'http'、53→'domain'，那属于端口→应用层的臆断，
    与实验纪律冲突，本阶段也不做应用层识别）。其余字段用 scapy 的 i2repr
    以保留 flags（如 'S'）、地址等可读形式。
    """
    try:
        val = layer.getfieldval(fld.name)
    except Exception:
        return "?"
    if fld.name in ("sport", "dport"):
        try:
            return str(int(val))
        except Exception:
            return str(val)
    try:
        return str(fld.i2repr(layer, val))
    except Exception:
        try:
            return str(val)
        except Exception:
            return "?"


def dissect_layers(pkt) -> List[LayerInfo]:
    """沿 .payload 链逐层解析，返回每层的字段列表。

    仅反映 scapy 的 dissection，不附加任何应用层判定。
    """
    layers: List[LayerInfo] = []
    cur = pkt
    count = 0
    while cur is not None and not isinstance(cur, NoPayload) and count < _MAX_LAYERS:
        count += 1
        name = getattr(cur, "name", cur.__class__.__name__)
        fields: List[Tuple[str, str]] = []

        if isinstance(cur, Raw):
            # 未被进一步解析的载荷：只给长度与字节，不猜测其应用层含义。
            load = getattr(cur, "load", b"") or b""
            fields.append(("load_len", str(len(load))))
            fields.append(("load", repr(bytes(load)[:64]) + ("…" if len(load) > 64 else "")))
        else:
            for fld in getattr(cur, "fields_desc", []):
                fields.append((fld.name, _field_repr(cur, fld)))

        layers.append(LayerInfo(name=name, fields=fields))
        cur = cur.payload

    return layers


def format_hex_dump(data: bytes, width: int = 16) -> str:
    """把原始字节格式化成「偏移 | 十六进制 | ASCII」三段，等宽对齐。

    不可见字节（<0x20 或 >=0x7f）在 ASCII 段用 '.' 表示。
    """
    if not data:
        return ""
    lines: List[str] = []
    hex_col_width = width * 3 - 1  # 每字节 "xx " 占 3，最后一个无尾空格
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(hex_col_width)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        lines.append(f"{off:08x}  {hex_part}  {ascii_part}")
    return "\n".join(lines)
