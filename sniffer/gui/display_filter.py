"""显示过滤（界面层，纯逻辑，**不依赖 PySide6**）。

与 BPF 抓包过滤的根本区别：
- BPF 抓包过滤在**内核层**，不匹配的包被直接丢弃、不可逆、不进用户态。
- 显示过滤在**界面层**，作用于**已经抓到的包**：不丢数据、可随时改/清空并立即重筛。

语法（本实现**真正支持**的子集，README 与此一致，不假装支持 Wireshark 全套）：
- 协议关键字：tcp | udp | icmp | arp | ip | ipv6
- 地址：  ip==<addr> | ip!=<addr> | src==<addr> | dst==<addr>   （ip 匹配源或目的）
- 端口：  port <n> | port==<n> | port!=<n> | sport==<n> | dport==<n>   （port 匹配源或目的）
- 组合：  用 and / or 连接，优先级 and 高于 or（无括号）。大小写不敏感。
- 空表达式 = 显示全部。
示例：`tcp`、`tcp and port 443`、`ip==172.22.124.230`、`udp and port 53`、`icmp or arp`

判定写成纯函数 compile_filter(text) -> predicate(PacketRecord)->bool，便于无头测试。
语法非法时抛 FilterError（GUI 捕获后提示，不改变当前视图）。
"""
from __future__ import annotations

import re
from typing import Callable

_PROTO_KEYWORDS = {"tcp", "udp", "icmp", "arp", "ip", "ipv6"}
_TERM_RE = re.compile(r"^(ip|src|dst|port|sport|dport)\s*(==|!=)?\s*(.+)$", re.IGNORECASE)


class FilterError(ValueError):
    """显示过滤表达式语法错误。"""


def _proto_pred(kw: str) -> Callable:
    kw = kw.lower()
    if kw == "tcp":
        return lambda r: r.proto == "TCP"
    if kw == "udp":
        return lambda r: r.proto == "UDP"
    if kw == "icmp":
        return lambda r: (r.proto or "").upper().startswith("ICMP")
    if kw == "arp":
        return lambda r: r.proto == "ARP" or getattr(r, "l3", "") == "ARP"
    if kw == "ip":
        return lambda r: getattr(r, "l3", "") == "IPv4"
    if kw == "ipv6":
        return lambda r: getattr(r, "l3", "") == "IPv6"
    raise FilterError(f"未知协议关键字: {kw}")


def _term_pred(term: str) -> Callable:
    term = term.strip()
    if not term:
        raise FilterError("空的过滤项")
    low = term.lower()
    if low in _PROTO_KEYWORDS:
        return _proto_pred(low)

    m = _TERM_RE.match(term)
    if not m:
        raise FilterError(f"无法解析的过滤项: {term!r}")
    field, op, value = m.group(1).lower(), (m.group(2) or "==").strip(), m.group(3).strip()
    if not value:
        raise FilterError(f"过滤项缺少值: {term!r}")

    if field in ("port", "sport", "dport"):
        if not value.isdigit():
            raise FilterError(f"端口必须是数字: {term!r}")
        port = int(value)

        def base_port(r):
            if field == "sport":
                return r.sport == port
            if field == "dport":
                return r.dport == port
            return r.sport == port or r.dport == port
    else:  # ip / src / dst
        def base_port(r):
            if field == "src":
                return r.src == value
            if field == "dst":
                return r.dst == value
            return r.src == value or r.dst == value

    if op == "!=":
        return lambda r: not base_port(r)
    return base_port


def _and_pred(group: str) -> Callable:
    parts = re.split(r"\band\b", group, flags=re.IGNORECASE)
    preds = [_term_pred(p) for p in parts]
    return lambda r: all(p(r) for p in preds)


def compile_filter(text: str) -> Callable:
    """把显示过滤表达式编译成 predicate(PacketRecord)->bool。

    空表达式返回恒 True（显示全部）；语法错误抛 FilterError。
    """
    if text is None or not text.strip():
        return lambda r: True
    groups = re.split(r"\bor\b", text, flags=re.IGNORECASE)
    preds = [_and_pred(g) for g in groups]
    return lambda r: any(p(r) for p in preds)
