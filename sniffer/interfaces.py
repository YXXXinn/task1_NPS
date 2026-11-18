"""网卡枚举：列出本机可用网络接口。

数据来源于 Scapy 的接口表（conf.ifaces），它在 libpcap / 原生 BPF 两种后端下
都能工作。返回结构化 dict，便于命令行打印，也方便后续 GUI 阶段复用。
"""
from __future__ import annotations

from typing import Any, Dict, List


def _ips_of(ifobj) -> List[str]:
    """尽量从 NetworkInterface 取出 IP 列表，兼容不同 scapy 版本的字段差异。"""
    ips: List[str] = []
    raw = getattr(ifobj, "ips", None)
    if isinstance(raw, dict):
        for family in raw.values():
            for ip in family:
                ips.append(str(ip))
    single = getattr(ifobj, "ip", None)
    if single and single not in ips:
        ips.append(str(single))
    return ips


def list_interfaces() -> List[Dict[str, Any]]:
    """返回本机网络接口的结构化列表。

    每个元素字段：name / index / mac / ips(list) / description。
    读取失败的单个字段以空值兜底，保证整体枚举不因个别接口异常而中断。
    """
    from scapy.all import conf

    result: List[Dict[str, Any]] = []
    for ifobj in conf.ifaces.values():
        try:
            result.append(
                {
                    "name": getattr(ifobj, "name", "") or "",
                    "index": getattr(ifobj, "index", None),
                    "mac": getattr(ifobj, "mac", "") or "",
                    "ips": _ips_of(ifobj),
                    "description": getattr(ifobj, "description", "") or "",
                }
            )
        except Exception as exc:  # 单个接口信息异常不应中断整体枚举
            result.append({"name": str(getattr(ifobj, "name", "?")), "error": str(exc)})
    return result


def format_interfaces(ifaces: List[Dict[str, Any]]) -> str:
    """渲染网卡列表为对齐的多行文本。"""
    lines = [f"=== 本机网络接口（共 {len(ifaces)} 个）===",
             f"{'IDX':>4}  {'NAME':<12} {'MAC':<17}  IPs"]
    for it in ifaces:
        if "error" in it:
            lines.append(f"{'?':>4}  {it.get('name', '?'):<12} <读取失败: {it['error']}>")
            continue
        idx = "-" if it["index"] is None else str(it["index"])
        ips = ", ".join(it["ips"]) if it["ips"] else "-"
        lines.append(f"{idx:>4}  {it['name']:<12} {it['mac'] or '-':<17}  {ips}")
    return "\n".join(lines)
