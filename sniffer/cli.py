"""命令行入口：网卡枚举 / 后端探测 / 最小抓包。

用法示例：
    python -m sniffer ifaces              # 列出本机网卡
    python -m sniffer backend             # 打印 Scapy 实际启用的后端
    sudo .venv/bin/python -m sniffer capture -i en0 -c 5 -t 10 -f "tcp"
"""
from __future__ import annotations

import argparse
import sys


def _cmd_ifaces(_args: argparse.Namespace) -> int:
    from sniffer.interfaces import format_interfaces, list_interfaces

    print(format_interfaces(list_interfaces()))
    return 0


def _cmd_backend(_args: argparse.Namespace) -> int:
    from sniffer.backend import detect_backend, format_backend

    print(format_backend(detect_backend()))
    return 0


def _cmd_capture(args: argparse.Namespace) -> int:
    from sniffer.backend import detect_backend
    from sniffer.capture import CapturePermissionError, capture

    info = detect_backend()
    print(f"[i] 后端：{info.backend} (use_pcap={info.use_pcap}, use_bpf={info.use_bpf})")
    print(f"[i] 网卡={args.iface or '默认'} count={args.count} "
          f"timeout={args.timeout} BPF过滤={args.filter or '无'}")
    print("[i] 开始抓包……（权限不足会在下方给出提示）")

    seen = {"n": 0}

    def _show(pkt) -> None:
        seen["n"] += 1
        print(f"  #{seen['n']:>3}  {pkt.summary()}")

    try:
        packets = capture(
            iface=args.iface,
            count=args.count,
            timeout=args.timeout,
            bpf_filter=args.filter,
            prn=_show,
        )
    except CapturePermissionError as exc:
        print(f"\n[!] {exc}", file=sys.stderr)
        return 2

    print(f"\n[✓] 共抓到 {len(packets)} 个包。")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sniffer",
        description="《软件与系统安全》实验 1A 网络嗅探器 —— 第一阶段命令行工具",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("ifaces", help="列出本机可用网络接口").set_defaults(func=_cmd_ifaces)
    sub.add_parser("backend", help="打印 Scapy 实际启用的抓包后端").set_defaults(func=_cmd_backend)

    cap = sub.add_parser("capture", help="最小抓包验证（可能需要 sudo）")
    cap.add_argument("-i", "--iface", default=None, help="网卡名，如 en0；默认交给 Scapy 选择")
    cap.add_argument("-c", "--count", type=int, default=5, help="抓包数量，0 表示不限（默认 5）")
    cap.add_argument("-t", "--timeout", type=float, default=10.0, help="超时秒数（默认 10）")
    cap.add_argument("-f", "--filter", default=None,
                     help='BPF 抓包过滤表达式（内核层），语法同 tcpdump，如 "tcp port 80"')
    cap.set_defaults(func=_cmd_capture)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
