"""抓包工作对象：QObject + moveToThread 模式。

为什么选 moveToThread（而非继承 QThread）：
- 把「做什么」（CaptureWorker）与「线程本身」（QThread）解耦，worker 是纯粹的
  QObject，逻辑清晰、易测试、易复用；
- 官方推荐用法；run 槽在 worker 所属线程执行，信号自动以 QueuedConnection 跨回主线程。

停止为什么干净：
- 直接用 scapy 的监听 socket（conf.L2listen）+ SuperSocket.select 轮询（0.2s 超时），
  每轮检查一次 stop 事件。即使完全没有流量，最多 0.2s 内就能退出循环——
  不依赖「下一个包到来」才触发停止。
- 退出时在 finally 里 close socket，线程函数正常返回，不残留。

跨线程纪律：worker 只发信号（packetCaptured/started/finished/error），
绝不触碰任何 Widget。
"""
from __future__ import annotations

import threading

from PySide6.QtCore import QObject, Signal, Slot

from sniffer.gui.packet_model import packet_to_record

# 单轮 select 超时：决定「停止」的最大响应延迟，也决定空闲时的 CPU 轮询间隔。
_SELECT_TIMEOUT = 0.2


class CaptureWorker(QObject):
    """在独立线程里用 scapy 监听 socket 抓包，逐包发信号给主线程。"""

    packetCaptured = Signal(object)  # 载荷为 PacketRecord
    started = Signal()
    finished = Signal()
    error = Signal(str)

    def __init__(self, iface=None, bpf_filter=None) -> None:
        super().__init__()
        self._iface = iface or None
        self._bpf = bpf_filter or None
        self._stop = threading.Event()
        self._seq = 0

    def request_stop(self) -> None:
        """从主线程调用：请求停止。设置 Event 是线程安全的。"""
        self._stop.set()

    @Slot()
    def run(self) -> None:
        """在 worker 所属线程执行的抓包主循环。"""
        from scapy.config import conf
        from scapy.supersocket import SuperSocket

        self._stop.clear()
        try:
            # 打开二层监听 socket；filter 即 BPF 抓包过滤（内核层）。
            # 权限不足 / BPF 语法错误都会在这里抛异常。
            sock = conf.L2listen(iface=self._iface, filter=self._bpf)
        except (PermissionError, OSError) as exc:
            self.error.emit(
                "打开抓包 socket 失败，疑似权限不足：%s\n"
                "macOS 抓包需访问 /dev/bpf*，通常要 root。请用："
                "  sudo .venv/bin/python -m sniffer gui" % exc
            )
            self.finished.emit()
            return
        except Exception as exc:  # 典型为 BPF 过滤表达式非法
            self.error.emit("打开抓包 socket 失败（可能是 BPF 过滤表达式非法）：%s" % exc)
            self.finished.emit()
            return

        self.started.emit()
        try:
            while not self._stop.is_set():
                ready = SuperSocket.select([sock], _SELECT_TIMEOUT)
                if not ready:
                    continue  # 本轮无包，回到循环顶部再查 stop 标志
                try:
                    pkt = sock.recv()
                except Exception:
                    continue
                if pkt is None:
                    continue
                self._seq += 1
                # 解析/转换在本（子）线程完成，主线程只收到轻量 PacketRecord。
                self.packetCaptured.emit(packet_to_record(pkt, self._seq))
        finally:
            try:
                sock.close()
            except Exception:
                pass
            self.finished.emit()
