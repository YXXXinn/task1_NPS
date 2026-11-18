"""无头 GUI 逻辑测试（offscreen）：验证 Qt 相关但不需要真实抓包/显示的部分。

覆盖：
1. PacketTableModel 批量追加 + 行数上限（超出从表头淘汰最旧行）；
2. 跨线程管线：worker 线程发 Signal(PacketRecord) -> 主线程槽收包 -> 有界缓冲，
   验证 moveToThread + 排队连接下数据结构完整、计数正确（用合成记录，不开 socket）。

运行：QT_QPA_PLATFORM=offscreen python tests/test_gui_headless.py
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import QObject, QThread, QTimer, Signal, Slot
from PySide6.QtWidgets import QApplication

from sniffer.gui.packet_model import BoundedPacketBuffer, PacketRecord
from sniffer.gui.packet_table import PacketTableModel

_fail = 0


def check(cond, msg):
    global _fail
    if not cond:
        _fail += 1
    print(f"[{'ok  ' if cond else 'FAIL'}] {msg}")


def _rec(seq):
    return PacketRecord(seq=seq, ts=0.0, time_str="00:00:00.000",
                        src="a", dst="b", proto="TCP", length=60, summary="x")


class _Emitter(QObject):
    """模拟 CaptureWorker 的发包模式：在自己线程里逐个发 Signal。"""
    packetCaptured = Signal(object)
    done = Signal()

    def __init__(self, n):
        super().__init__()
        self._n = n

    @Slot()
    def run(self):
        for i in range(1, self._n + 1):
            self.packetCaptured.emit(_rec(i))
        self.done.emit()


def test_table_model():
    model = PacketTableModel(max_rows=100)
    model.append_batch([_rec(i) for i in range(1, 51)])   # 50
    check(model.rowCount() == 50, "追加 50 行后 rowCount=50")
    model.append_batch([_rec(i) for i in range(51, 131)])  # +80 => 130 > 100
    check(model.rowCount() == 100, "超上限后 rowCount 封顶=100")
    # 最旧应被淘汰：首行序号应为 31（130-100+1）
    top_seq = model.data(model.index(0, 0))
    check(top_seq == 31, f"淘汰最旧后首行序号=31（实际 {top_seq}）")
    model.append_batch([])
    check(model.rowCount() == 100, "空批次不改变行数")


def test_cross_thread_pipeline(app):
    buffer = BoundedPacketBuffer(maxlen=10000)
    collected = {"n": 0}

    def on_packet(rec):
        collected["n"] += 1
        buffer.append(rec)

    thread = QThread()
    emitter = _Emitter(500)
    emitter.moveToThread(thread)
    thread.started.connect(emitter.run)
    emitter.packetCaptured.connect(on_packet)  # 自动排队连接（跨线程）

    def finish():
        thread.quit()
    emitter.done.connect(finish)
    thread.finished.connect(app.quit)

    # 安全阀：最多跑 5 秒
    QTimer.singleShot(5000, app.quit)
    thread.start()
    app.exec()
    thread.wait(2000)

    check(collected["n"] == 500, f"主线程槽收到 500 个包（实际 {collected['n']}）")
    check(len(buffer) == 500, "有界缓冲内有 500 个记录")
    drained = buffer.drain()
    check(all(isinstance(r, PacketRecord) for r in drained), "跨线程传来的仍是 PacketRecord")
    check([r.seq for r in drained] == list(range(1, 501)), "顺序与序号完整无错乱")


def main():
    app = QApplication.instance() or QApplication(sys.argv)
    test_table_model()
    test_cross_thread_pipeline(app)
    print(f"\n结果：{'全部通过' if _fail == 0 else str(_fail) + ' 项失败'}")
    return 1 if _fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
