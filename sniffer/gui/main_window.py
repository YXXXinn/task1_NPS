"""主窗口：最简 Packet List 实时显示。

数据流（关键设计）：
  抓包线程(CaptureWorker) --packetCaptured(信号/排队连接)--> 主线程槽 _on_packet
    -> 追加进 BoundedPacketBuffer（有界，满了丢最旧）
  QTimer(200ms) --> _flush -> buffer.drain() 批量 -> PacketTableModel.append_batch
这样做到：子线程不碰 Widget；主线程不逐包刷新；高流量下缓冲与表格都有界。
"""
from __future__ import annotations

from PySide6.QtCore import QThread, QTimer, Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sniffer.gui.capture_worker import CaptureWorker
from sniffer.gui.dissect import dissect_layers, format_hex_dump
from sniffer.gui.packet_model import BoundedPacketBuffer
from sniffer.gui.packet_table import PacketTableModel

_FLUSH_INTERVAL_MS = 200
_BUFFER_MAXLEN = 20000
_TABLE_MAX_ROWS = 5000


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("网络嗅探器 — 实验 1A 第三阶段（列表 + 详情 + 十六进制三栏）")
        self.resize(1000, 700)

        self._thread = None
        self._worker = None
        self._buffer = BoundedPacketBuffer(maxlen=_BUFFER_MAXLEN)
        self._model = PacketTableModel(max_rows=_TABLE_MAX_ROWS)
        self._total = 0
        self._shown_seq = None  # 当前详情/hex 已展示的包序号，避免重复渲染

        self._build_ui()

        self._timer = QTimer(self)
        self._timer.setInterval(_FLUSH_INTERVAL_MS)
        self._timer.timeout.connect(self._flush)

    # ---------------- UI ----------------
    def _build_ui(self) -> None:
        central = QWidget(self)
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        top = QHBoxLayout()
        top.addWidget(QLabel("网卡："))
        self.iface_combo = QComboBox()
        self._populate_ifaces()
        top.addWidget(self.iface_combo, 2)

        top.addWidget(QLabel("BPF 抓包过滤："))
        self.bpf_edit = QLineEdit()
        self.bpf_edit.setPlaceholderText('内核层过滤，语法同 tcpdump，如 "tcp port 80"；留空抓全部')
        top.addWidget(self.bpf_edit, 3)

        self.start_btn = QPushButton("开始")
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self._on_start)
        self.stop_btn.clicked.connect(self._on_stop)
        top.addWidget(self.start_btn)
        top.addWidget(self.stop_btn)

        self.status_dot = QLabel("■ 已停止")
        top.addWidget(self.status_dot)
        root.addLayout(top)

        # 三栏（类 Wireshark）：上=Packet List；下=（左 详情树 / 右 十六进制）。
        # 用 QSplitter 组合，渲染详情/hex 只在选中时触发，不影响列表实时刷新、不阻塞主线程。
        main_split = QSplitter(Qt.Vertical)

        self.table = QTableView()
        self.table.setModel(self._model)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.selectionModel().currentRowChanged.connect(self._on_row_changed)
        main_split.addWidget(self.table)

        bottom_split = QSplitter(Qt.Horizontal)

        # 详情栏（协议分层树）
        detail_box = QWidget()
        detail_lay = QVBoxLayout(detail_box)
        detail_lay.setContentsMargins(0, 0, 0, 0)
        detail_lay.addWidget(QLabel("详情（协议分层）"))
        self.detail_tree = QTreeWidget()
        self.detail_tree.setHeaderLabels(["字段", "值"])
        self.detail_tree.setColumnWidth(0, 220)
        detail_lay.addWidget(self.detail_tree)
        bottom_split.addWidget(detail_box)

        # 十六进制 + ASCII 栏
        hex_box = QWidget()
        hex_lay = QVBoxLayout(hex_box)
        hex_lay.setContentsMargins(0, 0, 0, 0)
        hex_lay.addWidget(QLabel("十六进制 / ASCII（原始字节）"))
        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        mono = QFont("Menlo")
        mono.setStyleHint(QFont.Monospace)
        mono.setPointSize(11)
        self.hex_view.setFont(mono)
        hex_lay.addWidget(self.hex_view)
        bottom_split.addWidget(hex_box)
        bottom_split.setSizes([480, 520])

        main_split.addWidget(bottom_split)
        main_split.setSizes([400, 300])
        root.addWidget(main_split, 1)

        self.statusBar().showMessage(
            "提示：点击列表某行 → 下方查看该包的协议分层与十六进制。"
            "BPF 抓包过滤在内核层（本框）；显示过滤属后续子阶段，层级不同。"
        )

    def _populate_ifaces(self) -> None:
        self.iface_combo.clear()
        try:
            from sniffer.interfaces import list_interfaces

            for it in list_interfaces():
                name = it.get("name", "")
                if not name:
                    continue
                ips = ", ".join(it.get("ips", [])) if it.get("ips") else ""
                label = f"{name}  [{ips}]" if ips else name
                self.iface_combo.addItem(label, userData=name)
        except Exception as exc:  # 枚举失败不应阻断界面
            self.iface_combo.addItem(f"<网卡枚举失败: {exc}>", userData=None)

    # ---------------- 抓包生命周期 ----------------
    def _on_start(self) -> None:
        if self._thread is not None:
            return
        iface = self.iface_combo.currentData()
        bpf = self.bpf_edit.text().strip() or None

        self._thread = QThread(self)
        self._worker = CaptureWorker(iface=iface, bpf_filter=bpf)
        self._worker.moveToThread(self._thread)

        # 线程启动即运行 worker.run；worker 结束即退出线程事件循环。
        self._thread.started.connect(self._worker.run)
        self._worker.packetCaptured.connect(self._on_packet)
        self._worker.started.connect(self._on_capture_started)
        self._worker.error.connect(self._on_error)
        self._worker.finished.connect(self._on_worker_finished)

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.iface_combo.setEnabled(False)
        self.bpf_edit.setEnabled(False)
        self.status_dot.setText("● 启动中…")

        self._thread.start()
        self._timer.start()

    def _on_stop(self) -> None:
        self.stop_btn.setEnabled(False)
        self.status_dot.setText("● 停止中…")
        if self._worker is not None:
            self._worker.request_stop()

    def _on_capture_started(self) -> None:
        self.status_dot.setText("● 运行中")

    def _on_error(self, msg: str) -> None:
        QMessageBox.critical(self, "抓包错误", msg)

    def _on_worker_finished(self) -> None:
        """worker 结束（正常停止或出错）：收尾线程、刷掉残包、恢复按钮。"""
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(2000)
        self._timer.stop()
        self._flush()  # 把缓冲里剩余的包刷进表格

        self._worker = None
        self._thread = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.iface_combo.setEnabled(True)
        self.bpf_edit.setEnabled(True)
        self.status_dot.setText("■ 已停止")

    # ---------------- 数据流 ----------------
    def _on_packet(self, record) -> None:
        """主线程槽：只入缓冲，不碰表格。"""
        self._total += 1
        self._buffer.append(record)

    def _flush(self) -> None:
        """QTimer 定时：批量把缓冲里的包塞进表格模型。"""
        batch = self._buffer.drain()
        if batch:
            self._model.append_batch(batch)
            # 用户正在查看某个包时（有选中）暂停自动滚动，避免抢焦点/把要看的行滚走。
            if not self.table.selectionModel().hasSelection():
                self.table.scrollToBottom()
        self.statusBar().showMessage(
            f"累计抓包 {self._total}  |  表格显示 {self._model.rowCount()} 行"
            f"（上限 {_TABLE_MAX_ROWS}）  |  缓冲丢弃 {self._buffer.dropped}"
            f"  |  BPF 抓包过滤(内核层) ≠ 显示过滤(后续子阶段)"
        )

    # ---------------- 详情 / 十六进制 ----------------
    def _on_row_changed(self, current, _previous) -> None:
        """选中行变化：取该行记录的快照，渲染协议分层树与 hex/ASCII。

        以 PacketRecord.seq（稳定标识）为准，不缓存行号（行会随抓包滚动/淘汰）。
        """
        if current is None or not current.isValid():
            return
        rec = self._model.record_at(current.row())
        if rec is None or rec.seq == self._shown_seq:
            return
        self._shown_seq = rec.seq
        self._render_detail(rec)

    def _render_detail(self, rec) -> None:
        from scapy.layers.l2 import Ether

        # 十六进制 / ASCII
        self.hex_view.setPlainText(format_hex_dump(rec.raw))

        # 协议分层树：用原始字节按二层帧重新解析（抓包为 L2，故用 Ether）。
        self.detail_tree.clear()
        if not rec.raw:
            return
        try:
            pkt = Ether(rec.raw)
        except Exception as exc:
            top = QTreeWidgetItem([f"#{rec.seq} 解析失败", str(exc)])
            self.detail_tree.addTopLevelItem(top)
            return
        for layer in dissect_layers(pkt):
            node = QTreeWidgetItem([layer.name, ""])
            for fname, fval in layer.fields:
                node.addChild(QTreeWidgetItem([str(fname), str(fval)]))
            self.detail_tree.addTopLevelItem(node)
        self.detail_tree.expandAll()

    # ---------------- 关闭 ----------------
    def closeEvent(self, event) -> None:
        """关窗：确保抓包线程安全结束，不残留。"""
        if self._worker is not None:
            self._worker.request_stop()
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(2000)
        self._timer.stop()
        super().closeEvent(event)
