"""Packet List 的表格模型：QAbstractTableModel + 行数上限（有界）。

为什么用 QAbstractTableModel 而非 QTableWidget：
- 批量插入/淘汰行时性能好，且内存有上限（deque 容量封顶，超出从表头淘汰最旧行）；
- 模型/视图分离，符合 Qt 推荐实践。

行数上限（MAX_ROWS）与 BoundedPacketBuffer 的 maxlen 共同保证「高流量下内存不无限涨」：
缓冲层先丢最旧、表格层再封顶，双重有界。
"""
from __future__ import annotations

from collections import deque
from typing import List

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt

from sniffer.gui.packet_model import PacketRecord

_COLUMNS = ["序号", "时间", "源", "目的", "协议", "长度"]


class PacketTableModel(QAbstractTableModel):
    def __init__(self, max_rows: int = 5000) -> None:
        super().__init__()
        self._rows: deque = deque()
        self._max_rows = max_rows

    # --- Qt 必要接口 ---
    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(_COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return _COLUMNS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        rec: PacketRecord = self._rows[index.row()]
        col = index.column()
        if col == 0:
            return rec.seq
        if col == 1:
            return rec.time_str
        if col == 2:
            return rec.src
        if col == 3:
            return rec.dst
        if col == 4:
            return rec.proto
        if col == 5:
            return rec.length
        return None

    # --- 批量追加（供 QTimer 定时调用）---
    def append_batch(self, records: List[PacketRecord]) -> None:
        if not records:
            return
        # 若单批就超过上限，只保留最后 max_rows 条。
        if len(records) > self._max_rows:
            records = records[-self._max_rows:]

        incoming = len(records)
        overflow = max(0, len(self._rows) + incoming - self._max_rows)
        if overflow:
            self.beginRemoveRows(QModelIndex(), 0, overflow - 1)
            for _ in range(overflow):
                self._rows.popleft()
            self.endRemoveRows()

        start = len(self._rows)
        self.beginInsertRows(QModelIndex(), start, start + incoming - 1)
        self._rows.extend(records)
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()

    # --- 选中行 → 记录映射 ---
    def record_at(self, row: int):
        """按行号取 PacketRecord；越界返回 None。

        选中处理应在「选中事件发生的当下」立即调用本方法取快照，而不是缓存行号：
        表格会随抓包滚动/淘汰，行号不稳定；PacketRecord.seq 才是稳定标识。
        """
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None
