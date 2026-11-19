"""Packet List 的表格模型：全量有界记录 + 显示过滤视图。

两层数据：
- self._all ：**全部**已抓到的记录（deque，行数上限 max_rows，超出从表头淘汰最旧）。
  显示过滤**不丢**这里的数据，清空过滤即可恢复。
- self._view：当前显示过滤下**可见**的记录（_all 的有序子集）。视图即 Qt 模型对外的行。

为什么这样：显示过滤属界面层，作用于已抓到的包、可逆；底层仍有界（内存不无限涨）。
行数上限 + BoundedPacketBuffer.maxlen 双重有界。
"""
from __future__ import annotations

from collections import deque
from typing import Callable, List

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt

from sniffer.gui.packet_model import PacketRecord

_COLUMNS = ["序号", "时间", "源", "目的", "协议", "长度"]


class PacketTableModel(QAbstractTableModel):
    def __init__(self, max_rows: int = 5000) -> None:
        super().__init__()
        self._all: deque = deque()                 # 全部记录（有界）
        self._view: List[PacketRecord] = []        # 过滤后可见记录
        self._max_rows = max_rows
        self._predicate: Callable = lambda r: True  # 当前显示过滤（默认全部显示）

    # --- Qt 必要接口（对外行 = 过滤后视图）---
    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._view)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(_COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return _COLUMNS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        rec: PacketRecord = self._view[index.row()]
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
            # 协议列：基础层标识 + 可选的应用层推测（带问号，绝不像确证）
            short = rec.app.short() if getattr(rec, "app", None) is not None else ""
            return f"{rec.proto} ({short})" if short else rec.proto
        if col == 5:
            return rec.length
        return None

    # --- 批量追加（供 QTimer 定时调用）---
    def append_batch(self, records: List[PacketRecord]) -> None:
        if not records:
            return
        if len(records) > self._max_rows:
            records = records[-self._max_rows:]
        incoming = len(records)

        # 1) 先算 _all 的淘汰量，并把其中「当前可见（在 _view 前缀）」的部分从视图移除
        overflow = max(0, len(self._all) + incoming - self._max_rows)
        if overflow:
            evicted = list(self._all)[:overflow]
            ev_ids = {id(r) for r in evicted}
            remove_from_view = 0
            for r in self._view:
                if id(r) in ev_ids:
                    remove_from_view += 1
                else:
                    break
            if remove_from_view:
                self.beginRemoveRows(QModelIndex(), 0, remove_from_view - 1)
                del self._view[:remove_from_view]
                self.endRemoveRows()
            for _ in range(overflow):
                self._all.popleft()

        self._all.extend(records)

        # 2) 新记录里通过过滤的，追加到视图尾部
        passing = [r for r in records if self._predicate(r)]
        if passing:
            start = len(self._view)
            self.beginInsertRows(QModelIndex(), start, start + len(passing) - 1)
            self._view.extend(passing)
            self.endInsertRows()

    def set_filter(self, predicate: Callable) -> None:
        """切换显示过滤：保留 _all 全量，仅按新谓词重建可见视图。"""
        self.beginResetModel()
        self._predicate = predicate
        self._view = [r for r in self._all if predicate(r)]
        self.endResetModel()

    def clear(self) -> None:
        self.beginResetModel()
        self._all.clear()
        self._view.clear()
        self.endResetModel()

    # --- 统计 ---
    def total_count(self) -> int:
        return len(self._all)

    def visible_count(self) -> int:
        return len(self._view)

    # --- 选中行 → 记录映射 ---
    def record_at(self, row: int):
        """按（视图）行号取 PacketRecord；越界返回 None。

        选中处理应在「选中事件发生的当下」立即调用，不缓存行号：
        表格会随抓包滚动/淘汰/过滤变化，行号不稳定；PacketRecord.seq 才是稳定标识。
        """
        if 0 <= row < len(self._view):
            return self._view[row]
        return None
