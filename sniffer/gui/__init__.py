"""第二阶段 GUI 包：最简 PySide6 界面，实时显示数据包列表。

模块划分：
- packet_model : 纯逻辑（无 Qt）——包→记录转换、有界缓存。可无头单测。
- capture_worker : 抓包工作对象（QObject + moveToThread），跨线程用信号传包。
- main_window : 主窗口，有界缓存 + QTimer 批量刷新表格，负责线程生命周期。
- app : QApplication 启动入口（python -m sniffer gui）。

本阶段不做协议深度解析、不做详情/十六进制栏（第三阶段）。
"""
