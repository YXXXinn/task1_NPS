"""GUI 启动入口：python -m sniffer gui。

抓包通常需要 root（见 README）。本入口只负责拉起 QApplication 和主窗口，
是否有抓包权限由点击「开始」后 worker 的 error 信号如实反馈。
"""
from __future__ import annotations

import sys


def main(argv=None) -> int:
    from PySide6.QtWidgets import QApplication

    from sniffer.gui.main_window import MainWindow

    app = QApplication(argv if argv is not None else sys.argv)
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
