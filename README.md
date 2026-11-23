# 网络嗅探器

一个带 GUI 的网络嗅探器。技术栈：**macOS + Python + Scapy + PySide6**。

## 环境要求

- macOS
- Python 3.12
- libpcap（macOS 自带）

## 创建 venv 与安装依赖

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 运行方式

```bash
python scripts/check_env.py
python -m sniffer ifaces
python -m sniffer backend
sudo .venv/bin/python -m sniffer gui
sudo .venv/bin/python -m sniffer capture -i en0 -c 5 -t 10 -f "tcp"
```

## 抓包权限说明

macOS 抓包需要访问 `/dev/bpf*` 设备，通常需要 **root 权限**：

- GUI：用 `sudo .venv/bin/python -m sniffer gui` 启动；不加 sudo 时点「开始」会弹出权限错误提示，界面不崩溃。
- 命令行抓包同理，需 sudo；`ifaces` 与 `backend` 不需要 root。
- 请使用 venv 里的解释器配合 sudo：`sudo .venv/bin/python -m sniffer ...`

## 测试

```bash
python tests/test_packet_model.py
python tests/test_dissect.py
python tests/test_appid.py
python tests/test_display_filter.py
python tests/test_tcpflow.py
QT_QPA_PLATFORM=offscreen python tests/test_gui_headless.py
```

## 目录结构

```
.
├── sniffer/            # 核心包
│   ├── __init__.py     #   libpcap 偏好设置
│   ├── __main__.py     #   python -m sniffer 入口
│   ├── backend.py      #   抓包后端探测
│   ├── interfaces.py   #   网卡枚举
│   ├── capture.py      #   命令行抓包
│   ├── cli.py          #   子命令：ifaces / backend / capture / gui
│   └── gui/            #   GUI 与解析、过滤、流追踪
├── scripts/check_env.py
├── tests/
├── docs/
├── requirements.txt
└── README.md
```

