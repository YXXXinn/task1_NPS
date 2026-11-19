# 网络嗅探器（《软件与系统安全》实验 1A）

一个带 GUI 的网络嗅探器。技术栈：**macOS + Python + Scapy + PySide6**。
本仓库按阶段推进，当前处于 **第三阶段：三栏界面（列表 + 协议详情 + 十六进制/ASCII）**。

## 阶段计划

- 第一阶段（已完成）：环境搭建、项目骨架、命令行工具——网卡枚举、最小抓包、Scapy 后端探测、权限处理。
- 第二阶段（已完成）：抓包线程化（QObject worker + moveToThread）+ 跨线程 Qt 信号传包 + 有界缓存 + QTimer 批量刷新，最简 GUI 实时显示包列表。
- **第三阶段（当前，子阶段 a）**：类 Wireshark 三栏——Packet List + 协议分层详情树 + 十六进制/ASCII 视图。本子阶段**不做** GUI 显示过滤、**不做**应用层协议识别（留待后续子阶段）。
- 第三阶段后续：GUI 显示过滤（与 BPF 抓包过滤分层）。
- 第四阶段：应用层协议解析与判定（端口仅作「推测」提示，结合载荷特征并标注「推测」）。

## 环境要求（本机实测）

- macOS（arm64 / Apple Silicon，实测 `uname -m` = `arm64`）
- Python 3.12（Homebrew `/opt/homebrew/bin/python3.12`，实测 3.12.15）
  - 系统自带 `python3` 为 3.9.6，也能跑 scapy；选 3.12 是为了与后续 PySide6 更好地匹配。
- libpcap：macOS 自带 libpcap 1.10.1（随 `/usr/sbin/tcpdump` 一同提供）。
  - 注意：该 dylib 位于 dyld 共享缓存中，`ls /usr/lib/libpcap*` 看不到实体文件，属正常现象。

## 创建 venv 与安装依赖

```bash
cd "/Users/yuxinxin/软件与系统安全/实验1"

# 1) 用 Homebrew Python 3.12 创建虚拟环境（venv 不提交，已在 .gitignore 中）
/opt/homebrew/bin/python3.12 -m venv .venv

# 2) 激活
source .venv/bin/activate

# 3) 安装依赖
python -m pip install --upgrade pip
pip install -r requirements.txt
```

> 说明：`scapy` 与 `PySide6-Essentials` 为项目运行依赖（GUI 只用 QtCore/QtGui/QtWidgets）。
> 第二阶段已实际安装并 import 验证 `PySide6-Essentials==6.12.0`（PySide6 的精简子集，
> 本机 arm64 + Python 3.12 + macOS）。若需完整套件可改装 `PySide6==6.12.0`。
> 注：国内网络从 pythonhosted 下载较慢，可加镜像，如
> `pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt`。

## 运行方式

```bash
# 环境自检（Python/架构/Scapy 后端/网卡，一次看全）
python scripts/check_env.py

# 列出本机网络接口
python -m sniffer ifaces

# 打印 Scapy 实际启用的抓包后端（libpcap 还是原生 BPF）
python -m sniffer backend

# 启动最简 GUI（实时包列表）——抓包需 root，见下
sudo .venv/bin/python -m sniffer gui

# 命令行最小抓包验证（需要抓包权限，见下）
sudo .venv/bin/python -m sniffer capture -i en0 -c 5 -t 10 -f "tcp"
```

## 无头自动化验证（合成包，无需 root/GUI）

```bash
python tests/test_packet_model.py                               # 纯逻辑：判定/字段/有界缓存
QT_QPA_PLATFORM=offscreen python tests/test_gui_headless.py     # 表格模型 + 跨线程信号管线
```

## 抓包权限说明

macOS 抓包需要访问 `/dev/bpf*` 设备，通常需要 **root 权限**：

- **GUI**：用 `sudo .venv/bin/python -m sniffer gui` 启动；若不加 sudo，点「开始」后会弹出权限错误对话框，界面不崩溃。
  - macOS 上 sudo 拉起 GUI 偶有坑（窗口服务器/焦点问题）。若遇到，可先 `sudo -v` 预授权，或改用已安装 ChmodBPF（Wireshark 自带）放宽 `/dev/bpf*` 权限后免 sudo 运行。**此项需用户在本机手动验证。**
- 不加 sudo 运行 `capture` 一般会失败，程序会捕获权限错误并打印清晰提示。
- 正确做法是用 **venv 里的解释器 + sudo**：`sudo .venv/bin/python -m sniffer ...`
  直接 `sudo python -m sniffer` 可能走到系统 python 而找不到 scapy。
- `ifaces` 与 `backend` 两个子命令**不需要** root，可直接运行。

## 抓包后端与过滤的概念区分

- **libpcap vs 原生 BPF**：本项目优先让 Scapy 走 libpcap（通过环境变量
  `SCAPY_USE_LIBPCAP=yes`，已在 `sniffer/__init__.py` 中设置）。若本机 libpcap
  provider 不可用，Scapy 会自动回退到 macOS 原生 BPF。实际结果以
  `python -m sniffer backend` 的运行时检测为准，不臆测。
- **BPF 抓包过滤 vs GUI 显示过滤**：
  - BPF 抓包过滤在**内核层**生效，通过 `capture(..., bpf_filter=...)` 或 GUI 顶部的
    「BPF 抓包过滤」框传给 Scapy 的 `filter=`，语法同 tcpdump（如 `tcp port 80`），
    不匹配的包在内核即被丢弃。
  - GUI 显示过滤（第三阶段）在**用户态**对「已抓到的包」做界面筛选，可反复开关。
  - 两者层级与时机不同，代码与讲解中分别对待。

## 目录结构

```
.
├── sniffer/            # 核心包
│   ├── __init__.py     #   设置 libpcap 偏好（须在导入 scapy 前）
│   ├── __main__.py     #   python -m sniffer 入口
│   ├── backend.py      #   Scapy 后端探测（libpcap / 原生 BPF）
│   ├── interfaces.py   #   网卡枚举
│   ├── capture.py      #   命令行最小抓包 + 权限错误处理
│   ├── cli.py          #   argparse 子命令：ifaces / backend / capture / gui
│   └── gui/            #   GUI
│       ├── packet_model.py    # 纯逻辑(无Qt)：包→记录、有界缓存、原始字节留存
│       ├── dissect.py         # 纯逻辑(无Qt)：协议分层解析 + 十六进制/ASCII 格式化
│       ├── capture_worker.py  # QObject worker + moveToThread 抓包线程
│       ├── packet_table.py    # QAbstractTableModel（行上限 + 序号→记录映射）
│       ├── main_window.py     # 三栏窗口：列表+详情树+hex；缓存+QTimer批量刷新+线程生命周期
│       └── app.py             # QApplication 启动入口
├── scripts/check_env.py       # 环境自检脚本
├── tests/                     # 无头自动化验证（合成包）
├── docs/                      # 证据/示意图/录屏脚本（见 AGENTS.md）
├── requirements.txt
├── README.md
└── 实验 1 讲解 2026.pdf        # 实验讲义（未纳入 Git，保持 untracked）
```

