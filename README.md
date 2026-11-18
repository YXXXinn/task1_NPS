# 网络嗅探器（《软件与系统安全》实验 1A）

一个带 GUI 的网络嗅探器。技术栈：**macOS + Python + Scapy + PySide6**。
本仓库按阶段推进，当前处于 **第一阶段：命令行最小实现**（尚未实现 GUI）。

## 阶段计划

- **第一阶段（当前）**：环境搭建、项目骨架、命令行工具——网卡枚举、最小抓包、Scapy 后端探测、权限处理。
- 第二阶段：抓包线程化（QThread/worker）+ 有界缓存 + 定时批量刷新，跨线程用 Qt 信号传递。
- 第三阶段：PySide6 GUI（包列表、详情、十六进制视图）、BPF 抓包过滤与 GUI 显示过滤分层。
- 第四阶段：协议解析与分层展示（端口仅作「推测」提示，判定结合载荷特征）。

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

> 说明：第一阶段验证只需 `scapy`；`PySide6` 列在 requirements 中供 GUI 阶段使用，
> 本阶段未实际安装/import 验证（版本 6.12.0 为 pip dry-run 解析所得，兼容本机 arm64 + py3.12 + macOS 14+）。

## 运行方式

```bash
# 环境自检（Python/架构/Scapy 后端/网卡，一次看全）
python scripts/check_env.py

# 列出本机网络接口
python -m sniffer ifaces

# 打印 Scapy 实际启用的抓包后端（libpcap 还是原生 BPF）
python -m sniffer backend

# 最小抓包验证（需要抓包权限，见下）
sudo .venv/bin/python -m sniffer capture -i en0 -c 5 -t 10 -f "tcp"
```

## 抓包权限说明

macOS 抓包需要访问 `/dev/bpf*` 设备，通常需要 **root 权限**：

- 不加 sudo 运行 `capture` 一般会失败，程序会捕获权限错误并打印清晰提示。
- 正确做法是用 **venv 里的解释器 + sudo**：
  `sudo .venv/bin/python -m sniffer capture ...`
  直接 `sudo python -m sniffer` 可能走到系统 python 而找不到 scapy。
- `ifaces` 与 `backend` 两个子命令**不需要** root，可直接运行。

## 抓包后端与过滤的概念区分

- **libpcap vs 原生 BPF**：本项目优先让 Scapy 走 libpcap（通过环境变量
  `SCAPY_USE_LIBPCAP=yes`，已在 `sniffer/__init__.py` 中设置）。若本机 libpcap
  provider 不可用，Scapy 会自动回退到 macOS 原生 BPF。实际结果以
  `python -m sniffer backend` 的运行时检测为准，不臆测。
- **BPF 抓包过滤 vs GUI 显示过滤**：
  - BPF 抓包过滤在**内核层**生效，通过 `capture(..., bpf_filter=...)` 传给 Scapy
    的 `filter=`，语法同 tcpdump（如 `tcp port 80`），不匹配的包在内核即被丢弃。
  - GUI 显示过滤（后续阶段）在**用户态**对「已抓到的包」做界面筛选，可反复开关。
  - 两者层级与时机不同，代码与讲解中分别对待。

## 目录结构

```
.
├── sniffer/            # 核心包（命令行工具）
│   ├── __init__.py     #   设置 libpcap 偏好（须在导入 scapy 前）
│   ├── __main__.py     #   python -m sniffer 入口
│   ├── backend.py      #   Scapy 后端探测（libpcap / 原生 BPF）
│   ├── interfaces.py   #   网卡枚举
│   ├── capture.py      #   最小抓包 + 权限错误处理
│   └── cli.py          #   argparse 子命令：ifaces / backend / capture
├── scripts/
│   └── check_env.py    # 环境自检脚本
├── requirements.txt
├── README.md
└── 实验 1 讲解 2026.pdf  # 实验讲义（是否纳入 Git 提交由用户决定）
```

> GUI 代码目录（如 `sniffer/gui/`）留待后续阶段创建，本阶段不实现。

