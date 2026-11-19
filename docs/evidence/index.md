# 证据索引（index.md）

本文件登记实验各阶段的证据素材。**严禁伪造**：未实际采集的条目标注「待手动采集/验证」。

字段说明：文件 | 采集日期 | 场景 | 操作/命令 | 预期 | 实际结果 | 代码版本 | 报告用途 | 脱敏

---

## 第二阶段（最简 GUI：实时包列表）

### 已采集（自动化、真实输出）

- 文件：`logs/stage2_headless_tests.log`
  - 采集日期：2026-11-18
  - 场景：无头单元验证（合成包）——协议判定/字段提取、有界缓存丢最旧、跨线程信号管线、表格行上限淘汰
  - 操作/命令：
    - `python tests/test_packet_model.py`
    - `QT_QPA_PLATFORM=offscreen python tests/test_gui_headless.py`
  - 预期：全部断言通过，退出码 0
  - 实际结果：见日志（全部通过）
  - 代码版本：第二阶段（未提交，待用户确认）
  - 报告用途：证明线程/缓存/判定核心逻辑正确
  - 脱敏：合成数据，无敏感信息

### 待手动采集/验证（需 GUI 窗口 / root / 人工操作，助手无法代办）

- 文件：`screenshots/stage2_gui_main.png` —— **待手动采集**
  - 场景：GUI 主界面（网卡下拉、BPF 过滤框、开始/停止按钮、状态指示、空表格）
  - 操作/命令：`sudo .venv/bin/python -m sniffer gui`
  - 预期：窗口正常显示，各控件可见；状态为「■ 已停止」
  - 实际结果：待采集
  - 脱敏：仅截本程序窗口

- 文件：`screenshots/stage2_capture_running.png` —— **待手动采集**
  - 场景：点击「开始」后实时抓包，表格持续增行，状态「● 运行中」，底部状态栏显示累计/显示/丢弃计数
  - 操作/命令：同上，选 en0，BPF 可填 `tcp`，另开终端制造可控流量（如 `curl http://example.com`）
  - 预期：包列表实时刷新且不卡顿
  - 实际结果：待采集
  - 脱敏：公开前检查是否含敏感地址/内容

- 文件：`screenshots/stage2_capture_stopped.png` —— **待手动采集**
  - 场景：点击「停止」后抓包停止、状态「■ 已停止」、按钮恢复可用、无异常
  - 操作/命令：运行中点「停止」
  - 预期：及时停止，残包刷完，可再次开始
  - 实际结果：待采集

- 文件：`screenshots/stage2_permission_error.png` —— **待手动采集**
  - 场景：**不加 sudo** 启动并点「开始」，弹出权限错误对话框
  - 操作/命令：`.venv/bin/python -m sniffer gui`（无 sudo）
  - 预期：弹窗提示权限不足与 sudo 用法，界面不崩溃
  - 实际结果：待采集

## 第三阶段（子阶段 a：详情栏 + 十六进制/ASCII 视图）

### 已采集（自动化、真实输出）

- 文件：`logs/stage3_headless_tests.log`
  - 采集日期：2026-11-19
  - 场景：无头单元验证（合成包）——协议分层解析 dissect_layers（Ether/IP/TCP、IPv6/UDP、ICMP、ARP）、
    端口显示为数字（不臆断应用层）、hex/ASCII 格式化、选中序号→取回包对象、有界淘汰释放 raw、
    MainWindow 三栏构建 + 选中渲染详情树/hex（offscreen）
  - 操作/命令：
    - `python tests/test_dissect.py`
    - `QT_QPA_PLATFORM=offscreen python tests/test_gui_headless.py`
    - `QT_QPA_PLATFORM=offscreen python tests/test_packet_model.py`
  - 预期：全部断言通过，退出码 0
  - 实际结果：见日志（全部通过）
  - 代码版本：第三阶段子阶段 a（未提交，待用户确认）
  - 报告用途：证明分层解析/hex/映射/内存释放核心逻辑正确
  - 脱敏：合成数据，无敏感信息

### 待手动采集/验证（需 GUI 窗口 / root / 人工点击，助手无法代办）

- 文件：`screenshots/stage3_three_pane.png` —— **待手动采集**
  - 场景：三栏布局总览（上=Packet List，下左=详情树，下右=十六进制/ASCII）
  - 操作/命令：`sudo .venv/bin/python -m sniffer gui`，抓到若干包后观察三栏
  - 预期：三栏可见、可用 QSplitter 拖拽调整

- 文件：`screenshots/stage3_detail_tree.png` —— **待手动采集**
  - 场景：点击列表某包 → 详情栏按协议层展开（Ethernet/IP 或 IPv6/TCP 或 UDP/ICMP/ARP …）
  - 操作/命令：点选一行 TCP 或 UDP 包，展开各层查看字段（地址/端口数字/标志位/长度）
  - 预期：分层正确、端口显示为**数字**、无 HTTP 等应用层标签

- 文件：`screenshots/stage3_hexdump.png` —— **待手动采集**
  - 场景：同一选中包的十六进制 + ASCII 视图（偏移/hex/ASCII 三段，等宽对齐，不可见字节为 '.'）
  - 操作/命令：选中包后看右下 hex 栏
  - 预期：字节与 Wireshark 对照一致
