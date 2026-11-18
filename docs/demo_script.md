# 演示录屏脚本（demo_script.md）

持续更新：录屏步骤、讲解要点、对应证据。本阶段=第二阶段（最简 GUI 实时包列表）。

## 第二阶段录屏步骤（待录制）

1. 环境说明（口播）：macOS arm64 + venv(Python 3.12) + Scapy(libpcap 后端) + PySide6。
2. 启动：终端执行 `sudo .venv/bin/python -m sniffer gui`，展示主界面。
   - 讲解：为何需要 sudo（抓包要访问 /dev/bpf*）。
3. 选网卡（如 en0），BPF 过滤框演示：
   - 先留空点「开始」，看全量实时抓包；状态「● 运行中」。
   - 讲解：BPF 抓包过滤在**内核层**，不匹配的包内核即丢弃；与第三阶段「显示过滤」区别。
4. 制造可控流量：另开终端 `curl http://example.com` 或 `ping` 本网关，观察表格实时增行。
5. 停止：点「停止」，状态回到「■ 已停止」，按钮恢复；再「开始」验证可重入。
6. 关窗：验证无异常、进程干净退出。
7. 错误处理（可选）：不加 sudo 启动并点「开始」，展示权限错误弹窗。

## 讲解要点（答辩）

- 线程模型：QObject worker + moveToThread；子线程只发信号、不碰 Widget。
- 停止干净：select 轮询 0.2s 检查 stop 事件，空闲也能及时退出；finally 关 socket。
- 有界缓存 + QTimer 200ms 批量刷新：高流量不卡、内存不无限涨（缓冲丢最旧 + 表格行上限）。
- 协议列只做链路/网络/传输层标识，不按端口臆断应用层（协议判定审慎）。

## 对应证据

- 自动化验证：`evidence/logs/stage2_headless_tests.log`
- 截图：`evidence/screenshots/stage2_*.png`（**待手动采集**，见 index.md）
- 设计示意图：`evidence/diagrams/threading_model.md`
