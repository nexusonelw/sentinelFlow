# Sentinel Flow

Sentinel Flow 是一个 local-first 的跨平台 Agent 文件与网络流量监控 MVP。它的核心问题不是“哪个 IP 流量大”，而是把网络行为归属回具体的进程实例、根应用和连接目标。

## 当前可用能力

- Tauri 2 桌面应用、系统托盘和后台常驻
- React 实时仪表盘、上传/下载曲线、进程排行、风险分布与事件时间线
- 可调单进程每分钟上传阈值
- Agent 及子进程归属提示，覆盖 Codex、Claude Code、Grok CLI、Harness、Cursor、Windsurf 等常见命名
- VPN / 代理进程识别；观测与识别本身不会修改、阻断或解密任何连接
- macOS：通过系统 `nettop` 读取真实的进程级累计收发字节，通过 `lsof` 关联活动连接目标
- 点开进程后按需深查：完整命令行（敏感凭据遮蔽）、实际脚本/模块、启动参数、工作目录、完整父进程链、TCP/UDP 状态与本地/远端端点
- 活动进程列表可一键复制 AI 分析上下文：合并当前进程详情、上传/下载观测、文件与连接证据、风险事件及预设分析提示词；进程退出时自动回退到最近快照
- 进程列表可一键持久禁止联网并手动解禁；按可执行文件保存规则，操作前校验 PID 与路径并请求系统管理员授权
- Windows：使用入站/出站 Windows Defender 防火墙规则；Linux：使用 cgroup v2、iptables 和开机守护服务持续约束同一路径的新进程
- macOS：接入系统 Application Firewall 的持久应用封禁；受 Apple 原生能力限制，该接口主要管理入站连接，完整出站拦截仍需要带授权的 Network Extension
- macOS 文件证据关联：展示经过运行时文件过滤的项目/媒体/文档/归档访问证据、访问模式、文件大小和读取偏移；不再把打开句柄标记为“候选上传源”
- 程序上传统计：进程详情内提供近 180 天按天汇总，并可下钻到小时、30 分钟时间桶、来源地址与上传量；仅写入 SQLite 聚合统计，不保存上传内容，后台微批写入并自动清理过期数据
- TLS 客户端监控：设置中可选择无侵入元数据、SSLKEYLOGFILE 或单应用本地解密代理；本地解密模式按 PID 启动独立的 `mitmdump --mode local:<PID>` 会话，可同时监控多个用户明确选择的进程
- 云端数据边界：应用监控数据、进程详情、TLS 流记录和上传统计默认只保存在本机；项目没有把这些数据发送到 Sentinel Flow 云端的客户端接口。云端只在发布流程中接收 GitHub Release 安装包附件
- Windows / Linux：进程图正常工作；网络字节进入安全降级模式，等待 WFP / eBPF 原生适配器，不显示伪造数据

## 本地运行

```bash
npm install
npm run tauri dev
```

只预览界面：

```bash
npm run dev
```

浏览器预览会明确标注为预览数据；Tauri 桌面端会自动切换到真实本机采集。

## 安全边界

当前版本不会修改系统全局代理、默认路由或 TUN/虚拟网卡，也不会自动接管 VirtualBox、VPN 或代理进程。单应用解密模式需要额外安装 `mitmproxy`/`mitmdump`，并且目标应用必须信任其本地 CA；证书会由引擎生成到应用数据目录，但本程序不会静默把它加入系统信任库。证书锁定应用可能拒绝连接。若要使用无证书方案，目标进程必须在启动前导出 `SSLKEYLOGFILE`，并取得同一连接的抓包，再由 TLS 解码器使用会话密钥；已经运行的进程不能被本程序事后补注入密钥导出。完整、持续的系统级文件事件仍需要 Apple Endpoint Security entitlement；Linux 本地捕获可能需要 eBPF 与管理员授权。

### TLS 监控依赖

单应用解密模式使用 mitmproxy 的 local capture：打开设置中的 TLS 客户端监控即可看到当前平台、引擎状态、官方文档和可执行命令。用户可在页面点击“一键安装 mitmproxy”，也可以复制命令手动执行；安装完成后重新探测 `mitmdump --version`，再保存 `local_proxy` 模式并在目标进程详情点击“启动此进程 TLS 监控”。后端使用官方的 `--mode local:<PID>` 语法，不会把普通代理监听端口拼到 local capture 参数中。每个 PID 使用独立的 mitmproxy 子进程、CA 缓存、引擎日志和流日志，因此可以同时监控多个进程；进程详情中的“停止此进程 TLS 监控”只停止对应 PID，进程列表上方和设置页的“一键停止所有 TLS 监控”会停止所有会话，但保留已经记录的历史流。启动后只记录新产生的 HTTP、WebSocket 或 TCP 流，已有 TLS 会话不能回溯解密；目标应用仍需信任 CA，证书锁定、QUIC 或专有协议可能没有可见正文。设置页可配置最近保留 1–100 条流（默认 20 条），磁盘日志也会滚动裁剪到该上限；请求头、完整 URL 查询参数和有限正文预览都可单独控制。请求头可能包含 Cookie/Authorization，正文预览上限为 4–64 KB。macOS 优先使用官方文档推荐的 `brew install --cask mitmproxy`；Windows/Linux 优先使用已存在的 `uv tool install mitmproxy`，否则使用用户级 Python/PyPI 方式，官方安装包作为手工兜底。页面的卸载按钮只撤销由 Sentinel Flow 记录的安装来源，且运行中的监控禁止卸载。安装和卸载不会自动信任 CA、修改系统代理、默认路由、TUN/VPN 或 VirtualBox；首次启动后设置页会显示 CA 文件路径，用户需要自行确认是否将它信任到目标应用使用的证书库。

所有进程名、连接目标、流量记录和风险分析均留在本机。

### 跨平台打包与下载

版本号统一由 `package.json`、`src-tauri/tauri.conf.json`、`src-tauri/Cargo.toml` 与锁文件维护。执行 `npm run package:local` 会自动递增 patch 版本、追加 `release-log.md`，并在本机生成当前平台安装包。发布前将版本提交并创建同名 Git tag（例如 `v0.1.1`）推送到 GitHub，`.github/workflows/release.yml` 会在 Windows、macOS 和 Linux runner 上构建并把 MSI/NSIS、DMG、AppImage/DEB 上传到 GitHub Release，用户可从 Release 页面直接下载对应平台的安装包。
