# 可复用经验

## [2026-09-19 04:05] 桌面应用安装命令必须补充 PATH

- GUI 应用从 Finder 或桌面启动时，通常不会继承交互式终端中的 Homebrew、uv、pip 用户目录 PATH。
- 仅执行裸命令 `mitmdump` 会导致“安装命令已完成，但 PATH 中仍找不到”的假失败，即使命令实际位于 `/opt/homebrew/bin/mitmdump`。
- 安装、安装后探测、启动运行时必须共用同一套 PATH 补充和可执行文件解析逻辑；探测成功后应把绝对路径回填设置，降低后续启动对 PATH 的依赖。
- 跨平台搜索范围应覆盖 macOS Homebrew/Cask、Linux 的系统与用户 bin/uv 目录、Windows 的 Python Scripts 和 mitmproxy 安装目录，同时避免扫描整个磁盘。
