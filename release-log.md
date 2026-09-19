# Sentinel Flow 发布日志

该文件记录版本递增、本地打包和跨平台 Release 流程。应用监控数据不通过此流程上传；云端上传仅指 GitHub Release 安装包附件。

## 2026-09-19T08:52:51.470Z | v0.1.1

- 版本从 0.1.0 自动递增为 0.1.1（patch）。
- 目标：本地构建 macOS 安装包，并由 GitHub Actions 构建 Windows、macOS、Linux 发布附件。
- 应用监控数据仍保持本地化；本次云端上传仅指 GitHub Release 安装包分发。

## 2026-09-19 | v0.1.1 发布完成

- 本地构建：`src-tauri/target/release/bundle/macos/Sentinel Flow.app`；手工生成 DMG：`src-tauri/target/release/bundle/dmg/Sentinel Flow_0.1.1_aarch64.dmg`。
- 远程提交：`e80ae3f`；发布流程修正提交：`a51d0b2`；版本 tag：`v0.1.1`。
- GitHub Actions run：`35433446129`，Windows、macOS、Linux 三个平台全部成功。
- Release：https://github.com/nexusonelw/sentinelFlow/releases/tag/v0.1.1
- 可下载附件：macOS Universal DMG；Windows x64 EXE/MSI；Linux x86_64 AppImage/DEB/RPM。
- GitHub Actions 的 Node.js 20 弃用提示为平台 warning，不影响本次构建成功。

## 2026-09-19 | TLS 引擎安装路径修复（纳入 v0.1.2）

- 根因：桌面应用从 Finder/启动器启动时通常没有终端继承的 Homebrew、uv 或 Python PATH；旧实现只执行裸命令 `mitmdump`，所以安装命令成功后仍可能误报“PATH 中找不到”。
- 修复：安装命令、安装后探测和启动 TLS 监控统一使用补充 PATH，并搜索 macOS Homebrew、Linux 常见 bin/uv 目录、Windows Python Scripts/mitmproxy 目录及 Homebrew Cask 应用目录。
- 设置页：检测或安装成功后自动回填已解析的 `mitmdump` 绝对路径；手动填写的路径会先执行 `mitmdump --version` 验证，避免保存不可运行文件。
- 验证：`cargo test` 14 项通过；`npm run build` 通过；本机已验证发现 `/opt/homebrew/bin/mitmdump`（Mitmproxy 12.2.3）。
- 修复内容已纳入随后递增的 v0.1.2 发布提交；本次发布仍不执行 mitmproxy 安装或卸载。

## 2026-09-19T11:13:12.632Z | v0.1.2

- 版本从 0.1.1 自动递增为 0.1.2（patch）。
- 目标：本地构建 macOS 安装包，并由 GitHub Actions 构建 Windows、macOS、Linux 发布附件。
- 应用监控数据仍保持本地化；本次云端上传仅指 GitHub Release 安装包分发。
