use crate::models::{
    MonitorSettings, TlsFlowEvent, TlsInstallationInfo, TlsMonitorSessionStatus,
    TlsMonitorStatus,
};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_RECENT_FLOWS: usize = 100;
const FLOW_LOG_TAIL_BYTES: u64 = 512 * 1024;
const HARD_EXCLUDED_PROCESSES: &[&str] = &[
    "virtualbox",
    "vboxsvc",
    "vboxheadless",
    "vmware",
    "vmnet",
    "wireguard",
    "openvpn",
    "tailscale",
    "clash",
    "sing-box",
    "surge",
    "tun2socks",
];
const MITMPROXY_INSTALL_URL: &str = "https://docs.mitmproxy.org/stable/overview/installation/";
const MITMPROXY_DOWNLOAD_URL: &str = "https://mitmproxy.org/";
const INSTALL_MARKER_FILE: &str = "engine-install.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct InstallRecord {
    package_manager: String,
    installed_at: u64,
}

#[derive(Debug, Clone)]
struct InstallPlan {
    manager: Option<String>,
    program: Option<String>,
    args: Vec<String>,
    display_command: String,
    uninstall_command: Option<String>,
    manual_note: String,
}

struct AddonConfig {
    capture_body_preview: bool,
    capture_headers: bool,
    body_preview_bytes: u32,
    redact_query_strings: bool,
    target_pid: u32,
    flow_limit: usize,
}

#[derive(Default)]
pub struct TlsMonitorManager {
    sessions: BTreeMap<u32, TlsMonitorSession>,
}

struct TlsMonitorSession {
    child: Option<Child>,
    target_pid: u32,
    process_name: String,
    engine: Option<String>,
    ca_path: PathBuf,
    flow_log_path: PathBuf,
    engine_log_path: PathBuf,
    last_error: Option<String>,
}

impl Drop for TlsMonitorManager {
    fn drop(&mut self) {
        self.stop_all();
    }
}

impl TlsMonitorManager {
    pub fn start(
        &mut self,
        data_dir: &Path,
        settings: &MonitorSettings,
        pid: u32,
        process_name: &str,
    ) -> Result<TlsMonitorStatus, String> {
        if settings.tls_mode != "local_proxy" {
            return Err(
                "请先在设置中选择“单应用 TLS 解密代理”；默认的元数据模式不会接管任何连接。"
                    .to_string(),
            );
        }
        if is_excluded_process(process_name, &settings.tls_excluded_processes) {
            return Err(format!(
                "已拒绝监控 {process_name}：它属于 VirtualBox、VPN 或代理保护名单，不会被接管。"
            ));
        }
        self.refresh_children();
        if self
            .sessions
            .get(&pid)
            .and_then(|session| session.child.as_ref())
            .is_some()
        {
            return Ok(self.status(data_dir, settings));
        }

        let engine = resolve_engine(&settings.tls_engine_path)?;
        // Each PID owns its own mitmproxy working directory. This prevents
        // concurrent engines from racing on the addon, CA cache, log, and
        // JSONL compaction files.
        let directory = data_dir.join("tls-monitor").join(format!("pid-{pid}"));
        fs::create_dir_all(&directory)
            .map_err(|error| format!("无法创建 TLS 监控目录：{error}"))?;
        let flow_log_path = directory.join("flows.jsonl");
        let addon_path = directory.join("sentinel_flow_addon.py");
        let ca_path = directory.join("mitmproxy-ca-cert.pem");
        let addon_config = AddonConfig {
            capture_body_preview: settings.tls_capture_body_preview,
            capture_headers: settings.tls_capture_headers,
            body_preview_bytes: settings.tls_body_preview_bytes,
            redact_query_strings: settings.tls_redact_query_strings,
            target_pid: pid,
            flow_limit: bounded_flow_limit(settings.tls_recent_flow_limit),
        };
        write_addon(&addon_path, &flow_log_path, &addon_config)?;
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&flow_log_path)
            .map_err(|error| format!("无法初始化 TLS 流量日志：{error}"))?;
        compact_flow_log(
            &flow_log_path,
            bounded_flow_limit(settings.tls_recent_flow_limit),
        )?;

        // Local Capture is a transparent per-process mode. It does not expose a
        // proxy listener, so appending @host:port would make the mode invalid.
        let mode = format!("local:{pid}");
        let engine_log_path = directory.join("mitmdump.log");
        let engine_log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&engine_log_path)
            .map_err(|error| format!("无法初始化 TLS 引擎日志：{error}"))?;
        let engine_error_log = engine_log
            .try_clone()
            .map_err(|error| format!("无法复制 TLS 引擎日志句柄：{error}"))?;
        let mut command = Command::new(&engine);
        command
            .args([
                "--mode",
                &mode,
                "--set",
                &format!("confdir={}", directory.display()),
                "--set",
                "ssl_insecure=false",
                "-s",
                &addon_path.to_string_lossy(),
            ])
            .stdout(engine_log)
            .stderr(engine_error_log);
        let child = command
            .spawn()
            .map_err(|error| format!("无法启动 TLS 监控引擎 {engine}：{error}"))?;

        self.sessions.insert(
            pid,
            TlsMonitorSession {
                child: Some(child),
                target_pid: pid,
                process_name: process_name.to_string(),
                engine: Some(engine),
                ca_path,
                flow_log_path,
                engine_log_path,
                last_error: None,
            },
        );
        Ok(self.status(data_dir, settings))
    }

    pub fn stop(&mut self, pid: u32) {
        if let Some(session) = self.sessions.get_mut(&pid) {
            stop_child(session);
        }
    }

    pub fn stop_all(&mut self) {
        for session in self.sessions.values_mut() {
            stop_child(session);
        }
    }

    pub fn status(&mut self, data_dir: &Path, settings: &MonitorSettings) -> TlsMonitorStatus {
        self.refresh_children();
        let recent_flow_limit = bounded_flow_limit(settings.tls_recent_flow_limit);
        let sessions: Vec<TlsMonitorSessionStatus> = self
            .sessions
            .values()
            .map(|session| self.session_status(session, recent_flow_limit))
            .collect();
        let running_sessions: Vec<&TlsMonitorSessionStatus> =
            sessions.iter().filter(|session| session.running).collect();
        let primary = running_sessions
            .first()
            .copied()
            .or_else(|| sessions.last());
        let running_count = running_sessions.len();
        let running = running_count > 0;
        let mut recent_flows = sessions
            .iter()
            .flat_map(|session| session.recent_flows.iter().cloned())
            .collect::<Vec<_>>();
        recent_flows.sort_by_key(|flow| flow.timestamp);
        if recent_flows.len() > MAX_RECENT_FLOWS {
            recent_flows.drain(0..recent_flows.len() - MAX_RECENT_FLOWS);
        }
        TlsMonitorStatus {
            running,
            running_count,
            mode: settings.tls_mode.clone(),
            target_pid: primary.map(|session| session.target_pid),
            listener: if running_count == 0 {
                if sessions.is_empty() {
                    "未启动（不修改系统代理）".to_string()
                } else {
                    format!("未运行（保留 {} 个会话历史）", sessions.len())
                }
            } else if running_count == 1 {
                format!(
                    "local capture · PID {} · 透明出站捕获",
                    running_sessions[0].target_pid
                )
            } else {
                format!("local capture · {running_count} 个进程 · 透明出站捕获")
            },
            engine: primary.and_then(|session| session.engine.clone()).or_else(|| {
                (!settings.tls_engine_path.is_empty()).then(|| settings.tls_engine_path.clone())
            }),
            ca_ready: primary.is_some_and(|session| session.ca_ready),
            ca_path: primary.and_then(|session| session.ca_path.clone()),
            flow_log_path: primary.and_then(|session| session.flow_log_path.clone()),
            recent_flows,
            recent_flow_limit,
            engine_log_path: primary.and_then(|session| session.engine_log_path.clone()),
            last_error: sessions.iter().find_map(|session| session.last_error.clone()),
            note: if running_count > 0 {
                format!(
                    "同时捕获 {running_count} 个用户选择的 PID；不改系统代理、不改默认路由、不创建 TUN，也不会接管 VirtualBox/VPN 保护名单。每个 PID 使用独立引擎和流日志，只记录启动监控后的新流。"
                )
            } else if settings.tls_mode == "local_proxy" {
                "选择进程详情中的“启动 TLS 监控”后才会捕获该 PID；现在支持同时监控多个进程。目标应用仍需信任本地 CA，证书锁定可能导致连接失败。".to_string()
            } else if settings.tls_mode == "keylog" {
                "无证书模式只读取目标进程启动前导出的 SSLKEYLOGFILE，并需要对应抓包；不会改变网络路径。".to_string()
            } else {
                "当前只显示 TLS 元数据，不接管连接。".to_string()
            },
            sessions,
        }
    }

    pub fn is_running(&mut self) -> bool {
        self.refresh_children();
        self.sessions
            .values()
            .any(|session| session.child.is_some())
    }

    fn refresh_children(&mut self) {
        for session in self.sessions.values_mut() {
            let Some(child) = session.child.as_mut() else {
                continue;
            };
            match child.try_wait() {
                Ok(Some(status)) => {
                    let log_note = read_log_tail(&session.engine_log_path)
                        .filter(|text| !text.trim().is_empty())
                        .map(|text| format!("；引擎日志：{text}"))
                        .unwrap_or_default();
                    session.last_error = Some(format!(
                        "PID {} 的 TLS 监控引擎已退出（{status}）{log_note}",
                        session.target_pid
                    ));
                    session.child = None;
                }
                Ok(None) => {}
                Err(error) => {
                    session.last_error = Some(format!(
                        "PID {} 无法读取 TLS 监控引擎状态：{error}",
                        session.target_pid
                    ));
                    session.child = None;
                }
            }
        }
    }

    fn session_status(
        &self,
        session: &TlsMonitorSession,
        recent_flow_limit: usize,
    ) -> TlsMonitorSessionStatus {
        TlsMonitorSessionStatus {
            running: session.child.is_some(),
            target_pid: session.target_pid,
            process_name: session.process_name.clone(),
            listener: if session.child.is_some() {
                format!("local capture · PID {} · 透明出站捕获", session.target_pid)
            } else {
                format!("未运行（上次监控 PID {}）", session.target_pid)
            },
            engine: session.engine.clone(),
            ca_path: Some(session.ca_path.to_string_lossy().into_owned()),
            ca_ready: session.ca_path.is_file(),
            flow_log_path: Some(session.flow_log_path.to_string_lossy().into_owned()),
            recent_flows: read_recent_flows(
                &session.flow_log_path,
                recent_flow_limit,
                Some(session.target_pid),
            ),
            engine_log_path: Some(session.engine_log_path.to_string_lossy().into_owned()),
            last_error: session.last_error.clone(),
        }
    }
}

fn stop_child(session: &mut TlsMonitorSession) {
    if let Some(mut child) = session.child.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

pub fn installation_info(data_dir: &Path) -> TlsInstallationInfo {
    let (engine_path, version) = probe_engine();
    let marker = read_install_record(data_dir);
    let plan = marker
        .as_ref()
        .and_then(|record| plan_for_manager(&record.package_manager))
        .unwrap_or_else(install_plan);
    let package_manager = if engine_path.is_some() {
        marker
            .map(|record| record.package_manager)
            .or(plan.manager.clone())
    } else {
        None
    };
    let uninstall_command = package_manager
        .as_deref()
        .and_then(|manager| plan_for_manager(manager).and_then(|item| item.uninstall_command));

    TlsInstallationInfo {
        platform: platform_name().to_string(),
        installed: engine_path.is_some(),
        engine_path,
        version,
        package_manager,
        install_command: plan.display_command,
        uninstall_command,
        official_url: MITMPROXY_INSTALL_URL.to_string(),
        manual_note: plan.manual_note,
        last_output: None,
    }
}

pub fn install_engine(data_dir: &Path) -> Result<TlsInstallationInfo, String> {
    let current = installation_info(data_dir);
    if current.installed {
        return Ok(current);
    }
    let plan = install_plan();
    let (program, args, manager) = match (plan.program, plan.manager) {
        (Some(program), Some(manager)) => (program, plan.args, manager),
        _ => {
            return Err(format!(
                "当前 {} 没有可执行的一键安装工具。{} 官方下载地址：{}",
                platform_name(),
                plan.manual_note,
                MITMPROXY_DOWNLOAD_URL
            ));
        }
    };
    let output = run_command(&program, &args)?;
    let directory = data_dir.join("tls-monitor");
    fs::create_dir_all(&directory).map_err(|error| format!("无法创建 TLS 监控目录：{error}"))?;
    let marker = InstallRecord {
        package_manager: manager,
        installed_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default(),
    };
    let marker_path = directory.join(INSTALL_MARKER_FILE);
    let content = serde_json::to_string_pretty(&marker)
        .map_err(|error| format!("无法记录 TLS 引擎安装来源：{error}"))?;
    fs::write(&marker_path, content)
        .map_err(|error| format!("无法记录 TLS 引擎安装来源：{error}"))?;

    let mut result = installation_info(data_dir);
    result.last_output = Some(output);
    if !result.installed {
        return Err(
            "安装命令已完成，但 PATH 中仍找不到 mitmdump。请重启应用，或在设置中填写 mitmdump 的绝对路径。"
                .to_string(),
        );
    }
    Ok(result)
}

pub fn uninstall_engine(
    data_dir: &Path,
    monitor_running: bool,
) -> Result<TlsInstallationInfo, String> {
    if monitor_running {
        return Err("请先停止正在运行的 TLS 监控，再卸载引擎".to_string());
    }
    let marker = read_install_record(data_dir).ok_or_else(|| {
        "没有找到由 Sentinel Flow 安装的引擎记录。为避免误删手工安装或系统包，请从原安装渠道卸载。"
            .to_string()
    })?;
    let plan = plan_for_manager(&marker.package_manager)
        .ok_or_else(|| "当前平台不支持该安装来源的自动卸载".to_string())?;
    let (program, args) = plan
        .program
        .zip(Some(plan.args))
        .ok_or_else(|| "当前平台没有可执行的一键卸载工具".to_string())?;
    let output = run_command(&program, &args)?;
    let marker_path = data_dir.join("tls-monitor").join(INSTALL_MARKER_FILE);
    let _ = fs::remove_file(marker_path);
    let mut result = installation_info(data_dir);
    result.last_output = Some(output);
    Ok(result)
}

fn install_plan() -> InstallPlan {
    #[cfg(target_os = "macos")]
    {
        if command_available("brew") {
            return plan_for_manager("homebrew-cask").expect("homebrew plan exists");
        }
    }
    if command_available("uv") {
        return plan_for_manager("uv").expect("uv plan exists");
    }
    #[cfg(target_os = "windows")]
    {
        if command_available("py") {
            return plan_for_manager("pip-py").expect("py pip plan exists");
        }
        if command_available("python") {
            return plan_for_manager("pip-python").expect("python pip plan exists");
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if command_available("python3") {
            return plan_for_manager("pip-python3").expect("python3 pip plan exists");
        }
        if command_available("python") {
            return plan_for_manager("pip-python").expect("python pip plan exists");
        }
    }
    let command = if cfg!(target_os = "macos") {
        "brew install --cask mitmproxy"
    } else if cfg!(target_os = "windows") {
        "py -m pip install --user mitmproxy"
    } else {
        "uv tool install mitmproxy"
    };
    InstallPlan {
        manager: None,
        program: None,
        args: Vec::new(),
        display_command: command.to_string(),
        uninstall_command: None,
        manual_note:
            "未找到可用的本地安装工具，请先按官方文档安装 Homebrew/uv/Python，或下载官方安装包。"
                .to_string(),
    }
}

fn plan_for_manager(manager: &str) -> Option<InstallPlan> {
    let plan = match manager {
        "homebrew-cask" => InstallPlan {
            manager: Some(manager.to_string()),
            program: Some("brew".to_string()),
            args: vec![
                "install".to_string(),
                "--cask".to_string(),
                "mitmproxy".to_string(),
            ],
            display_command: "brew install --cask mitmproxy".to_string(),
            uninstall_command: Some("brew uninstall --cask mitmproxy".to_string()),
            manual_note: "macOS 官方推荐 Homebrew；不会安装或信任 CA，也不会修改系统代理。"
                .to_string(),
        },
        "uv" => InstallPlan {
            manager: Some(manager.to_string()),
            program: Some("uv".to_string()),
            args: vec![
                "tool".to_string(),
                "install".to_string(),
                "mitmproxy".to_string(),
            ],
            display_command: "uv tool install mitmproxy".to_string(),
            uninstall_command: Some("uv tool uninstall mitmproxy".to_string()),
            manual_note:
                "使用 mitmproxy 官方文档列出的 uv/PyPI 安装方式；安装仅限当前用户工具环境。"
                    .to_string(),
        },
        "pip-py" => pip_plan(
            "py",
            "py -m pip install --user mitmproxy",
            "py -m pip uninstall -y mitmproxy",
        ),
        "pip-python" => pip_plan(
            "python",
            "python -m pip install --user mitmproxy",
            "python -m pip uninstall -y mitmproxy",
        ),
        "pip-python3" => pip_plan(
            "python3",
            "python3 -m pip install --user mitmproxy",
            "python3 -m pip uninstall -y mitmproxy",
        ),
        _ => return None,
    };
    Some(plan)
}

fn pip_plan(program: &str, install: &str, uninstall: &str) -> InstallPlan {
    InstallPlan {
        manager: Some(format!("pip-{program}")),
        program: Some(program.to_string()),
        args: vec![
            "-m".to_string(),
            "pip".to_string(),
            "install".to_string(),
            "--user".to_string(),
            "mitmproxy".to_string(),
        ],
        display_command: install.to_string(),
        uninstall_command: Some(uninstall.to_string()),
        manual_note:
            "使用 mitmproxy 官方文档列出的 PyPI 安装路径；如果系统阻止写入，请改用官方安装包。"
                .to_string(),
    }
}

fn platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        "当前平台"
    }
}

fn command_available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn run_command(program: &str, args: &[String]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("无法执行安装命令 {program}：{error}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&stderr);
    }
    let text = truncate_output(text);
    if output.status.success() {
        Ok(text)
    } else {
        Err(format!("安装命令执行失败（{}）：{}", output.status, text))
    }
}

fn truncate_output(mut output: String) -> String {
    const MAX_OUTPUT_CHARS: usize = 6000;
    if output.chars().count() > MAX_OUTPUT_CHARS {
        output = output.chars().take(MAX_OUTPUT_CHARS).collect::<String>();
        output.push_str("\n…输出已截断");
    }
    output
}

fn probe_engine() -> (Option<String>, Option<String>) {
    let Ok(output) = Command::new("mitmdump").arg("--version").output() else {
        return (None, None);
    };
    if !output.status.success() {
        return (None, None);
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (
        Some("mitmdump".to_string()),
        (!version.is_empty()).then_some(version),
    )
}

fn read_install_record(data_dir: &Path) -> Option<InstallRecord> {
    let path = data_dir.join("tls-monitor").join(INSTALL_MARKER_FILE);
    let content = fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

pub fn is_excluded_process(process_name: &str, configured: &[String]) -> bool {
    let lower = process_name.to_lowercase();
    HARD_EXCLUDED_PROCESSES
        .iter()
        .copied()
        .chain(configured.iter().map(String::as_str))
        .filter(|value| !value.trim().is_empty())
        .any(|value| lower.contains(&value.to_lowercase()))
}

fn resolve_engine(configured: &str) -> Result<String, String> {
    if !configured.trim().is_empty() {
        if !Path::new(configured).is_file() {
            return Err(format!("TLS 引擎路径不存在：{configured}"));
        }
        return Ok(configured.to_string());
    }
    let output = Command::new("mitmdump")
        .arg("--version")
        .output()
        .map_err(|_| {
            "未找到 mitmdump。请安装 mitmproxy，或在设置中填写 mitmdump 的绝对路径".to_string()
        })?;
    if output.status.success() {
        Ok("mitmdump".to_string())
    } else {
        Err("mitmdump 无法运行。请检查安装，或在设置中填写 TLS 引擎路径".to_string())
    }
}

fn bounded_flow_limit(value: u16) -> usize {
    usize::from(value.clamp(1, MAX_RECENT_FLOWS as u16))
}

fn read_log_tail(path: &Path) -> Option<String> {
    let metadata = fs::metadata(path).ok()?;
    let mut file = File::open(path).ok()?;
    let start = metadata.len().saturating_sub(16 * 1024);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).trim().to_string())
}

fn compact_flow_log(path: &Path, limit: usize) -> Result<(), String> {
    let Ok(metadata) = fs::metadata(path) else {
        return Ok(());
    };
    if metadata.len() == 0 {
        return Ok(());
    }
    let items = read_recent_flows(path, limit, None);
    if items.is_empty() {
        return Ok(());
    }
    let mut content = String::new();
    for item in items {
        let line = serde_json::to_string(&item)
            .map_err(|error| format!("无法整理 TLS 流量日志：{error}"))?;
        content.push_str(&line);
        content.push('\n');
    }
    fs::write(path, content).map_err(|error| format!("无法整理 TLS 流量日志：{error}"))
}

fn write_addon(path: &Path, log_path: &Path, config: &AddonConfig) -> Result<(), String> {
    let log_literal = serde_json::to_string(&log_path.to_string_lossy().to_string())
        .map_err(|error| format!("无法生成 TLS 日志脚本：{error}"))?;
    let capture_literal = if config.capture_body_preview {
        "True"
    } else {
        "False"
    };
    let headers_literal = if config.capture_headers {
        "True"
    } else {
        "False"
    };
    let redact_query_literal = if config.redact_query_strings {
        "True"
    } else {
        "False"
    };
    let preview_bytes = config.body_preview_bytes.clamp(0, 65_536);
    let target_pid = config.target_pid;
    let flow_limit = config.flow_limit;
    let source = format!(
        r#"from mitmproxy import http, tcp, websocket
import base64
import hashlib
import json
import os
import time

LOG_PATH = {log_literal}
CAPTURE_BODY_PREVIEW = {capture_literal}
CAPTURE_HEADERS = {headers_literal}
REDACT_QUERY_STRINGS = {redact_query_literal}
MAX_PREVIEW_BYTES = {preview_bytes}
TARGET_PID = {target_pid}
MAX_STORED_EVENTS = {flow_limit}

def _content_type(headers):
    try:
        return headers.get("content-type")
    except Exception:
        return None

def _safe_url(request):
    value = getattr(request, "pretty_url", "") or ""
    if not REDACT_QUERY_STRINGS:
        return value
    return value.split("?", 1)[0] + ("?<redacted>" if "?" in value else "")

def _headers(headers):
    if not CAPTURE_HEADERS:
        return None
    return {{str(key): str(value) for key, value in headers.items()}}

def _preview(body, content_type):
    if not CAPTURE_BODY_PREVIEW or not body or MAX_PREVIEW_BYTES <= 0:
        return None, None
    sample = body[:MAX_PREVIEW_BYTES]
    content_type = (content_type or "").lower()
    if content_type.startswith("text/") or any(value in content_type for value in ("json", "xml", "javascript", "x-www-form-urlencoded")):
        return sample.decode("utf-8", errors="replace"), "utf-8"
    return base64.b64encode(sample).decode("ascii"), "base64"

def _server_host(flow):
    try:
        address = flow.server_conn.address
        if address:
            return f"{{address[0]}}:{{address[1]}}"
    except Exception:
        pass
    return ""

def _emit(flow, direction, message, status=None, protocol="http", url="", method=None, headers=None, host=None):
    body = message.content or b""
    content_type = _content_type(getattr(message, "headers", {{}}))
    body_preview, body_preview_encoding = _preview(body, content_type)
    event = {{
        "timestamp": int(time.time()),
        "direction": direction,
        "target_pid": TARGET_PID,
        "protocol": protocol,
        "host": host or getattr(flow.request, "pretty_host", "") or getattr(flow.request, "host", "") if hasattr(flow, "request") else ( _server_host(flow) or ""),
        "url": url or (_safe_url(flow.request) if hasattr(flow, "request") else ""),
        "method": method if method is not None else (getattr(flow.request, "method", None) if hasattr(flow, "request") else None),
        "status": status,
        "content_type": content_type,
        "headers": _headers(getattr(message, "headers", {{}})),
        "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest() if body else None,
        "body_preview": body_preview,
        "body_preview_encoding": body_preview_encoding,
    }}
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=False) + "\n")

    with open(LOG_PATH, "r", encoding="utf-8") as stream:
        lines = stream.readlines()
    if len(lines) > MAX_STORED_EVENTS:
        with open(LOG_PATH, "w", encoding="utf-8") as stream:
            stream.writelines(lines[-MAX_STORED_EVENTS:])

def request(flow: http.HTTPFlow):
    _emit(flow, "request", flow.request)

def response(flow: http.HTTPFlow):
    _emit(flow, "response", flow.response, flow.response.status_code)

def tcp_message(flow: tcp.TCPFlow):
    if not flow.messages:
        return
    message = flow.messages[-1]
    _emit(
        flow,
        "request" if message.from_client else "response",
        message,
        protocol="tcp",
        host=_server_host(flow),
    )

def websocket_message(flow: websocket.WebSocketFlow):
    if not flow.messages:
        return
    message = flow.messages[-1]
    _emit(
        flow,
        "request" if message.from_client else "response",
        message,
        protocol="websocket",
        url=_safe_url(flow.handshake_flow.request),
        method="MESSAGE",
        host=getattr(flow.handshake_flow.request, "pretty_host", "") or "",
    )
"#
    );
    fs::write(path, source).map_err(|error| format!("无法写入 TLS 日志脚本：{error}"))
}

fn read_recent_flows(path: &Path, limit: usize, target_pid: Option<u32>) -> Vec<TlsFlowEvent> {
    let Ok(metadata) = fs::metadata(path) else {
        return Vec::new();
    };
    let Ok(mut file) = File::open(path) else {
        return Vec::new();
    };
    let start = metadata.len().saturating_sub(FLOW_LOG_TAIL_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut bytes = Vec::new();
    if file.read_to_end(&mut bytes).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut items: Vec<TlsFlowEvent> = text
        .lines()
        .filter_map(|line| serde_json::from_str::<TlsFlowEvent>(line).ok())
        .filter(|flow| target_pid.is_none() || flow.target_pid == target_pid)
        .collect();
    if start > 0 {
        // The first line may be truncated because the tail starts in the middle of a record.
        items.shrink_to_fit();
    }
    if items.len() > limit {
        items.drain(0..items.len() - limit);
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protects_virtualization_and_proxy_processes() {
        let configured = vec!["my-vpn".to_string()];
        assert!(is_excluded_process("VirtualBoxVM", &configured));
        assert!(is_excluded_process("My-VPN-Agent", &configured));
        assert!(!is_excluded_process("TalkTunnel", &configured));
    }

    #[test]
    fn addon_redacts_query_strings_and_does_not_include_headers() {
        let path = std::env::temp_dir().join("sentinel-flow-addon-test.py");
        let config = AddonConfig {
            capture_body_preview: false,
            capture_headers: true,
            body_preview_bytes: 4096,
            redact_query_strings: false,
            target_pid: 42,
            flow_limit: 20,
        };
        write_addon(&path, Path::new("/tmp/sentinel-flow.jsonl"), &config).unwrap();
        let source = fs::read_to_string(&path).unwrap();
        assert!(source.contains("<redacted>"));
        assert!(source.contains("CAPTURE_HEADERS = True"));
        assert!(source.contains("def tcp_message"));
        assert!(source.contains("def websocket_message"));
        if command_available("python3") {
            let status = Command::new("python3")
                .args(["-m", "py_compile", &path.to_string_lossy()])
                .status()
                .unwrap();
            assert!(status.success());
        }
        let _ = fs::remove_file(path);
    }
}
