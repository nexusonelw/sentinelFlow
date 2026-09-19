use crate::{collectors, models::*};
use chrono::Local;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

#[derive(Debug, Clone)]
struct PreviousCounter {
    upload: u64,
    download: u64,
}

pub struct MonitorState {
    system: System,
    pub monitoring: bool,
    pub settings: MonitorSettings,
    previous: HashMap<String, PreviousCounter>,
    last_sample: Option<Instant>,
    timeline: VecDeque<TimelinePoint>,
    events: VecDeque<RiskEvent>,
    alert_cooldown: HashMap<String, u64>,
    session_upload_bytes: u64,
    last_snapshot: Option<MonitorSnapshot>,
    process_history: HashMap<String, ProcessFlow>,
    root_application_cache: HashMap<String, String>,
    cached_platform_sample: PlatformSample,
    last_platform_sample: Option<Instant>,
}

impl Default for MonitorState {
    fn default() -> Self {
        Self {
            // Load only process data on the first sample. `new_all` also loads host-wide
            // memory/CPU/device data that this monitor never serializes into a snapshot.
            system: System::new(),
            monitoring: true,
            settings: MonitorSettings::default(),
            previous: HashMap::new(),
            last_sample: None,
            timeline: VecDeque::with_capacity(60),
            events: VecDeque::with_capacity(100),
            alert_cooldown: HashMap::new(),
            session_upload_bytes: 0,
            last_snapshot: None,
            process_history: HashMap::new(),
            root_application_cache: HashMap::new(),
            cached_platform_sample: PlatformSample::default(),
            last_platform_sample: None,
        }
    }
}

impl MonitorState {
    pub fn latest_snapshot(&mut self) -> MonitorSnapshot {
        if !self.monitoring {
            return self.snapshot();
        }
        self.last_snapshot
            .clone()
            .unwrap_or_else(|| self.snapshot())
    }

    pub fn snapshot(&mut self) -> MonitorSnapshot {
        if !self.monitoring {
            if let Some(mut snapshot) = self.last_snapshot.clone() {
                snapshot.monitoring = false;
                snapshot.collected_at = unix_time();
                snapshot.upload_bps = 0.0;
                snapshot.download_bps = 0.0;
                for process in &mut snapshot.processes {
                    process.upload_bps = 0.0;
                    process.download_bps = 0.0;
                }
                return snapshot;
            }
        }

        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_cmd(UpdateKind::OnlyIfNotSet)
                .with_cwd(UpdateKind::OnlyIfNotSet)
                .with_exe(UpdateKind::OnlyIfNotSet),
        );
        let sample_now = Instant::now();
        if self
            .last_platform_sample
            .map(|last| {
                sample_now.duration_since(last)
                    >= Duration::from_millis(PLATFORM_SAMPLE_INTERVAL_MS)
            })
            .unwrap_or(true)
        {
            self.cached_platform_sample = collectors::collect();
            self.last_platform_sample = Some(sample_now);
        }
        let platform_sample = self.cached_platform_sample.clone();
        let now = unix_time();
        let elapsed = self
            .last_sample
            .map(|last| sample_now.duration_since(last).as_secs_f64())
            .unwrap_or(0.0);

        let mut processes = Vec::new();
        let mut upload_bps = 0.0;
        let mut download_bps = 0.0;
        let mut delta_upload_total = 0_u64;
        let mut pending_events: Vec<(String, String, f64, u64, Option<String>)> = Vec::new();
        let mut next_previous = HashMap::new();

        for (pid_value, process) in self.system.processes() {
            let pid = pid_value.as_u32();
            let name = process.name().to_string_lossy().into_owned();
            let process_instance_id = format!("{}-{}", pid, process.start_time());
            let lower_name = name.to_lowercase();
            let is_agent = is_agent_name(&lower_name);
            let is_proxy = is_proxy_name(&lower_name);
            let counters = platform_sample
                .counters
                .get(&pid)
                .cloned()
                .unwrap_or_default();
            let (process_upload_bps, process_download_bps, upload_delta) = if elapsed > 0.0 {
                if let Some(previous) = self.previous.get(&process_instance_id) {
                    let upload_delta = counters.upload_total.saturating_sub(previous.upload);
                    let download_delta = counters.download_total.saturating_sub(previous.download);
                    (
                        upload_delta as f64 / elapsed,
                        download_delta as f64 / elapsed,
                        upload_delta,
                    )
                } else {
                    (0.0, 0.0, 0)
                }
            } else {
                (0.0, 0.0, 0)
            };
            next_previous.insert(
                process_instance_id.clone(),
                PreviousCounter {
                    upload: counters.upload_total,
                    download: counters.download_total,
                },
            );

            if !(self.settings.monitor_all_apps || self.settings.monitor_agents && is_agent) {
                continue;
            }

            upload_bps += process_upload_bps;
            download_bps += process_download_bps;
            delta_upload_total = delta_upload_total.saturating_add(upload_delta);

            let projected_mb = process_upload_bps * 60.0 / 1_048_576.0;
            let mut risk_score: u8 = 4;
            if is_agent {
                risk_score = risk_score.saturating_add(18);
            }
            if is_proxy {
                risk_score = risk_score.saturating_add(4);
            }
            if projected_mb >= self.settings.threshold_mb_per_minute as f64 {
                risk_score = risk_score.saturating_add(65);
            } else if projected_mb >= self.settings.threshold_mb_per_minute as f64 * 0.5 {
                risk_score = risk_score.saturating_add(32);
            }
            if process_upload_bps > 65_536.0 && process_upload_bps > process_download_bps * 3.0 {
                risk_score = risk_score.saturating_add(10);
            }
            let risk_level = if risk_score >= 70 {
                RiskLevel::High
            } else if risk_score >= 35 {
                RiskLevel::Medium
            } else {
                RiskLevel::Low
            };
            let parent_pid = process.parent().map(|parent| parent.as_u32());
            let root_application =
                if let Some(cached) = self.root_application_cache.get(&process_instance_id) {
                    cached.clone()
                } else {
                    let resolved = resolve_root_application(&self.system, *pid_value, &name);
                    self.root_application_cache
                        .insert(process_instance_id.clone(), resolved.clone());
                    resolved
                };
            let connections = platform_sample
                .connections
                .get(&pid)
                .cloned()
                .unwrap_or_default();
            let active_connection_count = connections.len();
            let mut observed_connection_details = platform_sample
                .connection_details
                .get(&pid)
                .cloned()
                .unwrap_or_default();
            if observed_connection_details.is_empty()
                && (process_upload_bps > 0.0 || process_download_bps > 0.0)
            {
                observed_connection_details.push(NetworkConnectionDetail {
                    protocol: "FLOW".to_string(),
                    local_endpoint: "本机".to_string(),
                    remote_endpoint: "端点已结束（短时流量）".to_string(),
                    state: "OBSERVED".to_string(),
                    is_alive: true,
                    ..NetworkConnectionDetail::default()
                });
            }
            if matches!(risk_level, RiskLevel::High) && process_upload_bps > 0.0 {
                pending_events.push((
                    process_instance_id.clone(),
                    root_application.clone(),
                    projected_mb,
                    upload_delta,
                    connections.first().cloned(),
                ));
            }

            processes.push(ProcessFlow {
                process_instance_id,
                pid,
                parent_pid,
                name,
                executable: process
                    .exe()
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                command_line: redact_command_line(
                    &process
                        .cmd()
                        .iter()
                        .map(|value| value.to_string_lossy().into_owned())
                        .collect::<Vec<_>>(),
                ),
                current_working_directory: process
                    .cwd()
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                launch_target: detect_launch_target(
                    &process
                        .cmd()
                        .iter()
                        .map(|value| value.to_string_lossy().into_owned())
                        .collect::<Vec<_>>(),
                ),
                root_application,
                upload_bps: process_upload_bps,
                download_bps: process_download_bps,
                upload_total: counters.upload_total,
                download_total: counters.download_total,
                cpu_percent: process.cpu_usage(),
                memory_bytes: process.memory(),
                connections,
                risk_score,
                risk_level,
                is_agent,
                is_proxy,
                is_running: true,
                started_at: process.start_time(),
                ended_at: None,
                last_activity_at: now,
                active_connection_count,
                total_connection_count: active_connection_count,
                connection_history: observed_connection_details,
                is_network_blocked: false,
            });
        }

        let running_ids: HashSet<String> = processes
            .iter()
            .map(|process| process.process_instance_id.clone())
            .collect();
        for mut process in processes.drain(..) {
            let previous = self.process_history.remove(&process.process_instance_id);
            let previous_connections = previous
                .as_ref()
                .map(|item| item.connection_history.clone())
                .unwrap_or_default();
            process.connection_history =
                merge_connection_history(previous_connections, process.connection_history, now);
            process.active_connection_count = process
                .connection_history
                .iter()
                .filter(|connection| connection.is_alive)
                .count();
            process.total_connection_count = process.connection_history.len();
            if process.active_connection_count == 0
                && process.upload_bps == 0.0
                && process.download_bps == 0.0
            {
                process.last_activity_at = previous
                    .as_ref()
                    .map(|item| item.last_activity_at)
                    .unwrap_or(process.started_at);
            }
            if let Some(previous) = previous {
                process.upload_total = process.upload_total.max(previous.upload_total);
                process.download_total = process.download_total.max(previous.download_total);
            }
            self.process_history
                .insert(process.process_instance_id.clone(), process);
        }

        for (instance_id, process) in self.process_history.iter_mut() {
            if !running_ids.contains(instance_id) && process.is_running {
                process.is_running = false;
                process.ended_at = Some(now);
                process.upload_bps = 0.0;
                process.download_bps = 0.0;
                process.cpu_percent = 0.0;
                process.connection_history = merge_connection_history(
                    std::mem::take(&mut process.connection_history),
                    Vec::new(),
                    now,
                );
                process.active_connection_count = 0;
                process.total_connection_count = process.connection_history.len();
                process.connections.clear();
            }
        }
        prune_process_history(&mut self.process_history);
        let history = &self.process_history;
        self.root_application_cache
            .retain(|instance_id, _| history.contains_key(instance_id));
        processes = self.process_history.values().cloned().collect();

        for (instance_id, process, projected_mb, upload_delta, target) in pending_events {
            self.maybe_add_event(
                now,
                &instance_id,
                &process,
                projected_mb,
                upload_delta,
                target.as_deref(),
            );
        }

        self.previous = next_previous;
        self.last_sample = Some(sample_now);
        self.session_upload_bytes = self.session_upload_bytes.saturating_add(delta_upload_total);
        processes.sort_by(|a, b| {
            b.is_running
                .cmp(&a.is_running)
                .then_with(|| b.last_activity_at.cmp(&a.last_activity_at))
                .then_with(|| b.upload_bps.total_cmp(&a.upload_bps))
                .then_with(|| b.risk_score.cmp(&a.risk_score))
        });

        if self.timeline.len() == 60 {
            self.timeline.pop_front();
        }
        self.timeline.push_back(TimelinePoint {
            timestamp: now,
            label: Local::now().format("%H:%M:%S").to_string(),
            upload_bps,
            download_bps,
        });

        let snapshot = MonitorSnapshot {
            monitoring: self.monitoring,
            platform: std::env::consts::OS.to_string(),
            hostname: hostname(),
            collected_at: now,
            upload_bps,
            download_bps,
            total_upload_bytes: self.session_upload_bytes,
            observed_processes: processes
                .iter()
                .filter(|process| process.is_running)
                .count(),
            active_connections: processes
                .iter()
                .map(|process| process.active_connection_count)
                .sum(),
            processes,
            timeline: self.timeline.iter().cloned().collect(),
            events: self.events.iter().cloned().collect(),
            settings: self.settings.clone(),
            coverage: collectors::coverage(),
        };
        self.last_snapshot = Some(snapshot.clone());
        snapshot
    }

    pub fn process_detail(
        &mut self,
        pid: u32,
        process_instance_id: &str,
    ) -> Result<ProcessDetail, String> {
        let system_pid = Pid::from_u32(pid);
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[system_pid]),
            true,
            ProcessRefreshKind::everything(),
        );
        let process = match self.system.process(system_pid) {
            Some(process) => process,
            None => return self.historical_process_detail(process_instance_id),
        };
        let current_instance_id = format!("{}-{}", pid, process.start_time());
        if current_instance_id != process_instance_id {
            return self.historical_process_detail(process_instance_id);
        }

        let raw_command_line: Vec<String> = process
            .cmd()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        let command_line = redact_command_line(&raw_command_line);
        let cwd = process.cwd();
        let current_working_directory = cwd
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        let launch_target = detect_launch_target(&raw_command_line);
        let parent_pid = process.parent().map(|parent| parent.as_u32());
        let name = process.name().to_string_lossy().into_owned();
        let executable = process
            .exe()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        let started_at = process.start_time();

        let mut ancestry = Vec::new();
        let mut current = Some(system_pid);
        for _ in 0..16 {
            let Some(ancestor_pid) = current else { break };
            let Some(ancestor) = self.system.process(ancestor_pid) else {
                break;
            };
            let ancestor_command: Vec<String> = ancestor
                .cmd()
                .iter()
                .map(|value| value.to_string_lossy().into_owned())
                .collect();
            ancestry.push(ProcessAncestor {
                pid: ancestor_pid.as_u32(),
                name: ancestor.name().to_string_lossy().into_owned(),
                executable: ancestor
                    .exe()
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                command_line: redact_command_line(&ancestor_command),
            });
            current = ancestor.parent();
        }
        ancestry.reverse();

        let platform = collectors::inspect_process(pid, &raw_command_line, cwd);
        let active_upload_bps = self
            .last_snapshot
            .as_ref()
            .and_then(|snapshot| {
                snapshot
                    .processes
                    .iter()
                    .find(|item| item.process_instance_id == process_instance_id)
            })
            .map(|item| item.upload_bps)
            .unwrap_or(0.0);
        let (upload_assessment, evidence_confidence) = if active_upload_bps > 0.0 {
            (
                "当前正在发送网络字节，但采集器没有拿到应用层明文或文件读取到 socket 发送的因果证据；下方文件仅代表进程访问证据。".to_string(),
                "无法确认".to_string(),
            )
        } else if !platform.open_files.is_empty() {
            (
                format!("当前采样点没有上传流量，但发现 {} 个有意义的文件访问证据；不能断定这些文件已被发送。", platform.open_files.len()),
                "无法确认".to_string(),
            )
        } else {
            (
                "当前采样点没有上传流量，也没有发现有意义的文件访问证据。".to_string(),
                "无法确认".to_string(),
            )
        };

        let mut notes = platform.notes;
        if command_line != raw_command_line {
            notes.push(
                "命令行中的令牌、密码、Cookie、Authorization 等敏感凭据已自动遮蔽。".to_string(),
            );
        }

        let connections = self
            .process_history
            .get(process_instance_id)
            .map(|process| process.connection_history.clone())
            .unwrap_or(platform.connections);

        Ok(ProcessDetail {
            process_instance_id: current_instance_id,
            pid,
            parent_pid,
            name,
            executable,
            command_line: command_line.clone(),
            current_working_directory,
            launch_target,
            arguments: command_line.into_iter().skip(1).collect(),
            started_at,
            ancestry,
            connections,
            open_files: platform.open_files,
            tls_inspection: platform.tls_inspection,
            upload_assessment,
            evidence_confidence,
            notes,
        })
    }

    fn historical_process_detail(
        &self,
        process_instance_id: &str,
    ) -> Result<ProcessDetail, String> {
        let process = self
            .process_history
            .get(process_instance_id)
            .ok_or_else(|| "该历史进程已不在保留窗口内".to_string())?;
        Ok(ProcessDetail {
            process_instance_id: process.process_instance_id.clone(),
            pid: process.pid,
            parent_pid: process.parent_pid,
            name: process.name.clone(),
            executable: process.executable.clone(),
            command_line: process.command_line.clone(),
            current_working_directory: process.current_working_directory.clone(),
            launch_target: process.launch_target.clone(),
            arguments: process.command_line.iter().skip(1).cloned().collect(),
            started_at: process.started_at,
            ancestry: Vec::new(),
            connections: process.connection_history.clone(),
            open_files: Vec::new(),
            tls_inspection: TlsInspection {
                state: "历史进程未保留 TLS 详情".to_string(),
                method: "退出前快照".to_string(),
                note: "进程已退出，无法从当前句柄或环境重新获取 TLS 会话状态。".to_string(),
                ..TlsInspection::default()
            },
            upload_assessment: "进程已经结束；以下内容来自退出前保留的最后观测快照。".to_string(),
            evidence_confidence: "历史记录".to_string(),
            notes: vec![
                "进程退出后无法再次读取文件句柄与父进程链，连接生命周期与基础进程元数据已保留。"
                    .to_string(),
            ],
        })
    }

    fn maybe_add_event(
        &mut self,
        now: u64,
        instance_id: &str,
        process: &str,
        projected_mb: f64,
        upload_delta: u64,
        target: Option<&str>,
    ) {
        let last = self.alert_cooldown.get(instance_id).copied().unwrap_or(0);
        if now.saturating_sub(last) < 120 {
            return;
        }
        self.alert_cooldown.insert(instance_id.to_string(), now);
        if self.events.len() == 100 {
            self.events.pop_back();
        }
        let target_text = target
            .map(|value| format!(" · {value}"))
            .unwrap_or_default();
        self.events.push_front(RiskEvent {
            id: format!("{instance_id}-{now}"),
            timestamp: now,
            level: RiskLevel::High,
            process: process.to_string(),
            title: "上传速率超过阈值".to_string(),
            detail: format!("过去 1 分钟预计上传 {projected_mb:.1} MB{target_text}"),
            upload_bytes: upload_delta,
            acknowledged: false,
        });
    }
}

const MAX_HISTORY_PROCESSES: usize = 500;
// A bounded history keeps IPC payloads and merge/sort work predictable while retaining
// several minutes of normal connection churn for each process.
const MAX_PROCESS_CONNECTIONS: usize = 120;
const PLATFORM_SAMPLE_INTERVAL_MS: u64 = 1_200;
const TRANSIENT_CONNECTION_SECONDS: u64 = 2;

fn connection_matches(left: &NetworkConnectionDetail, right: &NetworkConnectionDetail) -> bool {
    left.protocol == right.protocol
        && left.local_endpoint == right.local_endpoint
        && left.remote_endpoint == right.remote_endpoint
}

fn merge_connection_history(
    mut history: Vec<NetworkConnectionDetail>,
    observed: Vec<NetworkConnectionDetail>,
    now: u64,
) -> Vec<NetworkConnectionDetail> {
    let mut matched = HashSet::new();
    for current in observed {
        if let Some((index, existing)) = history
            .iter_mut()
            .enumerate()
            .find(|(_, existing)| existing.is_alive && connection_matches(existing, &current))
        {
            existing.state = current.state;
            existing.last_seen_at = now;
            existing.closed_at = None;
            existing.is_alive = true;
            matched.insert(index);
        } else {
            let mut connection = current;
            connection.first_seen_at = now;
            connection.last_seen_at = now;
            connection.closed_at = None;
            connection.is_alive = true;
            connection.is_transient = false;
            history.push(connection);
            matched.insert(history.len() - 1);
        }
    }

    for (index, connection) in history.iter_mut().enumerate() {
        if connection.is_alive && !matched.contains(&index) {
            connection.is_alive = false;
            connection.state = "CLOSED".to_string();
            connection.closed_at = Some(now);
            connection.last_seen_at = now;
            connection.is_transient =
                now.saturating_sub(connection.first_seen_at) <= TRANSIENT_CONNECTION_SECONDS;
        }
    }
    history.sort_by(|left, right| {
        right
            .is_alive
            .cmp(&left.is_alive)
            .then_with(|| right.last_seen_at.cmp(&left.last_seen_at))
    });
    history.truncate(MAX_PROCESS_CONNECTIONS);
    history
}

fn prune_process_history(history: &mut HashMap<String, ProcessFlow>) {
    let mut historical: Vec<(String, u64)> = history
        .iter()
        .filter(|(_, process)| !process.is_running)
        .map(|(id, process)| (id.clone(), process.last_activity_at))
        .collect();
    if historical.len() <= MAX_HISTORY_PROCESSES {
        return;
    }
    historical.sort_by(|left, right| right.1.cmp(&left.1));
    for (id, _) in historical.into_iter().skip(MAX_HISTORY_PROCESSES) {
        history.remove(&id);
    }
}

fn resolve_root_application(system: &System, start_pid: Pid, fallback: &str) -> String {
    let mut current = Some(start_pid);
    let mut preferred_agent = None;
    let mut app_bundle_name = None;
    for _ in 0..12 {
        let Some(pid) = current else { break };
        let Some(process) = system.process(pid) else {
            break;
        };
        let name = process.name().to_string_lossy().into_owned();
        let lower = name.to_lowercase();
        if is_agent_name(&lower) {
            preferred_agent = Some(name.clone());
        }
        if let Some(path) = process.exe() {
            for component in path.components() {
                let value = component.as_os_str().to_string_lossy();
                if let Some(bundle) = value.strip_suffix(".app") {
                    app_bundle_name = Some(bundle.to_string());
                    break;
                }
            }
        }
        current = process.parent();
    }
    preferred_agent
        .or(app_bundle_name)
        .unwrap_or_else(|| fallback.to_string())
}

fn is_agent_name(name: &str) -> bool {
    [
        "codex",
        "claude",
        "cursor",
        "windsurf",
        "grok",
        "harness",
        "qoder",
        "zcode",
        "zed",
        "copilot",
        "aider",
        "gemini",
        "continue",
        "antigravity",
    ]
    .iter()
    .any(|keyword| name.contains(keyword))
}

fn is_proxy_name(name: &str) -> bool {
    [
        "v2ray",
        "xray",
        "clash",
        "surge",
        "wireguard",
        "openvpn",
        "tailscale",
        "zerotier",
        "sing-box",
        "singbox",
        "shadowsocks",
    ]
    .iter()
    .any(|keyword| name.contains(keyword))
}

fn detect_launch_target(command_line: &[String]) -> Option<String> {
    let script_extensions = [
        ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".sh", ".rb", ".pl",
    ];
    let mut index = 1;
    while index < command_line.len() {
        let argument = &command_line[index];
        if argument == "-m" && index + 1 < command_line.len() {
            return Some(format!("Python 模块：{}", command_line[index + 1]));
        }
        if argument == "-c" {
            return Some("命令行内联代码（-c）".to_string());
        }
        let lower = argument.to_lowercase();
        if script_extensions
            .iter()
            .any(|extension| lower.ends_with(extension))
        {
            return Some(argument.clone());
        }
        index += 1;
    }
    None
}

fn redact_command_line(command_line: &[String]) -> Vec<String> {
    let mut redact_next = false;
    command_line
        .iter()
        .map(|argument| {
            if redact_next {
                redact_next = false;
                return "<已遮蔽>".to_string();
            }
            let lower = argument.to_lowercase();
            let sensitive = [
                "token",
                "password",
                "passwd",
                "secret",
                "api-key",
                "api_key",
                "apikey",
                "authorization",
                "cookie",
                "credential",
            ];
            if let Some((key, _)) = argument.split_once('=') {
                if sensitive
                    .iter()
                    .any(|word| key.to_lowercase().contains(word))
                {
                    return format!("{key}=<已遮蔽>");
                }
            }
            if argument.starts_with('-') && sensitive.iter().any(|word| lower.contains(word)) {
                redact_next = true;
                return argument.clone();
            }
            if lower.contains("authorization:") || lower.starts_with("bearer ") {
                return "<Authorization 已遮蔽>".to_string();
            }
            if (lower.starts_with("http://") || lower.starts_with("https://"))
                && argument.contains('?')
            {
                return format!(
                    "{}?<查询参数已遮蔽>",
                    argument.split('?').next().unwrap_or(argument)
                );
            }
            argument.clone()
        })
        .collect()
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "本机".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_python_script_and_module_targets() {
        assert_eq!(
            detect_launch_target(&["python3".into(), "-u".into(), "/project/upload.py".into()]),
            Some("/project/upload.py".into())
        );
        assert_eq!(
            detect_launch_target(&["python3".into(), "-m".into(), "uploader.worker".into()]),
            Some("Python 模块：uploader.worker".into())
        );
    }

    #[test]
    fn redacts_credentials_but_keeps_useful_arguments() {
        let command = vec![
            "python3".into(),
            "upload.py".into(),
            "--file".into(),
            "/tmp/video.mp4".into(),
            "--api-key=abc".into(),
            "--token".into(),
            "secret-value".into(),
        ];
        let redacted = redact_command_line(&command);
        assert_eq!(redacted[3], "/tmp/video.mp4");
        assert_eq!(redacted[4], "--api-key=<已遮蔽>");
        assert_eq!(redacted[6], "<已遮蔽>");
    }

    #[test]
    fn retains_closed_and_reopened_connections_as_separate_history() {
        let observed = NetworkConnectionDetail {
            protocol: "TCP".into(),
            local_endpoint: "127.0.0.1:50000".into(),
            remote_endpoint: "203.0.113.8:443".into(),
            state: "ESTABLISHED".into(),
            is_alive: true,
            ..NetworkConnectionDetail::default()
        };
        let active = merge_connection_history(Vec::new(), vec![observed.clone()], 100);
        assert_eq!(active.len(), 1);
        assert!(active[0].is_alive);

        let closed = merge_connection_history(active, Vec::new(), 101);
        assert!(!closed[0].is_alive);
        assert!(closed[0].is_transient);
        assert_eq!(closed[0].closed_at, Some(101));

        let reopened = merge_connection_history(closed, vec![observed], 105);
        assert_eq!(reopened.len(), 2);
        assert!(reopened[0].is_alive);
        assert!(!reopened[1].is_alive);
    }

    #[test]
    fn inspects_a_live_process_instance() {
        let mut monitor = MonitorState::default();
        let pid = std::process::id();
        let system_pid = Pid::from_u32(pid);
        monitor.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[system_pid]),
            true,
            ProcessRefreshKind::everything(),
        );
        let process = monitor.system.process(system_pid).expect("test process");
        let instance_id = format!("{}-{}", pid, process.start_time());
        let detail = monitor
            .process_detail(pid, &instance_id)
            .expect("live process detail");

        assert_eq!(detail.pid, pid);
        assert!(!detail.name.is_empty());
        assert!(!detail.command_line.is_empty());
        assert!(!detail.ancestry.is_empty());
    }
}
