use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelinePoint {
    pub timestamp: u64,
    pub label: String,
    pub upload_bps: f64,
    pub download_bps: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessFlow {
    pub process_instance_id: String,
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub executable: String,
    pub command_line: Vec<String>,
    pub current_working_directory: String,
    pub launch_target: Option<String>,
    pub root_application: String,
    pub upload_bps: f64,
    pub download_bps: f64,
    pub upload_total: u64,
    pub download_total: u64,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub connections: Vec<String>,
    pub risk_score: u8,
    pub risk_level: RiskLevel,
    pub is_agent: bool,
    pub is_proxy: bool,
    pub is_running: bool,
    pub started_at: u64,
    pub ended_at: Option<u64>,
    pub last_activity_at: u64,
    pub active_connection_count: usize,
    pub total_connection_count: usize,
    pub connection_history: Vec<NetworkConnectionDetail>,
    pub is_network_blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedNetworkRule {
    pub id: String,
    pub executable: String,
    pub process_name: String,
    pub platform: String,
    pub rule_identifier: String,
    pub created_at: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAncestor {
    pub pid: u32,
    pub name: String,
    pub executable: String,
    pub command_line: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkConnectionDetail {
    pub protocol: String,
    pub local_endpoint: String,
    pub remote_endpoint: String,
    pub state: String,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
    pub closed_at: Option<u64>,
    pub is_alive: bool,
    pub is_transient: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenFileEvidence {
    pub path: String,
    pub descriptor: String,
    pub access_mode: String,
    pub file_type: String,
    pub size_bytes: Option<u64>,
    pub offset_bytes: Option<u64>,
    pub category: String,
    pub evidence: String,
    pub likely_upload_source: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsInspection {
    pub detected: bool,
    pub state: String,
    pub method: String,
    pub keylog_path: Option<String>,
    pub plaintext_available: bool,
    pub note: String,
}

#[derive(Debug, Clone, Default)]
pub struct PlatformProcessDetail {
    pub connections: Vec<NetworkConnectionDetail>,
    pub open_files: Vec<OpenFileEvidence>,
    pub tls_inspection: TlsInspection,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDetail {
    pub process_instance_id: String,
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub executable: String,
    pub command_line: Vec<String>,
    pub current_working_directory: String,
    pub launch_target: Option<String>,
    pub arguments: Vec<String>,
    pub started_at: u64,
    pub ancestry: Vec<ProcessAncestor>,
    pub connections: Vec<NetworkConnectionDetail>,
    pub open_files: Vec<OpenFileEvidence>,
    pub tls_inspection: TlsInspection,
    pub upload_assessment: String,
    pub evidence_confidence: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEvent {
    pub id: String,
    pub timestamp: u64,
    pub level: RiskLevel,
    pub process: String,
    pub title: String,
    pub detail: String,
    pub upload_bytes: u64,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitorSettings {
    pub threshold_mb_per_minute: u32,
    pub alert_level: String,
    pub monitor_agents: bool,
    pub monitor_all_apps: bool,
    pub sensitive_file_correlation: bool,
    pub desktop_notifications: bool,
    pub tls_mode: String,
    pub tls_proxy_port: u16,
    pub tls_engine_path: String,
    pub tls_capture_body_preview: bool,
    pub tls_capture_headers: bool,
    pub tls_body_preview_bytes: u32,
    pub tls_recent_flow_limit: u16,
    pub tls_redact_query_strings: bool,
    pub tls_excluded_processes: Vec<String>,
}

impl Default for MonitorSettings {
    fn default() -> Self {
        Self {
            threshold_mb_per_minute: 50,
            alert_level: "notify".to_string(),
            monitor_agents: true,
            monitor_all_apps: true,
            sensitive_file_correlation: false,
            desktop_notifications: true,
            tls_mode: "metadata".to_string(),
            tls_proxy_port: 8899,
            tls_engine_path: String::new(),
            tls_capture_body_preview: true,
            tls_capture_headers: true,
            tls_body_preview_bytes: 4096,
            tls_recent_flow_limit: 20,
            tls_redact_query_strings: false,
            tls_excluded_processes: vec![
                "virtualbox".to_string(),
                "vboxsvc".to_string(),
                "vboxheadless".to_string(),
                "vmware".to_string(),
                "wireguard".to_string(),
                "openvpn".to_string(),
                "tailscale".to_string(),
                "clash".to_string(),
                "sing-box".to_string(),
                "surge".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsFlowEvent {
    pub timestamp: u64,
    pub direction: String,
    pub target_pid: Option<u32>,
    pub protocol: String,
    pub host: String,
    pub url: String,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub headers: Option<std::collections::BTreeMap<String, String>>,
    pub body_bytes: u64,
    pub body_sha256: Option<String>,
    pub body_preview: Option<String>,
    pub body_preview_encoding: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsMonitorStatus {
    pub running: bool,
    pub running_count: usize,
    pub mode: String,
    pub target_pid: Option<u32>,
    pub listener: String,
    pub engine: Option<String>,
    pub ca_path: Option<String>,
    pub ca_ready: bool,
    pub flow_log_path: Option<String>,
    pub recent_flows: Vec<TlsFlowEvent>,
    pub recent_flow_limit: usize,
    pub engine_log_path: Option<String>,
    pub last_error: Option<String>,
    pub note: String,
    pub sessions: Vec<TlsMonitorSessionStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsMonitorSessionStatus {
    pub running: bool,
    pub target_pid: u32,
    pub process_name: String,
    pub listener: String,
    pub engine: Option<String>,
    pub ca_path: Option<String>,
    pub ca_ready: bool,
    pub flow_log_path: Option<String>,
    pub recent_flows: Vec<TlsFlowEvent>,
    pub engine_log_path: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInstallationInfo {
    pub platform: String,
    pub installed: bool,
    pub engine_path: Option<String>,
    pub version: Option<String>,
    pub package_manager: Option<String>,
    pub install_command: String,
    pub uninstall_command: Option<String>,
    pub official_url: String,
    pub manual_note: String,
    pub last_output: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorCoverage {
    pub network: String,
    pub process: String,
    pub file: String,
    pub collector: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSnapshot {
    pub monitoring: bool,
    pub platform: String,
    pub hostname: String,
    pub collected_at: u64,
    pub upload_bps: f64,
    pub download_bps: f64,
    pub total_upload_bytes: u64,
    pub observed_processes: usize,
    pub active_connections: usize,
    pub processes: Vec<ProcessFlow>,
    pub timeline: Vec<TimelinePoint>,
    pub events: Vec<RiskEvent>,
    pub settings: MonitorSettings,
    pub coverage: MonitorCoverage,
}

#[derive(Debug, Clone, Default)]
pub struct NetworkCounters {
    pub upload_total: u64,
    pub download_total: u64,
}

#[derive(Debug, Clone, Default)]
pub struct PlatformSample {
    pub counters: std::collections::HashMap<u32, NetworkCounters>,
    pub connections: std::collections::HashMap<u32, Vec<String>>,
    pub connection_details: std::collections::HashMap<u32, Vec<NetworkConnectionDetail>>,
}
