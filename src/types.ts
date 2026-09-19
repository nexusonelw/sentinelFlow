export type RiskLevel = "low" | "medium" | "high";

export interface TimelinePoint {
  timestamp: number;
  label: string;
  upload_bps: number;
  download_bps: number;
}

export interface ProcessFlow {
  process_instance_id: string;
  pid: number;
  parent_pid?: number;
  name: string;
  executable: string;
  command_line: string[];
  current_working_directory: string;
  launch_target?: string;
  root_application: string;
  upload_bps: number;
  download_bps: number;
  upload_total: number;
  download_total: number;
  cpu_percent: number;
  memory_bytes: number;
  connections: string[];
  risk_score: number;
  risk_level: RiskLevel;
  is_agent: boolean;
  is_proxy: boolean;
  is_running: boolean;
  started_at: number;
  ended_at?: number;
  last_activity_at: number;
  active_connection_count: number;
  total_connection_count: number;
  connection_history: NetworkConnectionDetail[];
  is_network_blocked: boolean;
}

export interface ProcessAncestor {
  pid: number;
  name: string;
  executable: string;
  command_line: string[];
}

export interface NetworkConnectionDetail {
  protocol: string;
  local_endpoint: string;
  remote_endpoint: string;
  state: string;
  first_seen_at: number;
  last_seen_at: number;
  closed_at?: number;
  is_alive: boolean;
  is_transient: boolean;
}

export interface OpenFileEvidence {
  path: string;
  descriptor: string;
  access_mode: string;
  file_type: string;
  size_bytes?: number;
  offset_bytes?: number;
  category: string;
  evidence: string;
  likely_upload_source: boolean;
}

export interface TlsInspection {
  detected: boolean;
  state: string;
  method: string;
  keylog_path?: string;
  plaintext_available: boolean;
  note: string;
}

export interface ProcessDetail {
  process_instance_id: string;
  pid: number;
  parent_pid?: number;
  name: string;
  executable: string;
  command_line: string[];
  current_working_directory: string;
  launch_target?: string;
  arguments: string[];
  started_at: number;
  ancestry: ProcessAncestor[];
  connections: NetworkConnectionDetail[];
  open_files: OpenFileEvidence[];
  tls_inspection: TlsInspection;
  upload_assessment: string;
  evidence_confidence: string;
  notes: string[];
}

export interface RiskEvent {
  id: string;
  timestamp: number;
  level: RiskLevel;
  process: string;
  title: string;
  detail: string;
  upload_bytes: number;
  acknowledged: boolean;
}

export interface MonitorSettings {
  threshold_mb_per_minute: number;
  alert_level: "notify" | "high_risk";
  monitor_agents: boolean;
  monitor_all_apps: boolean;
  sensitive_file_correlation: boolean;
  desktop_notifications: boolean;
  tls_mode: "metadata" | "keylog" | "local_proxy";
  tls_proxy_port: number;
  tls_engine_path: string;
  tls_capture_body_preview: boolean;
  tls_capture_headers: boolean;
  tls_body_preview_bytes: number;
  tls_recent_flow_limit: number;
  tls_redact_query_strings: boolean;
  tls_excluded_processes: string[];
}

export interface TlsFlowEvent {
  timestamp: number;
  direction: string;
  target_pid?: number;
  protocol: string;
  host: string;
  url: string;
  method?: string;
  status?: number;
  content_type?: string;
  headers?: Record<string, string>;
  body_bytes: number;
  body_sha256?: string;
  body_preview?: string;
  body_preview_encoding?: string;
}

export interface TlsMonitorStatus {
  running: boolean;
  running_count: number;
  mode: string;
  target_pid?: number;
  listener: string;
  engine?: string;
  ca_path?: string;
  ca_ready: boolean;
  flow_log_path?: string;
  recent_flows: TlsFlowEvent[];
  recent_flow_limit: number;
  engine_log_path?: string;
  last_error?: string;
  note: string;
  sessions: TlsMonitorSessionStatus[];
}

export interface TlsMonitorSessionStatus {
  running: boolean;
  target_pid: number;
  process_name: string;
  listener: string;
  engine?: string;
  ca_path?: string;
  ca_ready: boolean;
  flow_log_path?: string;
  recent_flows: TlsFlowEvent[];
  engine_log_path?: string;
  last_error?: string;
}

export interface TlsInstallationInfo {
  platform: string;
  installed: boolean;
  engine_path?: string;
  version?: string;
  package_manager?: string;
  install_command: string;
  uninstall_command?: string;
  official_url: string;
  manual_note: string;
  last_output?: string;
}

export interface MonitorCoverage {
  network: "active" | "limited" | "permission_required";
  process: "active" | "limited" | "permission_required";
  file: "active" | "limited" | "permission_required";
  collector: string;
  note: string;
}

export interface MonitorSnapshot {
  monitoring: boolean;
  platform: string;
  hostname: string;
  collected_at: number;
  upload_bps: number;
  download_bps: number;
  total_upload_bytes: number;
  observed_processes: number;
  active_connections: number;
  processes: ProcessFlow[];
  timeline: TimelinePoint[];
  events: RiskEvent[];
  settings: MonitorSettings;
  coverage: MonitorCoverage;
}
