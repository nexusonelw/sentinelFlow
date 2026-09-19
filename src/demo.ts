import type { MonitorSnapshot } from "./types";

const names = ["Codex", "Claude Code", "Safari", "Dropbox", "v2ray", "Terminal"];
const remotes = ["api.openai.com:443", "api.anthropic.com:443", "gateway.icloud.com:443", "127.0.0.1:10808", "149.154.167.51:443"];

export function createDemoSnapshot(seed = Date.now()): MonitorSnapshot {
  const now = Math.floor(seed / 1000);
  const processes = names.map((name, index) => {
    const pulse = (Math.sin(seed / 4800 + index * 1.37) + 1.25) / 2.25;
    const agent = index < 2;
    const proxy = name === "v2ray";
    const upload = Math.round((agent ? 920_000 : 210_000) * pulse * (index === 0 ? 1.8 : 1));
    return {
      process_instance_id: `${1000 + index}-${now - index * 420}`,
      pid: 1000 + index,
      parent_pid: index < 2 ? 921 : 1,
      name,
      executable: `/Applications/${name}.app`,
      command_line: index === 0
        ? ["/usr/bin/python3", "/Users/demo/project/uploader.py", "--file", "/Users/demo/Videos/final-cut.mp4", "--target", "https://upload.example.com"]
        : [`/Applications/${name}.app/Contents/MacOS/${name}`],
      current_working_directory: index === 0 ? "/Users/demo/project" : "/Users/demo",
      launch_target: index === 0 ? "/Users/demo/project/uploader.py" : undefined,
      root_application: name,
      upload_bps: upload,
      download_bps: Math.round(upload * (index === 3 ? 4.2 : 1.6)),
      upload_total: upload * (50 + index * 20),
      download_total: upload * (90 + index * 30),
      cpu_percent: Number((pulse * 8 + index * 0.7).toFixed(1)),
      memory_bytes: (140 + index * 80) * 1024 * 1024,
      connections: [remotes[index % remotes.length]],
      risk_score: agent ? Math.round(48 + pulse * 42) : Math.round(8 + pulse * 28),
      risk_level: agent && pulse > 0.72 ? "high" as const : agent ? "medium" as const : "low" as const,
      is_agent: agent,
      is_proxy: proxy,
      is_running: index < 5,
      started_at: now - (index + 1) * 420,
      ended_at: index === 5 ? now - 48 : undefined,
      last_activity_at: now - index * 11,
      active_connection_count: index < 5 ? 1 : 0,
      total_connection_count: index === 5 ? 3 : 1,
      is_network_blocked: false,
      connection_history: [
        {
          protocol: "TCP",
          local_endpoint: `127.0.0.1:${51842 + index}`,
          remote_endpoint: remotes[index % remotes.length],
          state: index < 5 ? "ESTABLISHED" : "CLOSED",
          first_seen_at: now - 90 - index * 15,
          last_seen_at: index < 5 ? now : now - 48,
          closed_at: index === 5 ? now - 48 : undefined,
          is_alive: index < 5,
          is_transient: index === 5
        }
      ]
    };
  });

  const timeline = Array.from({ length: 32 }, (_, i) => {
    const t = now - (31 - i) * 6;
    const wave = 1.1 + Math.sin(i / 3.4) * 0.34 + Math.sin(i / 1.71) * 0.17;
    const spike = i === 24 || i === 25 ? 2.1 : 1;
    return {
      timestamp: t,
      label: new Date(t * 1000).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      upload_bps: Math.round(1_180_000 * wave * spike),
      download_bps: Math.round(2_040_000 * (1.16 + Math.cos(i / 4.1) * 0.24))
    };
  });

  const upload = processes.reduce((sum, process) => sum + process.upload_bps, 0);
  const download = processes.reduce((sum, process) => sum + process.download_bps, 0);
  return {
    monitoring: true,
    platform: "preview",
    hostname: "本机预览",
    collected_at: now,
    upload_bps: upload,
    download_bps: download,
    total_upload_bytes: 1_283_620_864,
    observed_processes: processes.length,
    active_connections: 18,
    processes,
    timeline,
    events: [
      { id: "demo-1", timestamp: now - 34, level: "high", process: "Codex", title: "上传速率超过阈值", detail: "过去 1 分钟预计上传 82.4 MB · api.openai.com:443", upload_bytes: 82_400_000, acknowledged: false },
      { id: "demo-2", timestamp: now - 246, level: "medium", process: "Claude Code", title: "首次连接后出现持续上传", detail: "该进程首次连接 api.anthropic.com:443", upload_bytes: 21_700_000, acknowledged: false },
      { id: "demo-3", timestamp: now - 813, level: "low", process: "v2ray", title: "已识别本地代理链路", detail: "流量将保留原始进程归属，避免重复计算", upload_bytes: 0, acknowledged: true }
    ],
    settings: {
      threshold_mb_per_minute: 50,
      alert_level: "notify",
      monitor_agents: true,
      monitor_all_apps: true,
      sensitive_file_correlation: false,
      desktop_notifications: true,
      tls_mode: "metadata",
      tls_proxy_port: 8899,
      tls_engine_path: "",
      tls_capture_body_preview: true,
      tls_capture_headers: true,
      tls_body_preview_bytes: 4096,
      tls_recent_flow_limit: 20,
      tls_redact_query_strings: false,
      tls_excluded_processes: ["virtualbox", "vboxsvc", "wireguard", "openvpn", "tailscale", "clash", "sing-box", "surge"]
    },
    coverage: {
      network: "active",
      process: "active",
      file: "permission_required",
      collector: "界面预览数据",
      note: "在 Tauri 桌面应用中启动后将自动切换为本机真实数据。"
    }
  };
}
