import { lazy, Suspense, useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { writeText as writeNativeClipboardText } from "@tauri-apps/plugin-clipboard-manager";
import { isPermissionGranted, requestPermission, sendNotification } from "@tauri-apps/plugin-notification";
import {
  Activity,
  Bell,
  BellRing,
  Blocks,
  Bot,
  Check,
  ChevronRight,
  CircleGauge,
  Copy,
  Cpu,
  Database,
  Download,
  FileCode2,
  FileText,
  FileLock2,
  FolderOpen,
  GitBranch,
  Globe2,
  HardDrive,
  Info,
  Laptop,
  LayoutDashboard,
  LoaderCircle,
  Menu,
  Network,
  Pause,
  Play,
  Radio,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Terminal,
  Upload,
  Waypoints,
  Wifi,
  WifiOff
} from "lucide-react";
import { createDemoSnapshot } from "./demo";
import { buildProcessAiReport } from "./processAiReport";
import UploadStatsTab from "./UploadStatsTab";
import {
  PROCESS_ROW_HEIGHT,
  PROCESS_VIRTUALIZATION_THRESHOLD,
  applyProcessOrder,
  buildProcessSearchIndex,
  filterProcesses,
  getLatestConnection,
  getMaxRunningUpload,
  getVirtualRange,
  sortProcessIds
} from "./processList";
import type { ConnectionScope, ProcessScope, ProcessSortKey, ProcessSortState, SortDirection } from "./processList";
import type { MonitorSettings, MonitorSnapshot, ProcessDetail, ProcessFlow, RiskEvent, RiskLevel, TlsInstallationInfo, TlsMonitorStatus } from "./types";

const DashboardCharts = lazy(() => import("./DashboardCharts"));

const riskText: Record<RiskLevel, string> = { low: "正常", medium: "关注", high: "高风险" };

function isTauri() {
  return "__TAURI_INTERNALS__" in window;
}

function formatRate(value: number) {
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(1)} MB/s`;
  if (value >= 1024) return `${(value / 1024).toFixed(0)} KB/s`;
  return `${value.toFixed(0)} B/s`;
}

function formatBytes(value: number) {
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(1)} GB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(1)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(0)} KB`;
  return `${value.toFixed(0)} B`;
}

function formatCommand(command: string[]) {
  return command.map((part) => /\s/.test(part) ? JSON.stringify(part) : part).join(" ");
}

function timeAgo(timestamp: number) {
  const seconds = Math.max(0, Math.floor(Date.now() / 1000 - timestamp));
  if (seconds < 60) return `${seconds} 秒前`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  return `${Math.floor(seconds / 3600)} 小时前`;
}

function formatTimestamp(timestamp?: number) {
  if (!timestamp) return "—";
  return new Date(timestamp * 1000).toLocaleString("zh-CN", {
    month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit"
  });
}

function formatDuration(startedAt: number, endedAt?: number) {
  const seconds = Math.max(0, (endedAt || Math.floor(Date.now() / 1000)) - startedAt);
  if (seconds < 60) return `${seconds} 秒`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分 ${seconds % 60} 秒`;
  return `${Math.floor(seconds / 3600)} 小时 ${Math.floor(seconds % 3600 / 60)} 分`;
}

async function writeClipboardText(text: string) {
  if (isTauri()) {
    await writeNativeClipboardText(text);
    return;
  }

  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // Some WebViews expose the API but reject it without an explicit permission.
    }
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("系统剪贴板拒绝了复制操作");
}

function AppMark({ compact = false }: { compact?: boolean }) {
  return (
    <div className={`app-mark ${compact ? "compact" : ""}`}>
      <div className="mark-icon"><Waypoints size={compact ? 18 : 21} strokeWidth={2.4} /></div>
      {!compact && <div><strong>Sentinel</strong><span>Flow</span></div>}
    </div>
  );
}

function Sidebar({ active, onSelect }: { active: string; onSelect: (value: string) => void }) {
  const items = [
    { id: "overview", icon: LayoutDashboard, label: "总览" },
    { id: "processes", icon: Cpu, label: "进程" },
    { id: "flows", icon: Network, label: "流量" },
    { id: "events", icon: ShieldAlert, label: "风险事件" }
  ];
  return (
    <aside className="sidebar">
      <AppMark />
      <nav>
        <p className="nav-caption">监控中心</p>
        {items.map(({ id, icon: Icon, label }) => (
          <button key={id} className={active === id ? "active" : ""} onClick={() => onSelect(id)}>
            <Icon size={18} /> <span>{label}</span>
            {id === "events" && <i>2</i>}
          </button>
        ))}
        <p className="nav-caption nav-second">管理</p>
        <button onClick={() => onSelect("rules")} className={active === "rules" ? "active" : ""}><SlidersHorizontal size={18} /><span>监控规则</span></button>
        <button onClick={() => onSelect("coverage")} className={active === "coverage" ? "active" : ""}><Blocks size={18} /><span>系统覆盖</span></button>
      </nav>
      <div className="local-card">
        <span><ShieldCheck size={17} /> Local-first</span>
        <p>所有行为分析均在本机完成</p>
        <div><i /><small>数据未离开设备</small></div>
      </div>
      <div className="sidebar-footer"><div className="device-icon"><Laptop size={17} /></div><div><strong>当前设备</strong><span>本地监控节点</span></div><ChevronRight size={16} /></div>
    </aside>
  );
}

function StatCard({ icon: Icon, label, value, sub, tone, spark }: { icon: typeof Activity; label: string; value: string; sub: string; tone: string; spark?: number[] }) {
  return (
    <article className="stat-card">
      <div className={`stat-icon ${tone}`}><Icon size={19} /></div>
      <div className="stat-copy"><span>{label}</span><strong>{value}</strong><small>{sub}</small></div>
      {spark && <div className={`mini-bars ${tone}`}>{spark.map((height, index) => <i key={index} style={{ height: `${height}%` }} />)}</div>}
    </article>
  );
}

function RiskBadge({ level }: { level: RiskLevel }) {
  return <span className={`risk-badge ${level}`}><i />{riskText[level]}</span>;
}

function ProcessIcon({ process }: { process: ProcessFlow }) {
  const initials = process.name.slice(0, 2).toUpperCase();
  return <div className={`process-icon ${process.is_agent ? "agent" : process.is_proxy ? "proxy" : ""}`}>{process.is_agent ? <Bot size={18} /> : process.is_proxy ? <Globe2 size={18} /> : initials}</div>;
}

function ProcessTable({ processes, processScope = "running", connectionScope = "active", maxRows, onOpen, onCopy, onToggleNetwork, copyingProcessId, networkActionId }: { processes: ProcessFlow[]; processScope?: ProcessScope; connectionScope?: ConnectionScope; maxRows?: number; onOpen: (process: ProcessFlow) => void; onCopy: (process: ProcessFlow) => void; onToggleNetwork: (process: ProcessFlow) => void; copyingProcessId: string | null; networkActionId: string | null }) {
  const [query, setQuery] = useState("");
  const [sortState, setSortState] = useState<ProcessSortState | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const deferredQuery = useDeferredValue(query);
  const searchIndex = useMemo(() => buildProcessSearchIndex(processes), [processes]);
  const scoped = useMemo(() => processes.filter((process) => processScope === "history" || process.is_running), [processes, processScope]);
  const filtered = useMemo(
    () => filterProcesses(processes, processScope, deferredQuery, searchIndex),
    [processes, processScope, deferredQuery, searchIndex]
  );
  const ordered = useMemo(() => applyProcessOrder(filtered, sortState), [filtered, sortState]);
  const visible = maxRows ? ordered.slice(0, maxRows) : ordered;
  const maxUpload = useMemo(() => getMaxRunningUpload(processes), [processes]);
  const isVirtualized = !maxRows && ordered.length > PROCESS_VIRTUALIZATION_THRESHOLD;
  const virtualRange = useMemo(
    () => isVirtualized ? getVirtualRange(ordered.length, scrollTop) : { start: 0, end: ordered.length, topOffset: 0, bottomOffset: 0 },
    [isVirtualized, ordered.length, scrollTop]
  );
  const virtualRows = isVirtualized ? ordered.slice(virtualRange.start, virtualRange.end) : visible;

  function sortProcesses(key: ProcessSortKey) {
    const direction: SortDirection = sortState?.key === key && sortState.direction === "desc" ? "asc" : "desc";
    setSortState({ key, direction, orderedIds: sortProcessIds(scoped, key, direction, connectionScope) });
    setScrollTop(0);
  }

  function sortHeader(label: string, key: ProcessSortKey) {
    const active = sortState?.key === key;
    const direction = active ? sortState.direction : null;
    return <button type="button" className={`sort-button ${active ? "active" : ""}`} onClick={() => sortProcesses(key)} title="点击切换升降序；排序后固定行顺序"><span>{label}</span><i aria-hidden="true">{direction === "asc" ? "↑" : direction === "desc" ? "↓" : "↕"}</i></button>;
  }

  return (
    <section className="panel process-panel">
      <div className="panel-head">
        <div><h2>进程活动</h2><p>{processScope === "history" ? `累计保留 ${filtered.length} 个进程实例` : `${filtered.length} 个进程正在运行`}{sortState ? " · 行顺序已锁定" : ""}</p></div>
        <div className="table-tools"><label><Search size={15} /><input value={query} onChange={(event) => { setQuery(event.target.value); setScrollTop(0); }} placeholder="名称 / PID / 地址" /></label></div>
      </div>
      <div className={`table-wrap ${isVirtualized ? "virtual-table-wrap" : ""}`} onScroll={isVirtualized ? (event) => setScrollTop(event.currentTarget.scrollTop) : undefined}>
        <table>
          <thead><tr><th>应用 / 进程</th><th className="sortable-header" aria-sort={sortState?.key === "status" ? (sortState.direction === "asc" ? "ascending" : "descending") : "none"}>{sortHeader("状态名称", "status")}</th><th>上传速率</th><th className="sortable-header" aria-sort={sortState?.key === "upload" ? (sortState.direction === "asc" ? "ascending" : "descending") : "none"}>{sortHeader("累计上传", "upload")}</th><th className="sortable-header" aria-sort={sortState?.key === "connections" ? (sortState.direction === "asc" ? "ascending" : "descending") : "none"}>{sortHeader("连接", "connections")}</th><th>连接目标</th><th>风险</th><th>操作</th></tr></thead>
          <tbody>
            {isVirtualized && virtualRange.topOffset > 0 && <tr aria-hidden="true" className="virtual-spacer"><td colSpan={8} style={{ height: virtualRange.topOffset }} /></tr>}
            {virtualRows.map((process) => {
              const latestConnection = getLatestConnection(process, connectionScope);
              const networkPending = networkActionId === process.executable;
              const networkUnavailable = !process.is_network_blocked && (!process.is_running || !process.executable);
              return <tr key={process.process_instance_id} className={process.is_running ? "" : "historical-row"} onClick={() => onOpen(process)}>
                <td><div className="process-name"><ProcessIcon process={process} /><div><strong>{process.root_application || process.name}</strong><span>{process.name} · PID {process.pid}</span></div></div></td>
                <td><span className={`process-status ${process.is_running ? "running" : "stopped"}`}><i />{process.is_running ? "运行中" : "已退出"}</span><small className="status-time">{process.is_running ? timeAgo(process.started_at) : formatTimestamp(process.ended_at)}</small></td>
                <td><strong className="mono">{process.is_running ? formatRate(process.upload_bps) : "—"}</strong>{process.is_running && <div className="rate-track"><i style={{ width: `${Math.min(100, process.upload_bps / maxUpload * 100)}%` }} /></div>}</td>
                <td className="mono muted">{formatBytes(process.upload_total)}</td>
                <td><span className="connection-count"><strong>{process.active_connection_count}</strong> 活跃 / {process.total_connection_count} 总计</span></td>
                <td><span className="destination"><Globe2 size={13} />{latestConnection?.remote_endpoint || (connectionScope === "active" ? "暂无活跃连接" : "暂无连接记录")}</span></td>
                <td><RiskBadge level={process.risk_level} /></td>
                <td><div className="row-actions"><button className={`network-toggle-button ${process.is_network_blocked ? "blocked" : ""}`} disabled={networkPending || networkUnavailable} title={networkUnavailable ? (process.executable ? "历史进程不能新建封禁规则" : "无法获取可执行文件绝对路径") : process.is_network_blocked ? "手动解除该程序的持久网络封禁" : "持久禁止该程序联网"} aria-label={`${process.is_network_blocked ? "恢复" : "禁止"} ${process.name} 联网`} onClick={(event) => { event.stopPropagation(); onToggleNetwork(process); }}>{networkPending ? <LoaderCircle size={13} className="spin" /> : process.is_network_blocked ? <Wifi size={13} /> : <WifiOff size={13} />}<span>{networkPending ? "处理中" : process.is_network_blocked ? "恢复联网" : "禁止联网"}</span></button><button className="ai-copy-button" disabled={copyingProcessId === process.process_instance_id} title="复制进程、上传与证据信息，并附带 AI 分析提示词" aria-label={`复制 ${process.name} 的 AI 分析信息`} onClick={(event) => { event.stopPropagation(); onCopy(process); }}>{copyingProcessId === process.process_instance_id ? <LoaderCircle size={13} className="spin" /> : <Copy size={13} />}<span>{copyingProcessId === process.process_instance_id ? "收集中" : "复制 AI 分析"}</span></button><ChevronRight size={16} className="row-chevron" /></div></td>
              </tr>;
            })}
            {isVirtualized && virtualRange.bottomOffset > 0 && <tr aria-hidden="true" className="virtual-spacer"><td colSpan={8} style={{ height: virtualRange.bottomOffset }} /></tr>}
            {!filtered.length && <tr><td colSpan={8} className="empty-row">没有匹配的进程</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function EventItem({ event }: { event: RiskEvent }) {
  return (
    <div className={`event-item ${event.level}`}>
      <div className="event-symbol">{event.level === "high" ? <ShieldAlert size={17} /> : event.level === "medium" ? <Activity size={17} /> : <Check size={17} />}</div>
      <div className="event-copy"><div><strong>{event.title}</strong><span>{timeAgo(event.timestamp)}</span></div><p>{event.process} · {event.detail}</p></div>
    </div>
  );
}

function SettingsDrawer({ settings, onClose, onSave }: { settings: MonitorSettings; onClose: () => void; onSave: (settings: MonitorSettings) => void }) {
  const [draft, setDraft] = useState(settings);
  const [tlsStatus, setTlsStatus] = useState<TlsMonitorStatus | null>(null);
  const [tlsInstallInfo, setTlsInstallInfo] = useState<TlsInstallationInfo | null>(null);
  const [tlsInstallBusy, setTlsInstallBusy] = useState(false);
  const [tlsInstallError, setTlsInstallError] = useState("");

  useEffect(() => {
    if (!isTauri()) return;
    let cancelled = false;
    void invoke<TlsMonitorStatus>("get_tls_monitor_status").then((status) => {
      if (!cancelled) setTlsStatus(status);
    }).catch(() => undefined);
    void invoke<TlsInstallationInfo>("get_tls_installation_info").then((info) => {
      if (!cancelled) setTlsInstallInfo(info);
    }).catch(() => undefined);
    return () => { cancelled = true; };
  }, []);

  async function stopAllTlsMonitors() {
    if (!isTauri()) return;
    try {
      const status = await invoke<TlsMonitorStatus>("stop_all_tls_monitors");
      setTlsStatus(status);
    } catch {
      // The status remains visible; the next open will retry the native query.
    }
  }

  async function installTlsEngine() {
    if (!isTauri()) return;
    setTlsInstallBusy(true);
    setTlsInstallError("");
    try {
      setTlsInstallInfo(await invoke<TlsInstallationInfo>("install_tls_engine"));
    } catch (error) {
      setTlsInstallError(String(error));
      void invoke<TlsInstallationInfo>("get_tls_installation_info").then(setTlsInstallInfo).catch(() => undefined);
    } finally {
      setTlsInstallBusy(false);
    }
  }

  async function uninstallTlsEngine() {
    if (!isTauri() || !window.confirm("卸载 TLS 引擎 mitmproxy？这不会删除 CA、流量日志或系统中已有的信任设置。")) return;
    setTlsInstallBusy(true);
    setTlsInstallError("");
    try {
      setTlsInstallInfo(await invoke<TlsInstallationInfo>("uninstall_tls_engine"));
    } catch (error) {
      setTlsInstallError(String(error));
    } finally {
      setTlsInstallBusy(false);
    }
  }

  return (
    <div className="drawer-layer" onMouseDown={onClose}>
      <aside className="settings-drawer" onMouseDown={(event) => event.stopPropagation()}>
        <div className="drawer-head"><div><span>监控偏好</span><h2>规则与提醒</h2></div><button onClick={onClose}>×</button></div>
        <div className="drawer-content">
          <section className="setting-section">
            <div className="setting-title"><div className="setting-symbol coral"><Upload size={18} /></div><div><strong>上传速率阈值</strong><span>单进程一分钟预计上传量超过该值时提醒</span></div></div>
            <div className="threshold-value"><strong>{draft.threshold_mb_per_minute}</strong><span>MB / 分钟</span></div>
            <input className="range" type="range" min="5" max="250" step="5" value={draft.threshold_mb_per_minute} onChange={(event) => setDraft({ ...draft, threshold_mb_per_minute: Number(event.target.value) })} />
            <div className="range-labels"><span>5 MB</span><span>250 MB</span></div>
          </section>
          <section className="setting-section">
            <h3>监控范围</h3>
            <Toggle icon={Bot} label="重点识别 AI Agent" detail="Codex、Claude Code、Grok CLI、Harness 等进程树" checked={draft.monitor_agents} onChange={(checked) => setDraft({ ...draft, monitor_agents: checked })} />
            <Toggle icon={Cpu} label="所有应用与子进程" detail="关联父子进程，避免只显示 node 或 helper" checked={draft.monitor_all_apps} onChange={(checked) => setDraft({ ...draft, monitor_all_apps: checked })} />
            <Toggle icon={FileLock2} label="敏感文件关联" detail="需要系统扩展权限；当前默认关闭" checked={draft.sensitive_file_correlation} onChange={(checked) => setDraft({ ...draft, sensitive_file_correlation: checked })} />
          </section>
          <section className="setting-section">
            <h3>TLS 客户端监控</h3>
            <div className="tls-setting-note"><ShieldCheck size={16} /><span>默认只显示 TLS 元数据。单应用解密模式只捕获你在进程详情中明确启动的 PID，不修改系统代理、默认路由或虚拟网卡。</span></div>
            <div className="select-row"><span>监控模式</span><select value={draft.tls_mode} onChange={(event) => setDraft({ ...draft, tls_mode: event.target.value as MonitorSettings["tls_mode"] })}><option value="metadata">仅 TLS 元数据（无侵入）</option><option value="keylog">SSLKEYLOGFILE（无证书，需抓包）</option><option value="local_proxy">单应用本地解密代理</option></select></div>
            {draft.tls_mode === "local_proxy" && <>
              <label className="tls-input-row"><span>mitmdump 路径</span><input value={draft.tls_engine_path} onChange={(event) => setDraft({ ...draft, tls_engine_path: event.target.value })} placeholder="留空则从 PATH 查找 mitmdump" /></label>
              <p className="setting-help">Local Capture 是透明的按进程捕获，不监听系统代理端口；因此不会接管系统代理、VPN 或 VirtualBox 流量。</p>
              <Toggle icon={FileText} label="保存请求头" detail="开启后记录 HTTP/WebSocket 请求或响应头；可能包含 Cookie、Authorization 等敏感信息" checked={draft.tls_capture_headers} onChange={(checked) => setDraft({ ...draft, tls_capture_headers: checked })} />
              <Toggle icon={FileText} label="保存正文预览" detail="开启后记录文本或二进制正文的有限预览；正文不会无限制写入" checked={draft.tls_capture_body_preview} onChange={(checked) => setDraft({ ...draft, tls_capture_body_preview: checked })} />
              {draft.tls_capture_body_preview && <label className="tls-input-row"><span>正文上限</span><select value={draft.tls_body_preview_bytes} onChange={(event) => setDraft({ ...draft, tls_body_preview_bytes: Number(event.target.value) })}><option value={4096}>4 KB</option><option value={16384}>16 KB</option><option value={65536}>64 KB</option></select></label>}
              <Toggle icon={FileText} label="保留 URL 查询参数" detail="关闭后会把 ? 后面的参数替换为脱敏标记；开启可能记录令牌等敏感参数" checked={!draft.tls_redact_query_strings} onChange={(checked) => setDraft({ ...draft, tls_redact_query_strings: !checked })} />
              <label className="tls-input-row"><span>保留流条数</span><input type="number" min={1} max={100} value={draft.tls_recent_flow_limit} onChange={(event) => setDraft({ ...draft, tls_recent_flow_limit: Math.min(100, Math.max(1, Number(event.target.value) || 20)) })} /><small>最近请求/响应，默认 20 条</small></label>
              <label className="tls-input-row"><span>保护进程</span><textarea value={draft.tls_excluded_processes.join(", ")} onChange={(event) => setDraft({ ...draft, tls_excluded_processes: event.target.value.split(/[,\n]/).map((value) => value.trim()).filter(Boolean) })} placeholder="VirtualBox, WireGuard, OpenVPN" rows={2} /></label>
            </>}
            {draft.tls_mode === "keylog" && <p className="setting-help">目标应用必须在启动前继承 SSLKEYLOGFILE；此模式不改网络路径，也不会影响 VPN 或 VirtualBox。</p>}
            {tlsStatus && <div className={`tls-monitor-status ${tlsStatus.running ? "running" : ""}`}>
              <strong>{tlsStatus.running ? `TLS 监控正在运行 · ${tlsStatus.running_count} 个进程` : "TLS 监控未运行"}</strong>
              <span>{tlsStatus.note}</span>
              {tlsStatus.sessions.filter((session) => session.running).length > 0 && <div className="tls-session-list">{tlsStatus.sessions.filter((session) => session.running).map((session) => <span key={session.target_pid}><i />{session.process_name || "未知进程"} · PID {session.target_pid}</span>)}</div>}
              {tlsStatus.ca_path && <code>CA：{tlsStatus.ca_path}{tlsStatus.ca_ready ? "（已生成，尚未自动信任）" : "（等待引擎生成）"}</code>}
              {tlsStatus.engine_log_path && <code>引擎日志：{tlsStatus.engine_log_path}</code>}
              {tlsStatus.last_error && <small>{tlsStatus.last_error}</small>}
              {tlsStatus.running && <button type="button" className="secondary tls-stop-button" onClick={() => void stopAllTlsMonitors()}>一键停止所有 TLS 监控</button>}
            </div>}
            <div className="tls-install-card">
              <div className="tls-install-head"><div><strong>监控引擎安装</strong><span>{tlsInstallInfo ? `${tlsInstallInfo.platform} · ${tlsInstallInfo.installed ? "已安装" : "未安装"}` : "正在检查本机安装状态…"}</span></div>{tlsInstallInfo?.installed ? <Check size={16} /> : <Terminal size={16} />}</div>
              {tlsInstallInfo && <>
                {tlsInstallInfo.version && <code className="tls-install-version">{tlsInstallInfo.version}</code>}
                {tlsInstallInfo.engine_path && <small className="tls-install-path">引擎：{tlsInstallInfo.engine_path}</small>}
                <code className="tls-install-command">安装：{tlsInstallInfo.install_command}</code>
                <span className="tls-install-note">{tlsInstallInfo.manual_note}</span>
                <span className="tls-install-note">官方文档：{tlsInstallInfo.official_url}</span>
                <div className="tls-install-actions">
                  {tlsInstallInfo.installed ? <button type="button" className="secondary" disabled={tlsInstallBusy || !!tlsStatus?.running} onClick={() => void uninstallTlsEngine()}>{tlsInstallBusy ? "处理中…" : "卸载 mitmproxy"}</button> : <button type="button" className="primary" disabled={tlsInstallBusy} onClick={() => void installTlsEngine()}>{tlsInstallBusy ? "安装中…" : "一键安装 mitmproxy"}</button>}
                  {tlsInstallInfo.uninstall_command && tlsInstallInfo.installed && <code>卸载：{tlsInstallInfo.uninstall_command}</code>}
                </div>
                {tlsStatus?.running && tlsInstallInfo.installed && <small className="tls-install-warning">请先停止 TLS 监控，才能卸载引擎。</small>}
                {tlsInstallInfo.last_output && <details><summary>查看安装命令输出</summary><pre>{tlsInstallInfo.last_output}</pre></details>}
              </>}
              {tlsInstallError && <small className="tls-install-error">{tlsInstallError}</small>}
            </div>
          </section>
          <section className="setting-section">
            <h3>提醒方式</h3>
            <Toggle icon={BellRing} label="系统桌面提醒" detail="监控窗口关闭时也能收到高风险提醒" checked={draft.desktop_notifications} onChange={(checked) => setDraft({ ...draft, desktop_notifications: checked })} />
            <div className="select-row"><span>触发级别</span><select value={draft.alert_level} onChange={(event) => setDraft({ ...draft, alert_level: event.target.value as MonitorSettings["alert_level"] })}><option value="notify">所有超阈值事件</option><option value="high_risk">仅高风险事件</option></select></div>
          </section>
          <div className="privacy-note"><ShieldCheck size={18} /><div><strong>设置只保存在这台设备</strong><p>Sentinel Flow 不会上传进程名、连接目标或文件路径。</p></div></div>
        </div>
        <div className="drawer-actions"><button className="secondary" onClick={onClose}>取消</button><button className="primary" onClick={() => onSave(draft)}>保存设置</button></div>
      </aside>
    </div>
  );
}

function Toggle({ icon: Icon, label, detail, checked, onChange }: { icon: typeof Activity; label: string; detail: string; checked: boolean; onChange: (value: boolean) => void }) {
  return <label className="toggle-row"><div className="toggle-icon"><Icon size={17} /></div><div><strong>{label}</strong><span>{detail}</span></div><input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} /><i className="toggle-ui" /></label>;
}

function demoProcessDetail(process: ProcessFlow): ProcessDetail {
  return {
    process_instance_id: process.process_instance_id,
    pid: process.pid,
    parent_pid: process.parent_pid,
    name: process.name,
    executable: process.executable,
    command_line: process.command_line ?? [],
    current_working_directory: process.current_working_directory ?? "",
    launch_target: process.launch_target,
    arguments: (process.command_line ?? []).slice(1),
    started_at: 0,
    ancestry: [
      { pid: 921, name: "Electron", executable: "/Applications/Codex.app/Contents/MacOS/Codex", command_line: ["/Applications/Codex.app/Contents/MacOS/Codex"] },
      { pid: process.pid, name: process.name, executable: process.executable, command_line: process.command_line ?? [] }
    ],
    connections: process.connection_history,
    open_files: process.launch_target ? [
      { path: "/Users/demo/Videos/final-cut.mp4", descriptor: "12r", access_mode: "读取", file_type: "REG", size_bytes: 824_388_608, offset_bytes: 347_078_656, category: "音视频", evidence: "完整启动命令直接引用此文件（不是上传证明）", likely_upload_source: false },
      { path: process.launch_target, descriptor: "argv", access_mode: "命令参数", file_type: "REG", size_bytes: 18_420, category: "源代码", evidence: "当前进程的执行脚本（不作为上传内容证据）", likely_upload_source: false }
    ] : [],
    tls_inspection: { detected: true, state: "TLS 已检测，未发现会话密钥", method: "仅被动观测", plaintext_available: false, note: "浏览器预览不执行网络解密。" },
    upload_assessment: process.launch_target ? "当前正在发送网络字节，但文件只提供访问相关性，不能断定视频已被上传。" : "当前正在发送网络字节，但没有可证明的文件到网络因果证据。",
    evidence_confidence: "无法确认",
    notes: ["浏览器预览使用演示数据；Tauri 桌面端会通过 lsof 读取该 PID 的真实文件句柄与连接。", "HTTPS 正文处于加密状态，未进行中间人解密。"]
  };
}

function ProcessDrawer({ process, nativeMode, connectionScope, onConnectionScopeChange, onClose }: { process: ProcessFlow; nativeMode: boolean; connectionScope: ConnectionScope; onConnectionScopeChange: (scope: ConnectionScope) => void; onClose: () => void }) {
  const [detail, setDetail] = useState<ProcessDetail | null>(() => nativeMode ? null : demoProcessDetail(process));
  const [detailError, setDetailError] = useState("");
  const [detailTab, setDetailTab] = useState<"overview" | "upload-stats">("overview");
  const [tlsStatus, setTlsStatus] = useState<TlsMonitorStatus | null>(null);
  const [tlsActionError, setTlsActionError] = useState("");

  useEffect(() => {
    if (!nativeMode) {
      setDetail(demoProcessDetail(process));
      return;
    }
    let cancelled = false;
    async function refreshDetail() {
      try {
        const data = await invoke<ProcessDetail>("get_process_detail", { pid: process.pid, processInstanceId: process.process_instance_id });
        if (!cancelled) { setDetail(data); setDetailError(""); }
      } catch (error) {
        if (!cancelled) setDetailError(String(error));
      }
    }
    void refreshDetail();
    if (!process.is_running) return () => { cancelled = true; };
    const timer = window.setInterval(refreshDetail, 2800);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [nativeMode, process.pid, process.process_instance_id, process.is_running]);

  useEffect(() => {
    if (!nativeMode) return;
    let cancelled = false;
    async function refreshTlsStatus() {
      try {
        const status = await invoke<TlsMonitorStatus>("get_tls_monitor_status");
        if (!cancelled) setTlsStatus(status);
      } catch {
        // The browser preview does not expose native TLS monitor commands.
      }
    }
    void refreshTlsStatus();
    const timer = window.setInterval(refreshTlsStatus, 2500);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [nativeMode, process.pid]);

  async function toggleTlsMonitor() {
    if (!nativeMode) return;
    setTlsActionError("");
    try {
      const currentSession = tlsStatus?.sessions.find((session) => session.target_pid === process.pid);
      const command = currentSession?.running
        ? "stop_tls_process_monitor"
        : "start_tls_monitor";
      const status = command === "start_tls_monitor"
        ? await invoke<TlsMonitorStatus>(command, { pid: process.pid, processName: process.name, executable: process.executable })
        : await invoke<TlsMonitorStatus>(command, { pid: process.pid });
      setTlsStatus(status);
    } catch (error) {
      setTlsActionError(String(error));
    }
  }

  const commandLine = detail?.command_line.length ? detail.command_line : process.command_line ?? [];
  const launchTarget = detail?.launch_target || process.launch_target;
  const cwd = detail?.current_working_directory || process.current_working_directory || "";
  const fileEvidence = detail?.open_files ?? [];
  const allConnections = detail?.connections.length ? detail.connections : process.connection_history;
  const visibleConnections = connectionScope === "active" ? allConnections.filter((connection) => connection.is_alive) : allConnections;
  const currentTlsSession = tlsStatus?.sessions.find((session) => session.target_pid === process.pid);
  const processTlsRunning = currentTlsSession?.running === true;
  const processTlsFlows = currentTlsSession?.recent_flows ?? tlsStatus?.recent_flows.filter((flow) => flow.target_pid === process.pid) ?? [];

  return (
    <div className="drawer-layer" onMouseDown={onClose}>
      <aside className="settings-drawer process-drawer" onMouseDown={(event) => event.stopPropagation()}>
        <div className="drawer-head"><div><span>进程详情</span><h2>{process.root_application || process.name}</h2></div><button onClick={onClose}>×</button></div>
        <div className="detail-tabs" role="tablist" aria-label="进程详情页签"><button role="tab" aria-selected={detailTab === "overview"} className={detailTab === "overview" ? "active" : ""} onClick={() => setDetailTab("overview")}>运行详情</button><button role="tab" aria-selected={detailTab === "upload-stats"} className={detailTab === "upload-stats" ? "active" : ""} onClick={() => setDetailTab("upload-stats")}>上传统计</button></div>
        {detailTab === "overview" ? <div className="drawer-content">
          <div className="process-hero"><ProcessIcon process={process} /><div><span className={`process-status ${process.is_running ? "running" : "stopped"}`}><i />{process.is_running ? "运行中" : "历史进程"}</span><strong>风险评分 {process.risk_score}</strong><span>PID {process.pid} · 实例 {process.process_instance_id}</span></div></div>
          <div className="detail-grid"><div><Upload size={17} /><span>实时上传</span><strong>{formatRate(process.upload_bps)}</strong></div><div><Download size={17} /><span>实时下载</span><strong>{formatRate(process.download_bps)}</strong></div><div><Database size={17} /><span>累计上传</span><strong>{formatBytes(process.upload_total)}</strong></div><div><CircleGauge size={17} /><span>CPU / 内存</span><strong>{process.cpu_percent.toFixed(1)}% · {formatBytes(process.memory_bytes)}</strong></div></div>
          {detail ? <div className={`evidence-summary ${detail.evidence_confidence === "较高" ? "strong" : ""}`}><div><Radio size={18} /></div><div><span>传输内容判断 · 证据强度 {detail.evidence_confidence}</span><strong>{detail.upload_assessment}</strong></div></div> : <div className="detail-loading"><span />正在读取该进程的命令、文件和连接…</div>}
          {detailError && <div className="detail-error"><Info size={16} />{detailError}</div>}

          <section className="setting-section detail-section">
            <h3><Terminal size={15} /> 启动与执行详情</h3>
            <div className="detail-pairs">
              <div><span>根应用</span><strong>{process.root_application || process.name}</strong></div>
              <div><span>当前进程</span><strong>{process.name} · PID {process.pid}</strong></div>
              <div className="wide"><span>实际执行目标</span><strong>{launchTarget || "未发现独立脚本或模块（可能是应用二进制自身）"}</strong></div>
              <div className="wide"><span>工作目录</span><code>{cwd || "系统未返回"}</code></div>
              <div className="wide"><span>解释器 / 可执行文件</span><code>{process.executable || "系统未返回"}</code></div>
            </div>
            <div className="command-block"><span>完整命令行</span><code>{commandLine.length ? formatCommand(commandLine) : "系统未返回命令参数"}</code></div>
            {!!detail?.arguments.length && <div className="argument-list"><span>参数拆分</span><div>{detail.arguments.map((argument, index) => <code key={`${argument}-${index}`}>{index + 1}. {argument}</code>)}</div></div>}
          </section>

          <section className="setting-section detail-section">
            <h3><FileText size={15} /> 文件访问证据 <em>{fileEvidence.length}</em></h3>
            <p className="evidence-boundary">这里只显示经过运行时过滤的用户文件或命令参数证据；句柄、偏移和同期上传不能证明文件内容已经进入网络。</p>
            {detail?.open_files.length ? <div className="file-evidence-list">{detail.open_files.map((file, index) => {
              const progress = file.size_bytes && file.offset_bytes !== undefined ? Math.min(100, file.offset_bytes / file.size_bytes * 100) : null;
              return <div className="file-evidence" key={`${file.path}-${index}`}>
                <div className="file-kind">{file.category === "源代码" ? <FileCode2 size={17} /> : <FileText size={17} />}</div>
                <div className="file-copy"><div><strong>{file.path.split("/").pop()}</strong></div><code>{file.path}</code><span>{file.category} · {file.access_mode} · {file.size_bytes !== undefined ? formatBytes(file.size_bytes) : "大小未知"} · {file.evidence}</span>{progress !== null && <div className="file-progress"><i style={{ width: `${progress}%` }} /><small>当前文件偏移 {progress.toFixed(1)}%</small></div>}</div>
              </div>;
            })}</div> : <p className="empty-copy">未发现有意义的打开文件或命令行文件参数。文件可能已经读入内存或在采样前关闭。</p>}
          </section>

          {detail?.tls_inspection && <section className="setting-section detail-section">
            <h3><ShieldCheck size={15} /> TLS 内容可见性</h3>
            <div className={`tls-status ${detail.tls_inspection.plaintext_available ? "available" : ""}`}><strong>{detail.tls_inspection.state}</strong><span>{detail.tls_inspection.method}</span><p>{detail.tls_inspection.note}</p>{detail.tls_inspection.keylog_path && <code>{detail.tls_inspection.keylog_path}</code>}</div>
            {nativeMode && <div className="tls-monitor-actions"><button className="secondary" disabled={!process.is_running || tlsStatus?.mode !== "local_proxy"} onClick={() => void toggleTlsMonitor()}>{processTlsRunning ? "停止此进程 TLS 监控" : "启动此进程 TLS 监控"}</button><span>{tlsStatus?.mode !== "local_proxy" ? "请先在设置中保存“单应用本地解密代理”模式" : processTlsRunning ? "此进程正在监控；关闭详情页不会停止" : "可同时监控多个进程；单应用捕获不会修改系统代理、路由或虚拟网卡"}</span></div>}
            {tlsActionError && <p className="tls-action-error">{tlsActionError}</p>}
            {currentTlsSession && <div className="tls-flow-list">
              <div className="tls-flow-head"><strong>最近流记录 · {processTlsFlows.length} / {tlsStatus?.recent_flow_limit ?? 0}</strong><span>{processTlsRunning ? "只记录监控启动后产生的新请求；当前上传速率和累计上传见上方" : "监控已停止，以下保留本次 PID 的历史流记录"}</span></div>
              {processTlsFlows.length ? processTlsFlows.map((flow, index) => <div className="tls-flow-row" key={`${flow.timestamp}-${flow.direction}-${index}`}>
                <span>{flow.protocol.toUpperCase()} · {flow.direction === "request" ? "请求/上传" : "响应/下载"} · {flow.method || (flow.status ? `HTTP ${flow.status}` : "TLS 数据")}</span>
                <strong>{flow.host || "未知端点"}</strong>
                <small>{flow.url || "非 HTTP 流"}{flow.status ? ` · HTTP ${flow.status}` : ""} · {formatBytes(flow.body_bytes)} · {new Date(flow.timestamp * 1000).toLocaleTimeString()}</small>
                {flow.headers && <details className="tls-flow-details"><summary>查看头部（{Object.keys(flow.headers).length}）</summary><div>{Object.entries(flow.headers).map(([key, value]) => <code key={key}>{key}: {value}</code>)}</div></details>}
                {flow.body_preview && <code className="tls-flow-body">{flow.body_preview_encoding === "base64" ? "[base64] " : ""}{flow.body_preview}</code>}
              </div>) : <p className="tls-flow-empty">暂时没有抓到新的可解密流。请在启动监控后重新触发一次请求；如果仍为空，检查目标应用是否信任上方 CA、是否启用了证书锁定，或是否使用了无法被 HTTP/TCP addon 识别的 QUIC/专有协议。</p>}
            </div>}
          </section>}

          <section className="setting-section detail-section">
            <div className="connection-section-head"><h3><Globe2 size={15} /> 网络连接 <em>{visibleConnections.length}</em></h3><div className="mini-segments"><button className={connectionScope === "active" ? "active" : ""} onClick={() => onConnectionScopeChange("active")}>当前</button><button className={connectionScope === "history" ? "active" : ""} onClick={() => onConnectionScopeChange("history")}>历史 + 当前</button></div></div>
            {visibleConnections.length ? visibleConnections.map((connection, index) => <div className={`connection-detail ${connection.is_alive ? "" : "closed"}`} key={`${connection.local_endpoint}-${connection.remote_endpoint}-${connection.first_seen_at}-${index}`}><div><Globe2 size={15} /></div><div><strong>{connection.remote_endpoint}</strong><span>{connection.is_transient ? "瞬时 · " : ""}{connection.protocol} · {connection.is_alive ? connection.state : "已断开"}</span><code>{connection.local_endpoint} → {connection.remote_endpoint}</code><small>{formatTimestamp(connection.first_seen_at)} · {connection.is_alive ? "连接中" : `${formatDuration(connection.first_seen_at, connection.closed_at)} 后断开`}</small></div></div>) : <p className="empty-copy">{connectionScope === "active" ? "当前没有活跃连接；可切换到历史连接查看已结束的瞬时活动。" : "尚未保留到连接记录。"}</p>}
          </section>

          {!!detail?.ancestry.length && <section className="setting-section detail-section"><h3><GitBranch size={15} /> 完整父进程链</h3><div className="ancestry-list">{detail.ancestry.map((ancestor, index) => <div key={`${ancestor.pid}-${index}`}><i>{index + 1}</i><div><strong>{ancestor.name} <span>PID {ancestor.pid}</span></strong><code>{ancestor.command_line.length ? formatCommand(ancestor.command_line) : ancestor.executable || "命令不可用"}</code></div></div>)}</div></section>}

          {!!detail?.notes.length && <div className="inspection-notes"><FolderOpen size={17} /><div><strong>如何理解这些结果</strong>{detail.notes.map((note) => <p key={note}>{note}</p>)}</div></div>}
          {process.is_proxy && <div className="privacy-note blue"><Waypoints size={18} /><div><strong>本地代理 / 隧道进程</strong><p>代理封装流量与原始应用流量分开展示，避免重复计数。</p></div></div>}
        </div> : <div className="drawer-content upload-stats-content"><UploadStatsTab process={process} nativeMode={nativeMode} /></div>}
      </aside>
    </div>
  );
}

function CoveragePage({ snapshot }: { snapshot: MonitorSnapshot }) {
  const rows = [
    { key: "network" as const, icon: Network, title: "网络流量", detail: "进程级上传/下载与连接目标" },
    { key: "process" as const, icon: Cpu, title: "进程关系", detail: "PID、启动时间、父子进程与根应用" },
    { key: "file" as const, icon: FileLock2, title: "文件访问", detail: "过滤后的句柄与命令参数证据（不等于上传证明）" }
  ];
  return <div className="page-section"><div className="section-heading"><span>系统覆盖</span><h1>采集能力与权限</h1><p>只显示真实生效的能力，不用模拟数据掩盖缺失的系统权限。</p></div><div className="coverage-grid">{rows.map(({ key, icon: Icon, title, detail }) => { const status = snapshot.coverage[key]; return <article key={key}><div className={`coverage-icon ${status}`}><Icon size={21} /></div><div><span>{title}</span><strong>{detail}</strong><small>{status === "active" ? "已启用" : status === "limited" ? "受限模式" : "需要系统权限"}</small></div></article>; })}</div><section className="panel coverage-note"><div><Shield size={20} /></div><div><h2>{snapshot.coverage.collector}</h2><p>{snapshot.coverage.note}</p></div></section></div>;
}

function TlsMonitorToolbar({ status, onStopAll }: { status: TlsMonitorStatus | null; onStopAll: () => void }) {
  const runningSessions = status?.sessions.filter((session) => session.running) ?? [];
  return <section className="panel tls-monitor-toolbar">
    <div className="tls-monitor-toolbar-head">
      <div><h2>TLS 监控列表</h2><p>{runningSessions.length ? `正在监控 ${runningSessions.length} 个进程；每个进程使用独立的 Local Capture 会话` : "尚未启动进程级 TLS 监控"}</p></div>
      <button type="button" className="secondary" disabled={!runningSessions.length} onClick={onStopAll}>一键停止所有 TLS 监控</button>
    </div>
    {runningSessions.length ? <div className="tls-toolbar-sessions">{runningSessions.map((session) => <span key={session.target_pid}><i />{session.process_name || "未知进程"} · PID {session.target_pid}</span>)}</div> : <span className="tls-toolbar-note">请在进程详情中启动。关闭详情页不会停止会话；只有单独停止或点击上方按钮才会停止。</span>}
  </section>;
}

function AllProcessesPage({ snapshot, tlsStatus, onStopAllTlsMonitors, connectionScope, onConnectionScopeChange, onOpen, onCopy, onToggleNetwork, copyingProcessId, networkActionId }: { snapshot: MonitorSnapshot; tlsStatus: TlsMonitorStatus | null; onStopAllTlsMonitors: () => void; connectionScope: ConnectionScope; onConnectionScopeChange: (scope: ConnectionScope) => void; onOpen: (p: ProcessFlow) => void; onCopy: (p: ProcessFlow) => void; onToggleNetwork: (p: ProcessFlow) => void; copyingProcessId: string | null; networkActionId: string | null }) {
  return <div className="page-section">
    <div className="section-heading"><span>进程观察器</span><h1>历史进程与连接</h1><p>同一个 PID 的不同生命周期按启动时间拆分。历史进程包含当前运行中的进程，短暂出现后停止的连接也会继续保留。</p></div>
    <TlsMonitorToolbar status={tlsStatus} onStopAll={onStopAllTlsMonitors} />
    <div className="scope-filter-bar">
      <div><span><Network size={14} />连接信息</span><div className="scope-segments"><button className={connectionScope === "active" ? "active" : ""} onClick={() => onConnectionScopeChange("active")}>仅当前活跃</button><button className={connectionScope === "history" ? "active" : ""} onClick={() => onConnectionScopeChange("history")}>历史连接（含当前）</button></div></div>
    </div>
    <ProcessTable processes={snapshot.processes} processScope="history" connectionScope={connectionScope} onOpen={onOpen} onCopy={onCopy} onToggleNetwork={onToggleNetwork} copyingProcessId={copyingProcessId} networkActionId={networkActionId} />
  </div>;
}

export default function App() {
  const [snapshot, setSnapshot] = useState<MonitorSnapshot>(() => createDemoSnapshot());
  const [activePage, setActivePage] = useState("overview");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [selectedProcess, setSelectedProcess] = useState<ProcessFlow | null>(null);
  const [mobileNav, setMobileNav] = useState(false);
  const [nativeMode, setNativeMode] = useState(false);
  const [copyingProcessId, setCopyingProcessId] = useState<string | null>(null);
  const [networkActionId, setNetworkActionId] = useState<string | null>(null);
  const [networkPrompt, setNetworkPrompt] = useState<ProcessFlow | null>(null);
  const [connectionScope, setConnectionScope] = useState<ConnectionScope>("active");
  const [tlsStatus, setTlsStatus] = useState<TlsMonitorStatus | null>(null);
  const [copyNotice, setCopyNotice] = useState<{ tone: "success" | "error"; message: string } | null>(null);
  const notifiedEvents = useRef(new Set<string>());
  const notificationSeeded = useRef(false);

  useEffect(() => {
    let cancelled = false;
    async function refresh() {
      if (!isTauri()) {
        if (!cancelled) setSnapshot(createDemoSnapshot());
        return;
      }
      try {
        const data = await invoke<MonitorSnapshot>("get_snapshot");
        if (!cancelled) { setSnapshot(data); setNativeMode(true); }
      } catch (error) {
        console.error("Unable to collect local snapshot", error);
      }
    }
    refresh();
    const timer = window.setInterval(refresh, 1500);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, []);

  useEffect(() => {
    if (!nativeMode || !snapshot.settings.desktop_notifications) return;
    if (!notificationSeeded.current) {
      snapshot.events.forEach((event) => notifiedEvents.current.add(event.id));
      notificationSeeded.current = true;
      return;
    }
    const newEvents = snapshot.events.filter((event) => event.level === "high" && !event.acknowledged && !notifiedEvents.current.has(event.id));
    newEvents.forEach((event) => notifiedEvents.current.add(event.id));
    if (!newEvents.length) return;
    void (async () => {
      let granted = await isPermissionGranted();
      if (!granted) granted = (await requestPermission()) === "granted";
      if (granted) {
        const event = newEvents[0];
        sendNotification({ title: `Sentinel Flow · ${event.process}`, body: `${event.title}：${event.detail}` });
      }
    })();
  }, [nativeMode, snapshot.events, snapshot.settings.desktop_notifications]);

  useEffect(() => {
    if (!nativeMode) return;
    let cancelled = false;
    async function refreshTlsStatus() {
      try {
        const status = await invoke<TlsMonitorStatus>("get_tls_monitor_status");
        if (!cancelled) setTlsStatus(status);
      } catch {
        // The browser preview does not expose native TLS monitor commands.
      }
    }
    void refreshTlsStatus();
    const timer = window.setInterval(refreshTlsStatus, 2500);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [nativeMode]);

  useEffect(() => {
    if (!copyNotice) return;
    const timer = window.setTimeout(() => setCopyNotice(null), 3600);
    return () => window.clearTimeout(timer);
  }, [copyNotice]);

  const runningProcesses = useMemo(() => snapshot.processes.filter((process) => process.is_running), [snapshot.processes]);
  const sortedProcesses = useMemo(() => [...runningProcesses].sort((a, b) => b.upload_bps - a.upload_bps), [runningProcesses]);
  const riskCounts = useMemo(() => [
    { name: "正常", value: runningProcesses.filter((item) => item.risk_level === "low").length, color: "#2caa78" },
    { name: "关注", value: runningProcesses.filter((item) => item.risk_level === "medium").length, color: "#f2ad4b" },
    { name: "高风险", value: runningProcesses.filter((item) => item.risk_level === "high").length, color: "#ef6b5b" }
  ], [runningProcesses]);
  const liveSelectedProcess = selectedProcess
    ? snapshot.processes.find((process) => process.process_instance_id === selectedProcess.process_instance_id) || selectedProcess
    : null;

  async function toggleMonitoring() {
    if (isTauri()) {
      const data = await invoke<MonitorSnapshot>("toggle_monitoring");
      setSnapshot(data);
    } else setSnapshot((current) => ({ ...current, monitoring: !current.monitoring }));
  }

  async function saveSettings(settings: MonitorSettings) {
    if (isTauri()) {
      const data = await invoke<MonitorSnapshot>("update_settings", { settings });
      setSnapshot(data);
    } else setSnapshot((current) => ({ ...current, settings }));
    setSettingsOpen(false);
  }

  async function stopAllTlsMonitors() {
    if (!isTauri()) return;
    try {
      const status = await invoke<TlsMonitorStatus>("stop_all_tls_monitors");
      setTlsStatus(status);
      setCopyNotice({ tone: "success", message: "已停止全部 TLS 监控；流量历史仍会保留。" });
    } catch (error) {
      setCopyNotice({ tone: "error", message: `停止 TLS 监控失败：${String(error)}` });
    }
  }

  async function copyProcessForAi(process: ProcessFlow) {
    if (copyingProcessId) return;
    setCopyingProcessId(process.process_instance_id);
    let detail: ProcessDetail | null = nativeMode ? null : demoProcessDetail(process);
    let detailError = "";

    if (nativeMode) {
      try {
        detail = await invoke<ProcessDetail>("get_process_detail", { pid: process.pid, processInstanceId: process.process_instance_id });
      } catch (error) {
        detailError = String(error);
      }
    }

    try {
      const text = buildProcessAiReport({ snapshot, process, detail, detailError });
      await writeClipboardText(text);
      setCopyNotice({
        tone: "success",
        message: detailError ? "已复制最近快照与 AI 提示词；该进程的深度详情当前不可用。" : "已复制完整进程信息、上传观测与 AI 分析提示词。"
      });
    } catch (error) {
      setCopyNotice({ tone: "error", message: `复制失败：${String(error)}` });
    } finally {
      setCopyingProcessId(null);
    }
  }

  function requestNetworkToggle(process: ProcessFlow) {
    if (!process.is_network_blocked && (!process.is_running || !process.executable)) return;
    setNetworkPrompt(process);
  }

  async function applyNetworkToggle() {
    if (!networkPrompt || networkActionId) return;
    const process = networkPrompt;
    const shouldUnblock = process.is_network_blocked;
    setNetworkActionId(process.executable);
    try {
      if (isTauri()) {
        if (shouldUnblock) {
          await invoke("unblock_process_network", { executable: process.executable });
        } else {
          await invoke("block_process_network", { pid: process.pid, executable: process.executable, processName: process.name });
        }
        const data = await invoke<MonitorSnapshot>("get_snapshot");
        setSnapshot(data);
      } else {
        setSnapshot((current) => ({
          ...current,
          processes: current.processes.map((item) => item.executable === process.executable
            ? { ...item, is_network_blocked: !shouldUnblock }
            : item)
        }));
      }
      setCopyNotice({
        tone: "success",
        message: shouldUnblock
          ? `已手动解除 ${process.root_application || process.name} 的网络封禁。`
          : snapshot.platform === "macos"
            ? `已写入 ${process.root_application || process.name} 的 macOS 持久应用防火墙规则（系统原生接口主要限制入站连接）。`
            : `已持久禁止 ${process.root_application || process.name} 联网，重启该程序后仍会保持。`
      });
      setNetworkPrompt(null);
    } catch (error) {
      setCopyNotice({ tone: "error", message: String(error) });
    } finally {
      setNetworkActionId(null);
    }
  }

  const overview = (
    <>
      <div className="welcome-row"><div><p>安全概览</p><h1>早上好，设备一切正常。</h1><span>Sentinel Flow 正在本机持续观察进程、连接与上传行为。</span></div><div className="live-pill"><i className={snapshot.monitoring ? "pulse" : "paused"} /><div><strong>{snapshot.monitoring ? "实时监控中" : "监控已暂停"}</strong><span>{snapshot.coverage.collector}</span></div></div></div>
      {!nativeMode && <div className="preview-banner"><Info size={17} /><div><strong>当前为浏览器界面预览</strong><span>运行 <code>npm run tauri dev</code> 后会自动切换为真实本机采集。</span></div></div>}
      <div className="stats-grid">
        <StatCard icon={Upload} label="当前上传" value={formatRate(snapshot.upload_bps)} sub="全部进程实时合计" tone="coral" spark={[25, 38, 31, 62, 47, 71, 89, 67, 79]} />
        <StatCard icon={Cpu} label="观察中的进程" value={String(snapshot.observed_processes)} sub={`${snapshot.active_connections} 个活动连接`} tone="violet" />
        <StatCard icon={ShieldAlert} label="未处理风险" value={String(snapshot.events.filter((event) => !event.acknowledged).length)} sub={snapshot.events.some((event) => event.level === "high") ? "包含高风险事件" : "暂无高风险事件"} tone="amber" />
        <StatCard icon={HardDrive} label="本次累计上传" value={formatBytes(snapshot.total_upload_bytes)} sub="仅记录元数据，不读取内容" tone="green" />
      </div>
      <Suspense fallback={<div className="dashboard-grid chart-loading-grid" aria-label="图表加载中"><section className="panel chart-loading" /><section className="panel chart-loading" /></div>}>
        <DashboardCharts
          timeline={snapshot.timeline}
          riskCounts={riskCounts}
          runningProcessCount={runningProcesses.length}
          uploadBps={snapshot.upload_bps}
          downloadBps={snapshot.download_bps}
          thresholdMbPerMinute={snapshot.settings.threshold_mb_per_minute}
        />
      </Suspense>
      <TlsMonitorToolbar status={tlsStatus} onStopAll={() => void stopAllTlsMonitors()} />
      <div className="lower-grid"><ProcessTable processes={sortedProcesses} maxRows={8} onOpen={setSelectedProcess} onCopy={copyProcessForAi} onToggleNetwork={requestNetworkToggle} copyingProcessId={copyingProcessId} networkActionId={networkActionId} /><section className="panel events-panel"><div className="panel-head"><div><h2>最近事件</h2><p>需要关注的行为变化</p></div><button className="text-button" onClick={() => setActivePage("events")}>查看全部</button></div><div className="event-list">{snapshot.events.slice(0, 4).map((event) => <EventItem key={event.id} event={event} />)}{!snapshot.events.length && <div className="all-clear"><ShieldCheck size={26} /><strong>暂未发现风险</strong><span>监控将继续在本机运行</span></div>}</div></section></div>
    </>
  );

  return (
    <div className="app-shell">
      <div className={`mobile-sidebar-layer ${mobileNav ? "show" : ""}`} onClick={() => setMobileNav(false)}><div onClick={(event) => event.stopPropagation()}><Sidebar active={activePage} onSelect={(page) => { setActivePage(page); setMobileNav(false); }} /></div></div>
      <Sidebar active={activePage} onSelect={setActivePage} />
      <main>
        <header className="topbar"><button className="mobile-menu" onClick={() => setMobileNav(true)}><Menu size={20} /></button><div className="breadcrumbs"><span>Sentinel Flow</span><ChevronRight size={13} /><strong>{activePage === "overview" ? "总览" : activePage === "processes" ? "进程" : activePage === "coverage" ? "系统覆盖" : activePage === "events" ? "风险事件" : "监控规则"}</strong></div><div className="top-actions"><button className="icon-button" aria-label="通知"><Bell size={18} />{snapshot.events.some((event) => !event.acknowledged) && <i />}</button><button className="icon-button" onClick={() => setSettingsOpen(true)} aria-label="设置"><Settings size={18} /></button><button className={`monitor-button ${snapshot.monitoring ? "active" : ""}`} onClick={toggleMonitoring}>{snapshot.monitoring ? <Pause size={15} /> : <Play size={15} />}{snapshot.monitoring ? "暂停监控" : "开始监控"}</button></div></header>
        <div className="content">
          {activePage === "overview" && overview}
          {(activePage === "processes" || activePage === "flows") && <AllProcessesPage snapshot={snapshot} tlsStatus={tlsStatus} onStopAllTlsMonitors={() => void stopAllTlsMonitors()} connectionScope={connectionScope} onConnectionScopeChange={setConnectionScope} onOpen={setSelectedProcess} onCopy={copyProcessForAi} onToggleNetwork={requestNetworkToggle} copyingProcessId={copyingProcessId} networkActionId={networkActionId} />}
          {activePage === "coverage" && <CoveragePage snapshot={snapshot} />}
          {activePage === "events" && <div className="page-section"><div className="section-heading"><span>本地风险时间线</span><h1>风险事件</h1><p>由实时阈值、Agent 识别和连接行为共同生成。</p></div><section className="panel all-events"><div className="event-list">{snapshot.events.map((event) => <EventItem key={event.id} event={event} />)}{!snapshot.events.length && <div className="all-clear"><ShieldCheck size={30} /><strong>没有风险事件</strong><span>当前所有进程均低于设置的阈值</span></div>}</div></section></div>}
          {activePage === "rules" && <div className="page-section"><div className="section-heading"><span>个性化策略</span><h1>监控规则</h1><p>阈值规则默认只提醒；进程封禁仅在你手动确认后生效。</p></div><section className="panel rules-hero"><div className="rule-icon"><Sparkles size={25} /></div><div><span>当前规则</span><h2>单进程超过 {snapshot.settings.threshold_mb_per_minute} MB / 分钟时提醒</h2><p>覆盖所有应用，重点标记 AI Agent 及其子进程。代理与 VPN 流量不会被重复统计。</p></div><button className="primary" onClick={() => setSettingsOpen(true)}>编辑规则</button></section></div>}
        </div>
      </main>
      {settingsOpen && <SettingsDrawer settings={snapshot.settings} onClose={() => setSettingsOpen(false)} onSave={saveSettings} />}
      {liveSelectedProcess && <ProcessDrawer process={liveSelectedProcess} nativeMode={nativeMode} connectionScope={connectionScope} onConnectionScopeChange={setConnectionScope} onClose={() => setSelectedProcess(null)} />}
      {networkPrompt && <div className="confirm-layer" onMouseDown={() => !networkActionId && setNetworkPrompt(null)}><section className="network-confirm" role="dialog" aria-modal="true" aria-labelledby="network-confirm-title" onMouseDown={(event) => event.stopPropagation()}><div className={`confirm-icon ${networkPrompt.is_network_blocked ? "restore" : "danger"}`}>{networkPrompt.is_network_blocked ? <Wifi size={23} /> : <WifiOff size={23} />}</div><h2 id="network-confirm-title">{networkPrompt.is_network_blocked ? "确认恢复联网" : "确认禁止联网"}</h2><p>{networkPrompt.is_network_blocked ? <>将删除 <strong>{networkPrompt.root_application || networkPrompt.name}</strong> 的系统网络封禁规则。</> : <>将阻止 <strong>{networkPrompt.root_application || networkPrompt.name}</strong> 的网络连接。规则按可执行文件路径保存，应用或系统重启后仍会保持，直至你在此手动解禁。</>}</p><code>{networkPrompt.executable}</code>{!networkPrompt.is_network_blocked && <div className="confirm-warning"><ShieldAlert size={16} /><span>系统将弹出管理员授权窗口；拒绝授权不会更改任何规则。{snapshot.platform === "macos" ? " macOS 系统应用防火墙由系统能力决定可拦截的连接方向。" : ""}</span></div>}<div className="confirm-actions"><button className="secondary" disabled={!!networkActionId} onClick={() => setNetworkPrompt(null)}>取消</button><button className={networkPrompt.is_network_blocked ? "restore-button" : "danger-button"} disabled={!!networkActionId} onClick={applyNetworkToggle}>{networkActionId ? <LoaderCircle size={14} className="spin" /> : networkPrompt.is_network_blocked ? <Wifi size={14} /> : <WifiOff size={14} />}{networkActionId ? "正在应用系统规则" : networkPrompt.is_network_blocked ? "确认解禁" : "确认禁止"}</button></div></section></div>}
      {copyNotice && <div className={`copy-toast ${copyNotice.tone}`} role="status" aria-live="polite">{copyNotice.tone === "success" ? <Check size={16} /> : <Info size={16} />}<span>{copyNotice.message}</span></div>}
    </div>
  );
}
