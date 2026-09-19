import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Activity, CalendarDays, Clock3, Database, Globe2, LoaderCircle, RefreshCw } from "lucide-react";
import type { ProcessFlow } from "./types";
import { getProgramId, type DailyUploadStatsResponse, type UploadPointStat, type UploadPointsResponse } from "./uploadStats";

type StatsSubTab = "daily" | "points";

function formatBytes(value: number) {
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(2)} GB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(2)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${value.toFixed(0)} B`;
}

function formatPointTime(timestamp: number) {
  return new Date(timestamp * 1000).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" });
}

function formatDateLabel(value: string) {
  const date = new Date(`${value}T00:00:00`);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit", weekday: "short" });
}

function StatsMetric({ icon: Icon, label, value }: { icon: typeof Database; label: string; value: string }) {
  return <div className="stats-metric"><Icon size={15} /><span>{label}</span><strong>{value}</strong></div>;
}

function HourBars({ points }: { points: UploadPointStat[] }) {
  const hours = useMemo(() => Array.from({ length: 24 }, (_, hour) => points.filter((point) => point.stat_hour === hour).reduce((total, point) => total + point.bytes, 0)), [points]);
  const maximum = Math.max(...hours, 1);
  return <div className="upload-hour-bars" aria-label="按小时上传量"><div className="upload-hour-bars-inner">{hours.map((bytes, hour) => <div className="upload-hour-bar" key={hour} title={`${hour}:00 · ${formatBytes(bytes)}`}><i style={{ height: `${bytes ? Math.max(5, bytes / maximum * 100) : 0}%` }} /><span>{hour % 3 === 0 ? hour : ""}</span></div>)}</div></div>;
}

export default function UploadStatsTab({ process, nativeMode }: { process: ProcessFlow; nativeMode: boolean }) {
  const [subTab, setSubTab] = useState<StatsSubTab>("daily");
  const [daily, setDaily] = useState<DailyUploadStatsResponse | null>(null);
  const [points, setPoints] = useState<UploadPointsResponse | null>(null);
  const [selectedDate, setSelectedDate] = useState("");
  const [selectedHour, setSelectedHour] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const programId = getProgramId(process);

  async function loadDaily() {
    if (!nativeMode) return;
    setLoading(true);
    setError("");
    try {
      const result = await invoke<DailyUploadStatsResponse>("get_daily_upload_stats", { programId });
      setDaily(result);
      setSelectedDate((current) => current || result.days[0]?.stat_date || "");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setLoading(false);
    }
  }

  async function loadPoints(date: string, hour: number | null = selectedHour) {
    if (!nativeMode || !date) return;
    setLoading(true);
    setError("");
    try {
      const result = await invoke<UploadPointsResponse>("get_upload_stats_points", { programId, date, hour });
      setPoints(result);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    setDaily(null);
    setPoints(null);
    setSelectedDate("");
    setSelectedHour(null);
    void loadDaily();
  }, [programId, nativeMode]);

  function selectDate(date: string) {
    setSelectedDate(date);
    setSelectedHour(null);
    setSubTab("points");
    void loadPoints(date, null);
  }

  function selectHour(hour: number | null) {
    setSelectedHour(hour);
    if (selectedDate) void loadPoints(selectedDate, hour);
  }

  if (!nativeMode) {
    return <div className="upload-stats-empty"><Database size={27} /><strong>桌面端启动后记录上传统计</strong><span>浏览器预览不会写入本机统计数据库；Tauri 模式会保留近 180 天的轻量汇总。</span></div>;
  }

  return <div className="upload-stats-view">
    <div className="stats-retention-note"><CalendarDays size={14} /><span>仅保留近 180 天的统计数据，不保存上传内容</span><button type="button" onClick={() => void (subTab === "daily" ? loadDaily() : loadPoints(selectedDate, selectedHour))} aria-label="刷新上传统计"><RefreshCw size={13} /></button></div>
    <div className="stats-subtabs"><button className={subTab === "daily" ? "active" : ""} onClick={() => setSubTab("daily")}><CalendarDays size={14} />按天汇总</button><button className={subTab === "points" ? "active" : ""} disabled={!selectedDate} onClick={() => { setSubTab("points"); if (selectedDate && !points) void loadPoints(selectedDate, selectedHour); }}><Clock3 size={14} />时间点 / IP</button></div>
    {loading && <div className="stats-loading"><LoaderCircle size={15} className="spin" />正在读取统计…</div>}
    {error && <div className="stats-error">统计读取失败：{error}</div>}
    {subTab === "daily" && <section className="upload-stats-section">
      <div className="stats-summary-grid"><StatsMetric icon={CalendarDays} label="有数据的天数" value={`${daily?.days.length ?? 0} 天`} /><StatsMetric icon={Database} label="半年累计上传" value={formatBytes(daily?.days.reduce((total, day) => total + day.total_bytes, 0) ?? 0)} /><StatsMetric icon={Activity} label="上传批次" value={`${daily?.days.reduce((total, day) => total + day.upload_count, 0) ?? 0}`} /></div>
      {daily?.days.length ? <div className="daily-stats-list">{daily.days.map((day) => <button type="button" className={`daily-stat-row ${selectedDate === day.stat_date ? "selected" : ""}`} key={day.stat_date} onClick={() => selectDate(day.stat_date)}><span className="daily-stat-date">{formatDateLabel(day.stat_date)}<small>{day.stat_date}</small></span><span className="daily-stat-bytes">{formatBytes(day.total_bytes)}<small>{day.upload_count} 次上传 · {day.ip_count} 个 IP</small></span><span className="daily-stat-action">查看时间点 <Activity size={14} /></span></button>)}</div> : !loading && <div className="upload-stats-empty compact"><CalendarDays size={22} /><strong>还没有可展示的上传统计</strong><span>统计会在进程产生新的上传字节后按 30 分钟时间桶写入。</span></div>}
    </section>}
    {subTab === "points" && <section className="upload-stats-section">
      <div className="stats-detail-head"><div><span>统计日期</span><strong>{selectedDate || "—"}</strong></div><label className="hour-filter"><span>小时</span><select value={selectedHour ?? ""} onChange={(event) => selectHour(event.target.value === "" ? null : Number(event.target.value))}><option value="">全天</option>{Array.from({ length: 24 }, (_, hour) => <option value={hour} key={hour}>{hour.toString().padStart(2, "0")}:00–{hour.toString().padStart(2, "0")}:59</option>)}</select></label></div>
      <div className="stats-summary-grid"><StatsMetric icon={Database} label="上传数据量" value={formatBytes(points?.summary.total_bytes ?? 0)} /><StatsMetric icon={Activity} label="上传次数" value={`${points?.summary.upload_count ?? 0}`} /><StatsMetric icon={Globe2} label="来源 IP" value={`${points?.summary.ip_count ?? 0}`} /></div>
      <HourBars points={points?.points ?? []} />
      {points?.points.length ? <div className="upload-points-list">{points.points.map((point) => <div className="upload-point-row" key={`${point.bucket_start}-${point.upload_ip}`}><span><Clock3 size={14} />{formatPointTime(point.bucket_start)}<small>{point.stat_hour.toString().padStart(2, "0")} 时段</small></span><code>{point.upload_ip}</code><strong>{formatBytes(point.bytes)}</strong><small>{point.upload_count} 次</small></div>)}</div> : !loading && <div className="upload-stats-empty compact"><Clock3 size={22} /><strong>该日期没有细化时间点</strong><span>上传会按半小时和来源地址聚合，避免明细数据膨胀。</span></div>}
    </section>}
  </div>;
}
