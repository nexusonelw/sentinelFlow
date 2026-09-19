import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import type { TimelinePoint } from "./types";

interface RiskCount {
  name: string;
  value: number;
  color: string;
}

interface DashboardChartsProps {
  timeline: TimelinePoint[];
  riskCounts: RiskCount[];
  runningProcessCount: number;
  uploadBps: number;
  downloadBps: number;
  thresholdMbPerMinute: number;
}

function formatRate(value: number) {
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(1)} MB/s`;
  if (value >= 1024) return `${(value / 1024).toFixed(0)} KB/s`;
  return `${value.toFixed(0)} B/s`;
}

export default function DashboardCharts({ timeline, riskCounts, runningProcessCount, uploadBps, downloadBps, thresholdMbPerMinute }: DashboardChartsProps) {
  return (
    <div className="dashboard-grid">
      <section className="panel traffic-panel">
        <div className="panel-head"><div><h2>实时网络流量</h2><p>最近 {timeline.length ? Math.max(1, Math.round(timeline.length * 6 / 60)) : 0} 分钟 · 每个进程的真实归属</p></div><div className="chart-legend"><span><i className="upload" />上传</span><span><i className="download" />下载</span></div></div>
        <div className="chart-wrap">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeline} margin={{ top: 8, right: 4, left: -16, bottom: 0 }}>
              <defs><linearGradient id="uploadGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#ef6b5b" stopOpacity={0.28} /><stop offset="100%" stopColor="#ef6b5b" stopOpacity={0} /></linearGradient><linearGradient id="downloadGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#635bff" stopOpacity={0.18} /><stop offset="100%" stopColor="#635bff" stopOpacity={0} /></linearGradient></defs>
              <CartesianGrid stroke="#e9ece9" strokeDasharray="3 5" vertical={false} />
              <XAxis dataKey="label" axisLine={false} tickLine={false} tick={{ fill: "#939a94", fontSize: 11 }} interval="preserveStartEnd" minTickGap={40} />
              <YAxis axisLine={false} tickLine={false} tick={{ fill: "#939a94", fontSize: 11 }} tickFormatter={(value) => value >= 1024 ** 2 ? `${(value / 1024 ** 2).toFixed(0)}M` : `${(value / 1024).toFixed(0)}K`} />
              <Tooltip contentStyle={{ borderRadius: 14, border: "1px solid #e2e6e2", boxShadow: "0 12px 35px rgba(31,39,34,.12)", fontSize: 12 }} formatter={(value) => [formatRate(Number(value ?? 0))]} />
              <Area type="monotone" dataKey="download_bps" name="下载" stroke="#635bff" strokeWidth={2} fill="url(#downloadGradient)" />
              <Area type="monotone" dataKey="upload_bps" name="上传" stroke="#ef6b5b" strokeWidth={2.5} fill="url(#uploadGradient)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div className="traffic-foot"><div><span>↑ 上传</span><strong>{formatRate(uploadBps)}</strong></div><div><span>↓ 下载</span><strong>{formatRate(downloadBps)}</strong></div><div><span>阈值</span><strong>{thresholdMbPerMinute} MB/min</strong></div></div>
      </section>
      <section className="panel risk-panel">
        <div className="panel-head"><div><h2>风险分布</h2><p>当前活跃进程</p></div><button className="more-button">•••</button></div>
        <div className="risk-chart">
          <ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={riskCounts} innerRadius={55} outerRadius={75} paddingAngle={4} dataKey="value" stroke="none">{riskCounts.map((entry) => <Cell key={entry.name} fill={entry.color} />)}</Pie></PieChart></ResponsiveContainer>
          <div className="risk-center"><strong>{runningProcessCount}</strong><span>进程</span></div>
        </div>
        <div className="risk-legend">{riskCounts.map((item) => <div key={item.name}><span><i style={{ background: item.color }} />{item.name}</span><strong>{item.value}</strong></div>)}</div>
      </section>
    </div>
  );
}

export type { RiskCount };
