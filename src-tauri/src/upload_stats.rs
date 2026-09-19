use crate::models::{MonitorSnapshot, ProcessFlow};
use chrono::{Duration as ChronoDuration, Local, TimeZone, Timelike};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};

const RETENTION_DAYS: i64 = 180;
const BUCKET_SECONDS: u64 = 30 * 60;
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60 * 60);
const MAX_PENDING_POINTS: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyUploadStat {
    pub stat_date: String,
    pub total_bytes: u64,
    pub upload_count: u64,
    pub ip_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadPointStat {
    pub bucket_start: u64,
    pub stat_hour: u8,
    pub upload_ip: String,
    pub bytes: u64,
    pub upload_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadStatsSummary {
    pub total_bytes: u64,
    pub upload_count: u64,
    pub ip_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyUploadStatsResponse {
    pub program_id: String,
    pub days: Vec<DailyUploadStat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadPointsResponse {
    pub program_id: String,
    pub date: String,
    pub hour: Option<u8>,
    pub summary: UploadStatsSummary,
    pub points: Vec<UploadPointStat>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct PointKey {
    program_id: String,
    stat_date: String,
    stat_hour: u8,
    bucket_start: u64,
    upload_ip: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct DailyKey {
    program_id: String,
    stat_date: String,
}

#[derive(Debug, Clone)]
struct PendingDelta {
    bytes: u64,
    upload_count: u64,
}

pub struct UploadStatsStore {
    connection: Connection,
    pending_daily: HashMap<DailyKey, PendingDelta>,
    pending_points: HashMap<PointKey, PendingDelta>,
    pending_ips: HashSet<DailyKeyWithIp>,
    previous_totals: HashMap<String, u64>,
    last_flush: Instant,
    last_cleanup: Instant,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct DailyKeyWithIp {
    program_id: String,
    stat_date: String,
    upload_ip: String,
}

impl UploadStatsStore {
    pub fn open(path: &Path) -> Result<Self, String> {
        let connection = Connection::open(path).map_err(|error| error.to_string())?;
        let mut store = Self::from_connection(connection)?;
        store.cleanup_expired()?;
        Ok(store)
    }

    #[cfg(test)]
    fn in_memory() -> Result<Self, String> {
        Self::from_connection(Connection::open_in_memory().map_err(|error| error.to_string())?)
    }

    fn from_connection(connection: Connection) -> Result<Self, String> {
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| error.to_string())?;
        connection
            .pragma_update(None, "synchronous", "NORMAL")
            .map_err(|error| error.to_string())?;
        connection
            .pragma_update(None, "busy_timeout", 5_000_i64)
            .map_err(|error| error.to_string())?;
        connection
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS program_daily_upload_stats (
                    program_id TEXT NOT NULL,
                    stat_date TEXT NOT NULL,
                    total_bytes INTEGER NOT NULL DEFAULT 0,
                    upload_count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (program_id, stat_date)
                );
                CREATE TABLE IF NOT EXISTS program_upload_points (
                    program_id TEXT NOT NULL,
                    stat_date TEXT NOT NULL,
                    stat_hour INTEGER NOT NULL,
                    bucket_start INTEGER NOT NULL,
                    upload_ip TEXT NOT NULL,
                    bytes INTEGER NOT NULL DEFAULT 0,
                    upload_count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (program_id, bucket_start, upload_ip)
                );
                CREATE INDEX IF NOT EXISTS idx_upload_points_program_date
                    ON program_upload_points (program_id, stat_date, bucket_start);
                CREATE INDEX IF NOT EXISTS idx_upload_points_retention
                    ON program_upload_points (stat_date);
                CREATE TABLE IF NOT EXISTS program_upload_ips (
                    program_id TEXT NOT NULL,
                    stat_date TEXT NOT NULL,
                    upload_ip TEXT NOT NULL,
                    PRIMARY KEY (program_id, stat_date, upload_ip)
                );
                CREATE INDEX IF NOT EXISTS idx_upload_ips_retention
                    ON program_upload_ips (stat_date);
                ",
            )
            .map_err(|error| error.to_string())?;
        Ok(Self {
            connection,
            pending_daily: HashMap::new(),
            pending_points: HashMap::new(),
            pending_ips: HashSet::new(),
            previous_totals: HashMap::new(),
            last_flush: Instant::now(),
            last_cleanup: Instant::now(),
        })
    }

    pub fn record_snapshot(&mut self, snapshot: &MonitorSnapshot) -> Result<(), String> {
        let mut seen_processes = HashSet::new();
        for process in &snapshot.processes {
            if !process.is_running {
                continue;
            }
            seen_processes.insert(process.process_instance_id.clone());
            let previous = self
                .previous_totals
                .insert(process.process_instance_id.clone(), process.upload_total)
                .unwrap_or(process.upload_total);
            let delta = process.upload_total.saturating_sub(previous);
            if delta == 0 {
                continue;
            }
            let program_id = process_program_id(process);
            let upload_ip = process_upload_ip(process);
            let (stat_date, stat_hour, bucket_start) = local_bucket(snapshot.collected_at);
            let daily_key = DailyKey {
                program_id: program_id.clone(),
                stat_date: stat_date.clone(),
            };
            add_delta(
                self.pending_daily.entry(daily_key).or_insert(PendingDelta {
                    bytes: 0,
                    upload_count: 0,
                }),
                delta,
            );
            self.pending_ips.insert(DailyKeyWithIp {
                program_id: program_id.clone(),
                stat_date: stat_date.clone(),
                upload_ip: upload_ip.clone(),
            });
            let point_key = PointKey {
                program_id,
                stat_date,
                stat_hour,
                bucket_start,
                upload_ip,
            };
            add_delta(
                self.pending_points
                    .entry(point_key)
                    .or_insert(PendingDelta {
                        bytes: 0,
                        upload_count: 0,
                    }),
                delta,
            );
        }
        self.previous_totals
            .retain(|process_id, _| seen_processes.contains(process_id));

        if self.pending_points.len() >= MAX_PENDING_POINTS
            || self.last_flush.elapsed() >= FLUSH_INTERVAL
        {
            self.flush()?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), String> {
        if self.pending_daily.is_empty() && self.pending_points.is_empty() {
            self.last_flush = Instant::now();
            return Ok(());
        }
        let pending_daily = std::mem::take(&mut self.pending_daily);
        let pending_points = std::mem::take(&mut self.pending_points);
        let pending_ips = std::mem::take(&mut self.pending_ips);
        let should_cleanup = self.last_cleanup.elapsed() >= CLEANUP_INTERVAL;
        let result = (|| {
            let transaction = self
                .connection
                .transaction()
                .map_err(|error| error.to_string())?;
            for (key, delta) in &pending_daily {
                transaction
                    .execute(
                        "INSERT INTO program_daily_upload_stats (program_id, stat_date, total_bytes, upload_count)
                         VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(program_id, stat_date) DO UPDATE SET
                           total_bytes = total_bytes + excluded.total_bytes,
                           upload_count = upload_count + excluded.upload_count",
                        params![key.program_id, key.stat_date, delta.bytes as i64, delta.upload_count as i64],
                    )
                    .map_err(|error| error.to_string())?;
            }
            for key in &pending_ips {
                transaction
                    .execute(
                        "INSERT OR IGNORE INTO program_upload_ips (program_id, stat_date, upload_ip) VALUES (?1, ?2, ?3)",
                        params![key.program_id, key.stat_date, key.upload_ip],
                    )
                    .map_err(|error| error.to_string())?;
            }
            for (key, delta) in &pending_points {
                transaction
                    .execute(
                        "INSERT INTO program_upload_points (program_id, stat_date, stat_hour, bucket_start, upload_ip, bytes, upload_count)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                         ON CONFLICT(program_id, bucket_start, upload_ip) DO UPDATE SET
                           bytes = bytes + excluded.bytes,
                           upload_count = upload_count + excluded.upload_count,
                           stat_date = excluded.stat_date,
                           stat_hour = excluded.stat_hour",
                        params![key.program_id, key.stat_date, key.stat_hour, key.bucket_start as i64, key.upload_ip, delta.bytes as i64, delta.upload_count as i64],
                    )
                    .map_err(|error| error.to_string())?;
            }
            if should_cleanup {
                let cutoff = cutoff_date();
                transaction
                    .execute(
                        "DELETE FROM program_upload_points WHERE stat_date < ?1",
                        params![cutoff],
                    )
                    .map_err(|error| error.to_string())?;
                transaction
                    .execute(
                        "DELETE FROM program_upload_ips WHERE stat_date < ?1",
                        params![cutoff],
                    )
                    .map_err(|error| error.to_string())?;
                transaction
                    .execute(
                        "DELETE FROM program_daily_upload_stats WHERE stat_date < ?1",
                        params![cutoff],
                    )
                    .map_err(|error| error.to_string())?;
            }
            transaction.commit().map_err(|error| error.to_string())
        })();
        if let Err(error) = result {
            merge_pending(&mut self.pending_daily, pending_daily);
            merge_pending(&mut self.pending_points, pending_points);
            self.pending_ips.extend(pending_ips);
            return Err(error);
        }
        self.last_flush = Instant::now();
        if should_cleanup {
            self.last_cleanup = Instant::now();
        }
        Ok(())
    }

    pub fn daily(
        &mut self,
        program_id: &str,
        start_date: Option<&str>,
        end_date: Option<&str>,
    ) -> Result<DailyUploadStatsResponse, String> {
        self.flush()?;
        let today = Local::now().format("%Y-%m-%d").to_string();
        let cutoff = cutoff_date();
        let start = start_date.unwrap_or(&cutoff).max(&cutoff).to_string();
        let end = end_date.unwrap_or(&today).min(&today).to_string();
        if !valid_date(&start) || !valid_date(&end) || start > end {
            return Err("日期范围无效，统计数据只支持最近 180 天".to_string());
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT d.stat_date, d.total_bytes, d.upload_count,
                    COALESCE((SELECT COUNT(*) FROM program_upload_ips i
                        WHERE i.program_id = d.program_id AND i.stat_date = d.stat_date), 0)
                 FROM program_daily_upload_stats d
                 WHERE d.program_id = ?1 AND d.stat_date BETWEEN ?2 AND ?3
                 ORDER BY d.stat_date DESC LIMIT 180",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![program_id, start, end], |row| {
                Ok(DailyUploadStat {
                    stat_date: row.get(0)?,
                    total_bytes: row.get::<_, i64>(1)?.max(0) as u64,
                    upload_count: row.get::<_, i64>(2)?.max(0) as u64,
                    ip_count: row.get::<_, i64>(3)?.max(0) as u64,
                })
            })
            .map_err(|error| error.to_string())?;
        let days = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        Ok(DailyUploadStatsResponse {
            program_id: program_id.to_string(),
            days,
        })
    }

    pub fn points(
        &mut self,
        program_id: &str,
        date: &str,
        hour: Option<u8>,
    ) -> Result<UploadPointsResponse, String> {
        self.flush()?;
        let today = Local::now().format("%Y-%m-%d").to_string();
        if !valid_date(date) || date < cutoff_date().as_str() || date > today.as_str() {
            return Err("日期无效或不在最近 180 天范围内".to_string());
        }
        if hour.is_some_and(|value| value > 23) {
            return Err("小时必须在 0 到 23 之间".to_string());
        }
        let summary = if let Some(hour) = hour {
            self.connection
                .query_row(
                    "SELECT COALESCE(SUM(bytes), 0), COALESCE(SUM(upload_count), 0), COUNT(DISTINCT upload_ip)
                     FROM program_upload_points WHERE program_id = ?1 AND stat_date = ?2 AND stat_hour = ?3",
                    params![program_id, date, hour],
                    |row| Ok(UploadStatsSummary {
                        total_bytes: row.get::<_, i64>(0)?.max(0) as u64,
                        upload_count: row.get::<_, i64>(1)?.max(0) as u64,
                        ip_count: row.get::<_, i64>(2)?.max(0) as u64,
                    }),
                )
                .map_err(|error| error.to_string())?
        } else {
            self.connection
                .query_row(
                    "SELECT COALESCE(total_bytes, 0), COALESCE(upload_count, 0),
                        COALESCE((SELECT COUNT(*) FROM program_upload_ips i
                          WHERE i.program_id = d.program_id AND i.stat_date = d.stat_date), 0)
                     FROM program_daily_upload_stats d WHERE d.program_id = ?1 AND d.stat_date = ?2",
                    params![program_id, date],
                    |row| Ok(UploadStatsSummary {
                        total_bytes: row.get::<_, i64>(0)?.max(0) as u64,
                        upload_count: row.get::<_, i64>(1)?.max(0) as u64,
                        ip_count: row.get::<_, i64>(2)?.max(0) as u64,
                    }),
                )
                .optional()
                .map_err(|error| error.to_string())?
                .unwrap_or(UploadStatsSummary {
                    total_bytes: 0,
                    upload_count: 0,
                    ip_count: 0,
                })
        };
        let mut sql = String::from(
            "SELECT bucket_start, stat_hour, upload_ip, bytes, upload_count
             FROM program_upload_points WHERE program_id = ?1 AND stat_date = ?2",
        );
        if hour.is_some() {
            sql.push_str(" AND stat_hour = ?3");
        }
        sql.push_str(" ORDER BY bucket_start ASC, upload_ip ASC");
        let mut statement = self
            .connection
            .prepare(&sql)
            .map_err(|error| error.to_string())?;
        let mut rows = if let Some(hour) = hour {
            statement
                .query(params![program_id, date, hour])
                .map_err(|error| error.to_string())?
        } else {
            statement
                .query(params![program_id, date])
                .map_err(|error| error.to_string())?
        };
        let mut points = Vec::new();
        while let Some(row) = rows.next().map_err(|error| error.to_string())? {
            points.push(UploadPointStat {
                bucket_start: row
                    .get::<_, i64>(0)
                    .map_err(|error| error.to_string())?
                    .max(0) as u64,
                stat_hour: row
                    .get::<_, i64>(1)
                    .map_err(|error| error.to_string())?
                    .clamp(0, 23) as u8,
                upload_ip: row.get(2).map_err(|error| error.to_string())?,
                bytes: row
                    .get::<_, i64>(3)
                    .map_err(|error| error.to_string())?
                    .max(0) as u64,
                upload_count: row
                    .get::<_, i64>(4)
                    .map_err(|error| error.to_string())?
                    .max(0) as u64,
            });
        }
        Ok(UploadPointsResponse {
            program_id: program_id.to_string(),
            date: date.to_string(),
            hour,
            summary,
            points,
        })
    }

    fn cleanup_expired(&mut self) -> Result<(), String> {
        let cutoff = cutoff_date();
        self.connection
            .execute(
                "DELETE FROM program_upload_points WHERE stat_date < ?1",
                params![cutoff],
            )
            .map_err(|error| error.to_string())?;
        self.connection
            .execute(
                "DELETE FROM program_upload_ips WHERE stat_date < ?1",
                params![cutoff],
            )
            .map_err(|error| error.to_string())?;
        self.connection
            .execute(
                "DELETE FROM program_daily_upload_stats WHERE stat_date < ?1",
                params![cutoff],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

fn add_delta(target: &mut PendingDelta, bytes: u64) {
    target.bytes = target.bytes.saturating_add(bytes);
    target.upload_count = target.upload_count.saturating_add(1);
}

fn merge_pending<K: std::hash::Hash + Eq>(
    target: &mut HashMap<K, PendingDelta>,
    source: HashMap<K, PendingDelta>,
) {
    for (key, delta) in source {
        let entry = target.entry(key).or_insert(PendingDelta {
            bytes: 0,
            upload_count: 0,
        });
        entry.bytes = entry.bytes.saturating_add(delta.bytes);
        entry.upload_count = entry.upload_count.saturating_add(delta.upload_count);
    }
}

pub fn process_program_id(process: &ProcessFlow) -> String {
    let executable = process.executable.trim();
    if executable.is_empty() {
        process.name.trim().to_string()
    } else {
        executable.to_string()
    }
}

fn process_upload_ip(process: &ProcessFlow) -> String {
    process
        .connection_history
        .iter()
        .find(|connection| connection.is_alive)
        .map(|connection| connection.remote_endpoint.as_str())
        .or_else(|| process.connections.first().map(String::as_str))
        .map(remote_host)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "未知".to_string())
}

fn remote_host(endpoint: &str) -> String {
    let endpoint = endpoint.trim();
    if endpoint.starts_with('[') {
        return endpoint
            .split_once(']')
            .map(|(host, _)| host.trim_start_matches('[').to_string())
            .unwrap_or_else(|| endpoint.to_string());
    }
    if let Some((host, port)) = endpoint.rsplit_once(':') {
        if port.parse::<u16>().is_ok() {
            return host.to_string();
        }
    }
    endpoint.to_string()
}

fn local_bucket(timestamp: u64) -> (String, u8, u64) {
    let bucket_start = timestamp - timestamp % BUCKET_SECONDS;
    let datetime = Local
        .timestamp_opt(bucket_start as i64, 0)
        .single()
        .unwrap_or_else(Local::now);
    (
        datetime.format("%Y-%m-%d").to_string(),
        datetime.hour() as u8,
        bucket_start,
    )
}

fn cutoff_date() -> String {
    (Local::now() - ChronoDuration::days(RETENTION_DAYS))
        .format("%Y-%m-%d")
        .to_string()
}

fn valid_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value.split('-').all(|part| {
            !part.is_empty() && part.chars().all(|character| character.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        MonitorCoverage, MonitorSettings, NetworkConnectionDetail, RiskLevel, TimelinePoint,
    };

    fn snapshot(total: u64, timestamp: u64) -> MonitorSnapshot {
        MonitorSnapshot {
            monitoring: true,
            platform: "test".to_string(),
            hostname: "test".to_string(),
            collected_at: timestamp,
            upload_bps: 1.0,
            download_bps: 0.0,
            total_upload_bytes: total,
            observed_processes: 1,
            active_connections: 1,
            processes: vec![ProcessFlow {
                process_instance_id: "1-1".to_string(),
                pid: 1,
                parent_pid: None,
                name: "uploader".to_string(),
                executable: "/Applications/Uploader.app".to_string(),
                command_line: Vec::new(),
                current_working_directory: "/tmp".to_string(),
                launch_target: None,
                root_application: "Uploader".to_string(),
                upload_bps: 1.0,
                download_bps: 0.0,
                upload_total: total,
                download_total: 0,
                cpu_percent: 0.0,
                memory_bytes: 0,
                connections: vec!["203.0.113.8:443".to_string()],
                risk_score: 0,
                risk_level: RiskLevel::Low,
                is_agent: false,
                is_proxy: false,
                is_running: true,
                started_at: timestamp,
                ended_at: None,
                last_activity_at: timestamp,
                active_connection_count: 1,
                total_connection_count: 1,
                connection_history: vec![NetworkConnectionDetail {
                    remote_endpoint: "203.0.113.8:443".to_string(),
                    is_alive: true,
                    ..NetworkConnectionDetail::default()
                }],
                is_network_blocked: false,
            }],
            timeline: vec![TimelinePoint {
                timestamp,
                label: "test".to_string(),
                upload_bps: 1.0,
                download_bps: 0.0,
            }],
            events: Vec::new(),
            settings: MonitorSettings::default(),
            coverage: MonitorCoverage {
                network: "active".to_string(),
                process: "active".to_string(),
                file: "limited".to_string(),
                collector: "test".to_string(),
                note: "test".to_string(),
            },
        }
    }

    #[test]
    fn aggregates_only_counter_deltas_and_deduplicates_ip_rows() {
        let mut store = UploadStatsStore::in_memory().expect("store");
        let now = Local::now().timestamp() as u64;
        store
            .record_snapshot(&snapshot(100, now - 100))
            .expect("first");
        store.record_snapshot(&snapshot(250, now)).expect("second");
        store.flush().expect("flush");
        let daily = store
            .daily("/Applications/Uploader.app", None, None)
            .expect("daily");
        assert_eq!(daily.days[0].total_bytes, 150);
        assert_eq!(daily.days[0].upload_count, 1);
        assert_eq!(daily.days[0].ip_count, 1);
        let points = store
            .points("/Applications/Uploader.app", &daily.days[0].stat_date, None)
            .expect("points");
        assert_eq!(points.points.len(), 1);
        assert_eq!(points.points[0].upload_ip, "203.0.113.8");
        let hour_points = store
            .points(
                "/Applications/Uploader.app",
                &daily.days[0].stat_date,
                Some(points.points[0].stat_hour),
            )
            .expect("hour points");
        assert_eq!(hour_points.summary.total_bytes, 150);
    }

    #[test]
    fn stores_multiple_ips_at_the_same_time_bucket_without_payloads() {
        assert_eq!(remote_host("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(remote_host("198.51.100.2:8443"), "198.51.100.2");
        assert_eq!(remote_host("unknown"), "unknown");
    }

    #[test]
    fn rejects_invalid_or_out_of_range_dates() {
        let mut store = UploadStatsStore::in_memory().expect("store");
        assert!(store.points("x", "bad", None).is_err());
        assert!(store
            .daily("x", Some("2020-01-01"), Some("2020-01-02"))
            .is_err());
    }

    #[test]
    fn retention_cleanup_removes_old_rows() {
        let mut store = UploadStatsStore::in_memory().expect("store");
        store
            .connection
            .execute(
                "INSERT INTO program_daily_upload_stats (program_id, stat_date, total_bytes, upload_count) VALUES ('x', '2020-01-01', 1, 1)",
                [],
            )
            .expect("insert old daily");
        store
            .connection
            .execute(
                "INSERT INTO program_upload_points (program_id, stat_date, stat_hour, bucket_start, upload_ip, bytes, upload_count) VALUES ('x', '2020-01-01', 1, 1, '1.1.1.1', 1, 1)",
                [],
            )
            .expect("insert old point");
        store.cleanup_expired().expect("cleanup");
        let count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM program_daily_upload_stats WHERE program_id = 'x'",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(count, 0);
    }
}
