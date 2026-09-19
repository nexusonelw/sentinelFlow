import type { ProcessFlow } from "./types";

export interface DailyUploadStat {
  stat_date: string;
  total_bytes: number;
  upload_count: number;
  ip_count: number;
}

export interface DailyUploadStatsResponse {
  program_id: string;
  days: DailyUploadStat[];
}

export interface UploadPointStat {
  bucket_start: number;
  stat_hour: number;
  upload_ip: string;
  bytes: number;
  upload_count: number;
}

export interface UploadPointsResponse {
  program_id: string;
  date: string;
  hour: number | null;
  summary: {
    total_bytes: number;
    upload_count: number;
    ip_count: number;
  };
  points: UploadPointStat[];
}

export function getProgramId(process: Pick<ProcessFlow, "executable" | "name">): string {
  return process.executable.trim() || process.name.trim();
}
