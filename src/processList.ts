import type { ProcessFlow } from "./types";

export type ProcessScope = "running" | "history";
export type ConnectionScope = "active" | "history";
export type ProcessSortKey = "upload" | "status" | "connections";
export type SortDirection = "asc" | "desc";

export interface ProcessSortState {
  key: ProcessSortKey;
  direction: SortDirection;
  orderedIds: string[];
}

export interface VirtualRange {
  start: number;
  end: number;
  topOffset: number;
  bottomOffset: number;
}

export const PROCESS_ROW_HEIGHT = 59;
export const PROCESS_VIEWPORT_HEIGHT = 540;
export const PROCESS_OVERSCAN = 6;
export const PROCESS_VIRTUALIZATION_THRESHOLD = 32;

/**
 * Search text is deliberately built once per snapshot instead of once per keypress.
 * Connection history can be large, so this also avoids allocating a mapped array for
 * every process on every input event.
 */
export function getProcessSearchText(process: ProcessFlow): string {
  let text = `${process.name} ${process.root_application} ${process.pid} ${process.executable}`;
  for (const connection of process.connection_history) {
    text += ` ${connection.remote_endpoint}`;
  }
  return text.toLowerCase();
}

export function buildProcessSearchIndex(processes: ProcessFlow[]): Map<string, string> {
  const index = new Map<string, string>();
  for (const process of processes) {
    index.set(process.process_instance_id, getProcessSearchText(process));
  }
  return index;
}

export function filterProcesses(
  processes: ProcessFlow[],
  processScope: ProcessScope,
  query: string,
  searchIndex?: ReadonlyMap<string, string>
): ProcessFlow[] {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery && processScope === "history") return processes;

  const filtered: ProcessFlow[] = [];
  for (const process of processes) {
    if (processScope === "running" && !process.is_running) continue;
    if (normalizedQuery) {
      const searchText = searchIndex?.get(process.process_instance_id) ?? getProcessSearchText(process);
      if (!searchText.includes(normalizedQuery)) continue;
    }
    filtered.push(process);
  }
  return filtered;
}

export function getConnectionCount(process: ProcessFlow, scope: ConnectionScope): number {
  return scope === "active" ? process.active_connection_count : process.total_connection_count;
}

export function getLatestConnection(process: ProcessFlow, scope: ConnectionScope) {
  if (scope === "history") return process.connection_history[0];
  for (const connection of process.connection_history) {
    if (connection.is_alive) return connection;
  }
  return undefined;
}

export function getMaxRunningUpload(processes: ProcessFlow[]): number {
  let maximum = 1;
  for (const process of processes) {
    if (process.is_running && process.upload_bps > maximum) maximum = process.upload_bps;
  }
  return maximum;
}

export function sortProcessIds(
  processes: ProcessFlow[],
  key: ProcessSortKey,
  direction: SortDirection,
  connectionScope: ConnectionScope
): string[] {
  const multiplier = direction === "asc" ? 1 : -1;
  return [...processes]
    .sort((left, right) => {
      let result = 0;
      if (key === "upload") result = left.upload_total - right.upload_total;
      if (key === "status") result = Number(left.is_running) - Number(right.is_running);
      if (key === "connections") result = getConnectionCount(left, connectionScope) - getConnectionCount(right, connectionScope);
      return result * multiplier || left.process_instance_id.localeCompare(right.process_instance_id);
    })
    .map((process) => process.process_instance_id);
}

export function applyProcessOrder(processes: ProcessFlow[], sortState: ProcessSortState | null): ProcessFlow[] {
  if (!sortState) return processes;
  const orderById = new Map<string, number>();
  sortState.orderedIds.forEach((id, index) => orderById.set(id, index));
  return [...processes].sort((left, right) => {
    const leftIndex = orderById.get(left.process_instance_id);
    const rightIndex = orderById.get(right.process_instance_id);
    if (leftIndex !== undefined && rightIndex !== undefined) return leftIndex - rightIndex;
    if (leftIndex !== undefined) return -1;
    if (rightIndex !== undefined) return 1;
    return left.process_instance_id.localeCompare(right.process_instance_id);
  });
}

export function getVirtualRange(
  count: number,
  scrollTop: number,
  viewportHeight = PROCESS_VIEWPORT_HEIGHT,
  rowHeight = PROCESS_ROW_HEIGHT,
  overscan = PROCESS_OVERSCAN
): VirtualRange {
  if (count <= 0) return { start: 0, end: 0, topOffset: 0, bottomOffset: 0 };
  const safeRowHeight = Math.max(1, rowHeight);
  const safeViewportHeight = Math.max(0, viewportHeight);
  const maxScrollTop = Math.max(0, count * safeRowHeight - safeViewportHeight);
  const safeScrollTop = Math.min(maxScrollTop, Math.max(0, scrollTop));
  const firstVisible = Math.floor(safeScrollTop / safeRowHeight);
  const start = Math.max(0, firstVisible - Math.max(0, overscan));
  const end = Math.min(count, Math.ceil((safeScrollTop + safeViewportHeight) / safeRowHeight) + Math.max(0, overscan));
  return {
    start,
    end: Math.max(start, end),
    topOffset: start * safeRowHeight,
    bottomOffset: Math.max(0, (count - end) * safeRowHeight)
  };
}
