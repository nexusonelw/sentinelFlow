import { describe, expect, it } from "vitest";
import {
  PROCESS_ROW_HEIGHT,
  applyProcessOrder,
  buildProcessSearchIndex,
  filterProcesses,
  getLatestConnection,
  getMaxRunningUpload,
  getVirtualRange,
  sortProcessIds
} from "../src/processList";
import type { ProcessFlow } from "../src/types";

function process(id: string, index: number, overrides: Partial<ProcessFlow> = {}): ProcessFlow {
  return {
    process_instance_id: id,
    pid: index,
    name: `process-${index}`,
    executable: `/Applications/process-${index}.app`,
    command_line: [],
    current_working_directory: "/tmp",
    root_application: index % 2 ? "Browser" : "Agent",
    upload_bps: index * 10,
    download_bps: 0,
    upload_total: index * 100,
    download_total: 0,
    cpu_percent: 0,
    memory_bytes: 0,
    connections: [],
    risk_score: 0,
    risk_level: "low",
    is_agent: index % 2 === 0,
    is_proxy: false,
    is_running: index !== 3,
    started_at: 1,
    last_activity_at: 1,
    active_connection_count: index % 3,
    total_connection_count: index % 4,
    connection_history: index === 2 ? [
      { protocol: "TCP", local_endpoint: "a", remote_endpoint: "active.example:443", state: "ESTABLISHED", first_seen_at: 1, last_seen_at: 2, is_alive: true, is_transient: false },
      { protocol: "TCP", local_endpoint: "b", remote_endpoint: "old.example:443", state: "CLOSED", first_seen_at: 1, last_seen_at: 1, closed_at: 2, is_alive: false, is_transient: true }
    ] : [],
    is_network_blocked: false,
    ...overrides
  };
}

describe("process list indexing and filtering", () => {
  it("indexes names, roots, pids, executables, and remote endpoints", () => {
    const item = process("a", 2);
    const index = buildProcessSearchIndex([item]);
    expect(index.get("a")).toContain("active.example:443");
    expect(index.get("a")).toContain("agent");
  });

  it("filters running scope without mutating the source array", () => {
    const items = [process("a", 1), process("b", 3)];
    const result = filterProcesses(items, "running", "");
    expect(result.map((item) => item.process_instance_id)).toEqual(["a"]);
    expect(items).toHaveLength(2);
  });

  it("returns the complete history for an empty history query", () => {
    const items = [process("a", 1), process("b", 3)];
    expect(filterProcesses(items, "history", "")).toBe(items);
  });

  it("matches a query against connection endpoints", () => {
    const items = [process("a", 2), process("b", 1)];
    const index = buildProcessSearchIndex(items);
    expect(filterProcesses(items, "history", "ACTIVE.EXAMPLE", index).map((item) => item.process_instance_id)).toEqual(["a"]);
  });

  it("does not match an unrelated query", () => {
    expect(filterProcesses([process("a", 1)], "history", "missing")).toEqual([]);
  });

  it("calculates max upload with a floor of one", () => {
    expect(getMaxRunningUpload([process("a", 1, { upload_bps: 0 })])).toBe(1);
    expect(getMaxRunningUpload([process("a", 1, { upload_bps: 70 }), process("b", 2, { upload_bps: 20 })])).toBe(70);
  });

  it("returns the newest active connection without allocating a filtered array", () => {
    const item = process("a", 2);
    expect(getLatestConnection(item, "active")?.remote_endpoint).toBe("active.example:443");
    expect(getLatestConnection(item, "history")?.remote_endpoint).toBe("active.example:443");
    expect(getLatestConnection(process("b", 1), "active")).toBeUndefined();
  });
});

describe("process list sorting", () => {
  it("sorts by upload total in both directions", () => {
    const items = [process("a", 1), process("b", 3), process("c", 2)];
    expect(sortProcessIds(items, "upload", "desc", "active")).toEqual(["b", "c", "a"]);
    expect(sortProcessIds(items, "upload", "asc", "active")).toEqual(["a", "c", "b"]);
  });

  it("sorts status with running processes before historical processes by default", () => {
    const items = [process("a", 3), process("b", 1), process("c", 2)];
    expect(sortProcessIds(items, "status", "desc", "active")).toEqual(["b", "c", "a"]);
  });

  it("uses active or total connection counts according to the selected scope", () => {
    const items = [process("a", 1, { active_connection_count: 1, total_connection_count: 9 }), process("b", 2, { active_connection_count: 2, total_connection_count: 2 })];
    expect(sortProcessIds(items, "connections", "desc", "active")).toEqual(["b", "a"]);
    expect(sortProcessIds(items, "connections", "desc", "history")).toEqual(["a", "b"]);
  });

  it("applies an existing order only to the filtered rows", () => {
    const items = [process("a", 1), process("b", 2), process("c", 3)];
    const ordered = applyProcessOrder(items.slice(0, 2), { key: "upload", direction: "desc", orderedIds: ["b", "c", "a"] });
    expect(ordered.map((item) => item.process_instance_id)).toEqual(["b", "a"]);
  });

  it("does not allocate or reorder when sorting is inactive", () => {
    const items = [process("a", 1), process("b", 2)];
    expect(applyProcessOrder(items, null)).toBe(items);
  });
});

describe("process list virtualization", () => {
  it("starts at zero and renders a small overscanned window", () => {
    const range = getVirtualRange(10_000, 0, 540, PROCESS_ROW_HEIGHT, 6);
    expect(range.start).toBe(0);
    expect(range.end).toBe(16);
    expect(range.topOffset).toBe(0);
    expect(range.bottomOffset).toBe((10_000 - 16) * PROCESS_ROW_HEIGHT);
  });

  it("keeps the window inside the collection while scrolling", () => {
    const range = getVirtualRange(100, 59 * 50, 540, 59, 6);
    expect(range.start).toBe(44);
    expect(range.end).toBe(66);
    expect(range.start).toBeGreaterThanOrEqual(0);
    expect(range.end).toBeLessThanOrEqual(100);
  });

  it("clamps negative scroll offsets and invalid dimensions", () => {
    expect(getVirtualRange(20, -100, -10, 0, -4)).toEqual({ start: 0, end: 0, topOffset: 0, bottomOffset: 20 });
    expect(getVirtualRange(0, 100)).toEqual({ start: 0, end: 0, topOffset: 0, bottomOffset: 0 });
  });

  it("keeps a useful final window at the bottom", () => {
    const range = getVirtualRange(20, 20 * 59, 540, 59, 6);
    expect(range.end).toBe(20);
    expect(range.start).toBe(4);
    expect(range.bottomOffset).toBe(0);
  });
});

describe("large process list performance", () => {
  it("filters ten thousand rows without scanning connection arrays per query", () => {
    const items = Array.from({ length: 10_000 }, (_, index) => process(String(index), index));
    const start = performance.now();
    const index = buildProcessSearchIndex(items);
    const result = filterProcesses(items, "history", "process-9999", index);
    const elapsed = performance.now() - start;
    expect(result).toHaveLength(1);
    expect(elapsed).toBeLessThan(500);
  });

  it("virtualizes ten thousand rows to a bounded DOM-sized window", () => {
    const range = getVirtualRange(10_000, 9_000 * PROCESS_ROW_HEIGHT, 540, PROCESS_ROW_HEIGHT, 6);
    expect(range.end - range.start).toBeLessThanOrEqual(22);
  });
});
