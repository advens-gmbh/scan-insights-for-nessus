import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

const { useScanStore } = await import("./scanStore");
const { useNotificationStore } = await import("./notificationStore");

// what the backend answers for an opened file
const info = (path: string, hosts = 5) => ({
  id: `id-${path}`, filename: path.split("/").pop(), path, loaded_at: "2026-11-10T00:00:00Z", report_name: "Big", target: null,
  compliance_skipped: 0, size: 1234, host_count: hosts, finding_count: hosts * 3,
  counts: { critical: 0, high: 1, medium: 2, low: 0, info: 12 }, start: null, duration_ms: null, credentialed: 0,
});

// reading progress arrives as events; `broken` paths fail the way the backend reports it
const progress: ((e: { payload: { path: string; percent: number } }) => void)[] = [];
vi.mock("@tauri-apps/api/event", () => ({ listen: async (_: string, handler: (e: { payload: { path: string; percent: number } }) => void) => { progress.push(handler); return () => {}; } }));

function backend({ broken }: { broken?: Record<string, { kind: string; message: string }> } = {}) {
  invoke.mockImplementation(async (cmd: string, args?: { path?: string }) => {
    if (cmd === "load_nessus_file") {
      if (broken?.[args!.path!]) throw broken[args!.path!];
      for (const tell of progress) {
        tell({ payload: { path: args!.path!, percent: 40 } });
      }
      return info(args!.path!);
    }
    return null;
  });
}

describe("scanStore opening files", () => {
  beforeEach(() => {
    invoke.mockReset();
    useScanStore.setState({ files: [], recentFiles: [], loading: false, opening: null, queue: [], batch: { done: 0, total: 0 }, failures: [] });
    useNotificationStore.setState({ notifications: [] });
  });

  it("shows how far the backend has read, and keeps what it found", async () => {
    backend();
    const seen: string[] = [];
    const stop = useScanStore.subscribe((s) => {
      const step = s.opening ? `reading ${s.opening.percent}%` : "idle";
      if (seen[seen.length - 1] !== step) seen.push(step);
    });
    const file = await useScanStore.getState().loadFile("C:/scans/big.nessus");
    stop();

    expect(file).toMatchObject({ host_count: 5, size: 1234 });
    expect(file).not.toHaveProperty("hosts");
    expect(seen).toEqual(["idle", "reading 0%", "reading 40%", "idle"]);
    const s = useScanStore.getState();
    expect(s.files).toHaveLength(1);
    expect(s.loading).toBe(false);
    expect(s.recentFiles[0]).toMatchObject({ path: "C:/scans/big.nessus", report_name: "Big" });
  });

  it("opens files one after another, counting them as one batch", async () => {
    backend();
    const batches: string[] = [];
    const stop = useScanStore.subscribe((s) => {
      const b = s.opening ? `${s.opening.filename} ${s.batch.done + 1}/${s.batch.total}` : null;
      if (b && batches[batches.length - 1] !== b) batches.push(b);
    });
    const first = useScanStore.getState().loadFiles(["C:/a.nessus", "C:/b.nessus"]);
    const second = useScanStore.getState().loadFiles(["C:/c.nessus", "C:/a.nessus"]); // a is already waiting
    await Promise.all([first, second]);
    stop();
    expect(useScanStore.getState().files.map((f) => f.filename)).toEqual(["a.nessus", "b.nessus", "c.nessus"]);
    expect(batches).toEqual(["a.nessus 1/3", "b.nessus 2/3", "c.nessus 3/3"]);
    expect(useScanStore.getState().batch).toEqual({ done: 0, total: 0 });
    expect(useScanStore.getState().queue).toEqual([]);
  });

  it("a file that is already open isn't opened again", async () => {
    backend();
    await useScanStore.getState().loadFile("C:/a.nessus");
    invoke.mockClear();
    expect(await useScanStore.getState().loadFile("C:/a.nessus")).toBeNull();
    expect(invoke).not.toHaveBeenCalledWith("load_nessus_file", expect.anything());
    expect(useNotificationStore.getState().notifications.slice(-1)[0]?.message).toContain("already open");
    // Windows: the same path in other case or with other slashes
    expect(await useScanStore.getState().loadFile("c:\\A.NESSUS")).toBeNull();
    expect(invoke).not.toHaveBeenCalledWith("load_nessus_file", expect.anything());
  });

  it("the same scan from another folder isn't opened twice", async () => {
    backend();
    await useScanStore.getState().loadFile("C:/scans/a.nessus");
    expect(await useScanStore.getState().loadFile("//nas/share/a.nessus")).toBeNull();
    expect(useScanStore.getState().files).toHaveLength(1);
    expect(invoke).toHaveBeenCalledWith("unload_file", { id: "id-//nas/share/a.nessus" });
    expect(useNotificationStore.getState().notifications.slice(-1)[0]?.message).toContain("already open from C:/scans/a.nessus");
  });

  it("each file shows as soon as it is read", async () => {
    backend();
    const counts: number[] = [];
    const stop = useScanStore.subscribe((s) => counts.push(s.files.length));
    await useScanStore.getState().loadFiles(["C:/a.nessus", "C:/b.nessus", "C:/c.nessus"]);
    stop();
    expect([...new Set(counts)]).toEqual([0, 1, 2, 3]);
    expect(useScanStore.getState().files.map((f) => f.filename)).toEqual(["a.nessus", "b.nessus", "c.nessus"]);
  });

  it("keeps what went wrong, adds nothing half-loaded, and can try again", async () => {
    backend({ broken: { "C:/policy.nessus": { kind: "no_hosts", message: "This file has no scanned hosts." } } });
    const done = await useScanStore.getState().loadFiles(["C:/policy.nessus", "C:/good.nessus"]);
    expect(done.map((f) => f.filename)).toEqual(["good.nessus"]);
    const [failure] = useScanStore.getState().failures;
    expect(failure).toMatchObject({ path: "C:/policy.nessus", filename: "policy.nessus", kind: "no_hosts", message: "This file has no scanned hosts." });

    backend();
    await useScanStore.getState().retry(failure.id);
    expect(useScanStore.getState().failures).toEqual([]);
    expect(useScanStore.getState().files.map((f) => f.filename)).toEqual(["good.nessus", "policy.nessus"]);
  });

  it("forgets one recent file, or all of them", async () => {
    backend();
    useScanStore.setState({ recentFiles: [{ path: "C:/a.nessus", filename: "a.nessus", last_opened: "x" }, { path: "C:/b.nessus", filename: "b.nessus", last_opened: "y" }] });
    await useScanStore.getState().forgetRecent("C:/a.nessus");
    expect(useScanStore.getState().recentFiles.map((r) => r.path)).toEqual(["C:/b.nessus"]);
    await useScanStore.getState().clearRecent();
    expect(useScanStore.getState().recentFiles).toEqual([]);
    expect(invoke).toHaveBeenLastCalledWith("save_recent_files", { files: [] });
  });
});
