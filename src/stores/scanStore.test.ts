import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

const { useScanStore } = await import("./scanStore");
const { useNotificationStore } = await import("./notificationStore");

const host = (n: number) => ({ name: `10.0.0.${n}`, ip: `10.0.0.${n}`, items: [] });
const head = (path: string, hosts = 5) => ({
  id: `id-${path}`, filename: path.split("/").pop(), path, loaded_at: "2026-11-10T00:00:00Z", report_name: "Big", target: null,
  host_count: hosts, finding_count: hosts * 3, size: 1234,
});

// the backend hands out two hosts per page; `broken` paths fail the way the backend reports it
function backend({ failPage, broken }: { failPage?: number; broken?: Record<string, { kind: string; message: string }> } = {}) {
  invoke.mockImplementation(async (cmd: string, args?: { path?: string; id?: string; start?: number }) => {
    if (cmd === "load_nessus_file") {
      if (broken?.[args!.path!]) throw broken[args!.path!];
      return head(args!.path!);
    }
    if (cmd === "file_hosts") {
      const start = args?.start ?? 0;
      if (start === failPage) throw "The file was closed while it was loading.";
      const hosts = [1, 2, 3, 4, 5].slice(start, start + 2).map(host);
      return { hosts, next: start + hosts.length };
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

  it("puts the file together from its pages of hosts, step by step", async () => {
    backend();
    const seen: string[] = [];
    const stop = useScanStore.subscribe((s) => {
      const o = s.opening;
      const step = o ? `${o.stage} ${o.hosts}/${o.total}` : "idle";
      if (seen[seen.length - 1] !== step) seen.push(step);
    });
    const file = await useScanStore.getState().loadFile("C:/scans/big.nessus");
    stop();

    expect(file?.hosts.map((h) => h.ip)).toEqual(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]);
    expect(file).not.toHaveProperty("host_count");
    expect(file?.size).toBe(1234);
    expect(invoke.mock.calls.filter(([cmd]) => cmd === "file_hosts").map(([, a]) => a)).toEqual([
      { id: "id-C:/scans/big.nessus", start: 0 }, { id: "id-C:/scans/big.nessus", start: 2 }, { id: "id-C:/scans/big.nessus", start: 4 },
    ]);
    expect(seen).toEqual(["idle", "reading 0/0", "receiving 0/5", "receiving 2/5", "receiving 4/5", "receiving 5/5", "preparing 5/5", "idle"]);
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

  it("files opened together join at once, when the last one is in", async () => {
    backend();
    const counts: number[] = [];
    const stop = useScanStore.subscribe((s) => counts.push(s.files.length));
    await useScanStore.getState().loadFiles(["C:/a.nessus", "C:/b.nessus", "C:/c.nessus"]);
    stop();
    expect(new Set(counts)).toEqual(new Set([0, 3]));
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

  it("a page that fails leaves no file behind", async () => {
    backend({ failPage: 2 });
    expect(await useScanStore.getState().loadFile("C:/big.nessus")).toBeNull();
    const s = useScanStore.getState();
    expect(s.files).toHaveLength(0);
    expect(s.loading).toBe(false);
    expect(s.opening).toBeNull();
    expect(s.failures[0]).toMatchObject({ kind: "other", message: "The file was closed while it was loading." });
  });

  it("stops instead of waiting forever when hosts go missing", async () => {
    invoke.mockImplementation(async (cmd: string) => (cmd === "load_nessus_file" ? head("C:/x.nessus") : cmd === "file_hosts" ? { hosts: [], next: 0 } : null));
    expect(await useScanStore.getState().loadFile("C:/x.nessus")).toBeNull();
    expect(useScanStore.getState().files).toHaveLength(0);
    expect(useScanStore.getState().failures[0].message).toContain("0 of 5 hosts");
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
