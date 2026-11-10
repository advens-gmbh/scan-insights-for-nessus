import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

const { useScanStore } = await import("./scanStore");
const { useNotificationStore } = await import("./notificationStore");

const host = (n: number) => ({ name: `10.0.0.${n}`, ip: `10.0.0.${n}`, items: [] });
const HEAD = { id: "f1", filename: "big.nessus", path: "C:/scans/big.nessus", loaded_at: "2026-11-10T00:00:00Z", report_name: "Big", target: null, host_count: 5 };

// the backend hands out two hosts per page
function backend(fail?: (start: number) => boolean) {
  invoke.mockImplementation(async (cmd: string, args?: { start?: number }) => {
    if (cmd === "load_nessus_file") return HEAD;
    if (cmd === "file_hosts") {
      const start = args?.start ?? 0;
      if (fail?.(start)) throw "The file was closed while it was loading.";
      const hosts = [1, 2, 3, 4, 5].slice(start, start + 2).map(host);
      return { hosts, next: start + hosts.length };
    }
    return null;
  });
}

describe("scanStore loading a file", () => {
  beforeEach(() => {
    invoke.mockReset();
    useScanStore.setState({ files: [], recentFiles: [], loading: false, progress: null, error: null });
    useNotificationStore.setState({ notifications: [] });
  });

  it("puts the file together from its pages of hosts", async () => {
    backend();
    const seen: string[] = [];
    const stop = useScanStore.subscribe((s) => { if (s.progress) seen.push(`${s.progress.done}/${s.progress.total}`); });
    const file = await useScanStore.getState().loadFile(HEAD.path);
    stop();

    expect(file?.hosts.map((h) => h.ip)).toEqual(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]);
    expect(file).not.toHaveProperty("host_count");
    expect(invoke.mock.calls.filter(([cmd]) => cmd === "file_hosts").map(([, a]) => a)).toEqual([
      { id: "f1", start: 0 }, { id: "f1", start: 2 }, { id: "f1", start: 4 },
    ]);
    expect(seen).toEqual(["0/5", "2/5", "4/5", "5/5"]);
    const s = useScanStore.getState();
    expect(s.files).toHaveLength(1);
    expect(s.loading).toBe(false);
    expect(s.progress).toBeNull();
  });

  it("adds nothing when a page fails, and says why", async () => {
    backend((start) => start === 2);
    const file = await useScanStore.getState().loadFile(HEAD.path);

    expect(file).toBeNull();
    const s = useScanStore.getState();
    expect(s.files).toHaveLength(0);
    expect(s.loading).toBe(false);
    expect(s.progress).toBeNull();
    const notes = useNotificationStore.getState().notifications;
    expect(notes.slice(-1)[0]?.message).toContain("closed while it was loading");
  });

  it("stops instead of waiting forever when hosts go missing", async () => {
    invoke.mockImplementation(async (cmd: string) => (cmd === "load_nessus_file" ? HEAD : cmd === "file_hosts" ? { hosts: [], next: 0 } : null));
    expect(await useScanStore.getState().loadFile(HEAD.path)).toBeNull();
    expect(useScanStore.getState().files).toHaveLength(0);
  });
});
