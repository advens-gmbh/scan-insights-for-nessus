import type { ExportFormat } from "../types/nessus";

// the last export, shown on the Export page until the next one
export type ExportResult =
  | { ok: true; path: string; format: ExportFormat; findings: number; files: number; at: string }
  | { ok: false; path: string; format: ExportFormat; reason: string; detail: string };

const EXPLAINED: Record<string, string> = {
  in_use: "It's open in another program. Close it and try again.",
  denied: "You can't save in that folder. Pick another one.",
  no_folder: "That folder doesn't exist any more.",
  disk_full: "The disk is full. Free some space and try again.",
};

export function explainExportError(reason: string): string {
  return EXPLAINED[reason] ?? "Something went wrong while saving.";
}// explainExportError

// the same file can't help here, so the button asks for another place
export const needsAnotherPlace = (reason: string) => reason === "denied" || reason === "no_folder";

// what export_data rejects with. ({ reason, detail }, or a plain message)
export function exportErrorOf(e: unknown): { reason: string; detail: string } {
  if (e && typeof e === "object" && "reason" in e) {
    const { reason, detail } = e as { reason: unknown; detail?: unknown };
    return { reason: String(reason), detail: String(detail ?? "") };
  }

  return { reason: "other", detail: String(e) };
}// exportErrorOf
