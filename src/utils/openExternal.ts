import { invoke } from "@tauri-apps/api/core";
import { useNotificationStore } from "../stores/notificationStore";

// Mirrors is_web_url in src-tauri/src/commands.rs, which is the actual enforcement.
// Used to avoid offering a link for scan file text that can't be opened.
export function isWebUrl(url: string): boolean {
  const authority = /^https?:\/\/([^/?#]*)/i.exec(url)?.[1];
  
  return !!authority && !authority.includes("@") && /^[\x21-\x7e]+$/.test(url) && !/["\\]/.test(url);
}// isWebUrl

export function metasploitSearchUrl(moduleName: string): string {
  const name = moduleName.slice(0, 200); // the name comes from the scan file; real ones are far shorter
  const query = name.replace(/\s*\([^)]*\)\s*$/, "") || name;

  return `https://www.rapid7.com/db/?q=${encodeURIComponent(query)}&type=metasploit`;
}// metasploitSearchUrl

export async function openExternal(url: string): Promise<void> {
  try {
    await invoke("open_url", { url });
  } catch (e) {
    useNotificationStore.getState().add(String(e), "error");
  }
}// openExternal
