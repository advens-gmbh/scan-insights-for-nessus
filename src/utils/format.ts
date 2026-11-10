export function formatDate(dateStr: string | null | undefined): string {
  if (!dateStr) {
    return "-";
  }
  
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) {
    return dateStr;
  }

  const p = (n: number) => String(n).padStart(2, "0");

  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}// formatDate

// Nessus writes dates as 2012/01/31
export function formatNessusDate(value: string): string {
  return value.replace(/\//g, "-");
}// formatNessusDate

export function formatDateShort(dateStr: string | null | undefined): string {
  if (!dateStr) {
    return "-";
  }

  const d = new Date(dateStr);
  if (isNaN(d.getTime())) {
    return dateStr;
  }
  const p = (n: number) => String(n).padStart(2, "0");

  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}// formatDateShort

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// 517 MB, 9.4 MB, 340 KB
export function formatBytes(bytes: number): string {
  const kb = 1024;
  const mb = kb * 1024;
  const gb = mb * 1024;
  if (bytes < mb) {
    return `${Math.max(1, Math.round(bytes / kb))} KB`;
  }
  if (bytes < gb) {
    const n = bytes / mb;
    return `${n < 10 ? n.toFixed(1) : Math.round(n)} MB`;
  }
  return `${(bytes / gb).toFixed(1)} GB`;
}// formatBytes

// just now, 5 min ago, 2 hours ago, yesterday, 3 days ago, Nov 2, Nov 2, 2024
export function timeAgo(iso: string, now: Date = new Date()): string {
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) {
    return "";
  }
  const minutes = Math.floor((now.getTime() - then.getTime()) / 60000);
  if (minutes < 1) {
    return "just now";
  }
  if (minutes < 60) {
    return `${minutes} min ago`;
  }
  const dayOf = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  const days = Math.round((dayOf(now) - dayOf(then)) / 86400000);
  if (days === 0) {
    const hours = Math.floor(minutes / 60);
    return `${hours} ${hours === 1 ? "hour" : "hours"} ago`;
  }
  if (days === 1) {
    return "yesterday";
  }
  if (days < 7) {
    return `${days} days ago`;
  }
  const date = `${MONTHS[then.getMonth()]} ${then.getDate()}`;
  return then.getFullYear() === now.getFullYear() ? date : `${date}, ${then.getFullYear()}`;
}// timeAgo

export function folderOf(path: string): string {
  const cut = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return cut > 0 ? path.slice(0, cut) : "";
}// folderOf
