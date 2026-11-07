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
