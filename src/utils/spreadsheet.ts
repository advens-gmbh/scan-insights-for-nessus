// Makes a value safe to paste into Excel or Sheets as one tab-separated cell. Values come
// from the scan, and a hostname like =cmd|... would otherwise run as a formula there.
export function spreadsheetCell(value: string): string {
  const oneLine = value.replace(/[\t\r\n]+/g, " ").trim();
  
  return /^[=+\-@]/.test(oneLine) ? `'${oneLine}` : oneLine;
}// spreadsheetCell
