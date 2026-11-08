export function httpUrl(ip: string, port: number): string {
  return `http://${ip}${port !== 80 ? `:${port}` : ""}`;
}// httpUrl

export function httpsUrl(ip: string, port: number): string {
  return `https://${ip}${port !== 443 ? `:${port}` : ""}`;
}// httpsUrl
