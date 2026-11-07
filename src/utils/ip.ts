const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

export function isIpv4(value: string): boolean {
  return IPV4.test(value);
}// isIpv4

function ipv4ToNumber(ip: string): number {
  return ip.split(".").reduce((acc, octet) => acc * 256 + Number(octet), 0);
}// ipv4ToNumber

// Orders IPv4 addresses numerically, then IPv6 addresses and hostnames as text.
export function compareHosts(a: string, b: string): number {
  const aIsV4 = IPV4.test(a);
  const bIsV4 = IPV4.test(b);
  if (aIsV4 && bIsV4) {
    return ipv4ToNumber(a) - ipv4ToNumber(b);
  }

  if (aIsV4 !== bIsV4) {
    return aIsV4 ? -1 : 1;
  }

  return a.localeCompare(b);
}// compareHosts
