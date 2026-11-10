const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

export function isIpv4(value: string): boolean {
  return IPV4.test(value);
}// isIpv4

function ipv4ToNumber(ip: string): number {
  return ip.split(".").reduce((acc, octet) => acc * 256 + Number(octet), 0);
}// ipv4ToNumber

const numbers = new Map<string, number | null>();
function numberOf(value: string): number | null {
  let n = numbers.get(value);
  if (n === undefined) {
    if (numbers.size > 500_000) {
      numbers.clear();
    }
    n = IPV4.test(value) ? ipv4ToNumber(value) : null;
    numbers.set(value, n);
  }
  return n;
}// numberOf

// Orders IPv4 addresses numerically, then IPv6 addresses and hostnames as text
export function compareHosts(a: string, b: string): number {
  const na = numberOf(a);
  const nb = numberOf(b);
  const aIsV4 = na !== null;
  const bIsV4 = nb !== null;
  if (aIsV4 && bIsV4) {
    return na - nb;
  }

  if (aIsV4 !== bIsV4) {
    return aIsV4 ? -1 : 1;
  }

  return a.localeCompare(b);
}// compareHosts
