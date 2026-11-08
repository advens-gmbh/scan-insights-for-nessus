import { isIpv4 } from "./ip";

export interface TargetCoverage {
  target: string;
  size: number | null; // addresses in a range or subnet, null for a single address or a name
  ips: string[];       // hosts found that fall under it
}// TargetCoverage

type Matcher = (host: { ip: string; name: string; hostname: string | null }) => boolean;

function toNumber(ip: string): number {
  return ip.split(".").reduce((n, octet) => n * 256 + Number(octet), 0);
}// toNumber

function between(from: number, to: number): Matcher {
  return (h) => isIpv4(h.ip) && toNumber(h.ip) >= from && toNumber(h.ip) <= to;
}// between

// Nessus targets: 10.0.0.5, 10.0.0.0/24, 10.0.0.1-10.0.0.40, 10.0.0.1-40 or a host name
function parseTarget(target: string): { size: number | null; matches: Matcher } {
  const cidr = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(target);
  if (cidr && isIpv4(cidr[1]) && Number(cidr[2]) <= 32) {
    const bits = Number(cidr[2]);
    const size = 2 ** (32 - bits);
    const start = Math.floor(toNumber(cidr[1]) / size) * size;
    return { size, matches: between(start, start + size - 1) };
  }

  const range = /^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})$/.exec(target);
  if (range && isIpv4(range[1])) {
    const end = range[2].includes(".") ? range[2] : range[1].replace(/\d+$/, range[2]);
    if (isIpv4(end) && toNumber(end) >= toNumber(range[1])) {
      return { size: toNumber(end) - toNumber(range[1]) + 1, matches: between(toNumber(range[1]), toNumber(end)) };
    }
  }

  const name = target.toLowerCase();
  return {
    size: null,
    matches: (h) => h.ip === target || h.name.toLowerCase() === name || h.hostname?.toLowerCase() === name,
  };
}// parseTarget

export function splitTargets(target: string | null): string[] {
  return target ? [...new Set(target.split(/[\n,]+/).map((t) => t.trim()).filter(Boolean))] : [];
}// splitTargets

export function targetCoverage(targets: string[], hosts: { ip: string; name: string; hostname: string | null }[]): TargetCoverage[] {
  return targets.map((target) => {
    const { size, matches } = parseTarget(target);
    return { target, size, ips: hosts.filter(matches).map((h) => h.ip) };
  });
}// targetCoverage
