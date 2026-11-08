import { SEVERITY_LABELS } from "../../types/nessus";

interface Props {
  severity: number;
  size?: "sm" | "md";
}// Props

const SOLID: Record<number, string> = {
  4: "bg-critical text-critical-on",
  3: "bg-high text-high-on",
  2: "bg-medium text-medium-on",
  1: "bg-low text-low-on",
  0: "bg-info text-info-on",
};// SOLID

export default function SeverityBadge({ severity, size = "md" }: Props) {
  const label = SEVERITY_LABELS[severity] ?? "Info";
  const colors = SOLID[severity] ?? SOLID[0];
  // same width for severity pills
  const box = size === "sm" ? "w-[3.75rem] py-0.5 text-[10px]" : "w-[4.5rem] py-0.5 text-xs";
  
  return (
    <span className={`pill justify-center font-semibold ${box} ${colors}`}>
      {label}
    </span>
  );
}// SeverityBadge
