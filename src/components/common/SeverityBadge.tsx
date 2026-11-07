import { SEVERITY_LABELS } from "../../types/nessus";

interface Props {
  severity: number;
  size?: "sm" | "md";
}// Props

const SOLID: Record<number, string> = {
  4: "bg-critical text-white",
  3: "bg-high text-white",
  2: "bg-medium text-white",
  1: "bg-low text-white",
  0: "bg-info text-white",
};// SOLID

export default function SeverityBadge({ severity, size = "md" }: Props) {
  const label = SEVERITY_LABELS[severity] ?? "Info";
  const colors = SOLID[severity] ?? SOLID[0];
  const px = size === "sm" ? "px-2 py-0.5 text-[10px]" : "px-2.5 py-0.5 text-xs";
  
  return (
    <span className={`pill font-semibold ${px} ${colors}`}>
      {label}
    </span>
  );
}// SeverityBadge
