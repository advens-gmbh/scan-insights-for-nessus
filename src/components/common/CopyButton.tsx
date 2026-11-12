import { useState } from "react";
import { Copy, Check } from "lucide-react";

interface Props {
  text: string;
  label?: string;
  className?: string;
  variant?: "icon" | "text" | "both";
}// Props

export default function CopyButton({ text, label, className = "", variant = "both" }: Props) {
  const [copied, setCopied] = useState(false);

  const copy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // ignore
    }
  };

  return (
    <button
      onClick={copy}
      title={label ?? `Copy: ${text}`}
      className={`btn-ghost h-7 px-2 text-caption gap-1 ${className}`}
    >
      {copied ? <Check size={13} className="text-emerald-500" /> : <Copy size={13} />}
      {variant !== "icon" && (
        <span>{copied ? "Copied!" : label ?? "Copy"}</span>
      )}
    </button>
  );
}// CopyButton
