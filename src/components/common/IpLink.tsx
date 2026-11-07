import { useUiStore } from "../../stores/uiStore";

interface Props {
  ip: string;
  fileId?: string; // limit the host panel to this file instead of merging all files
  className?: string;
}// Props

export default function IpLink({ ip, fileId, className = "" }: Props) {
  const openHostPanel = useUiStore((s) => s.openHostPanel);
  
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        openHostPanel(ip, fileId);
      }}
      className={`font-mono text-violet-600 dark:text-violet-400 hover:underline focus:outline-none text-sm ${className}`}
    >
      {ip}
    </button>
  );
}// IpLink
