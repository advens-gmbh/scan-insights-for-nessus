import { displayScanName } from "../../types/nessus";
import type { NessusFile } from "../../types/nessus";

// get name of the scan specified in Nessus
export default function ScanName({ file }: { file: NessusFile }) {
  const name = displayScanName(file);
  if (!name) {
    return null;
  }

  return (
    <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 truncate" title={name}>
      {name}
    </p>
  );
}// ScanName
