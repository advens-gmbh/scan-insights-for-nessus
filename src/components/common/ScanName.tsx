import { displayScanName } from "../../types/nessus";
import type { ScanFile } from "../../types/nessus";

// get name of the scan specified in Nessus
export default function ScanName({ file }: { file: ScanFile }) {
  const name = displayScanName(file);
  if (!name) {
    return null;
  }

  return (
    <p className="text-caption text-ink-500 dark:text-ink-400 mt-0.5 truncate" title={name}>
      {name}
    </p>
  );
}// ScanName
