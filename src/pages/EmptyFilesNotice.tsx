import { useNavigate } from "react-router-dom";
import { FolderOpen } from "lucide-react";
import { useScanStore } from "../stores/scanStore";

export default function EmptyFilesNotice() {
  const openFiles = useScanStore((s) => s.openFiles);
  const navigate = useNavigate();
  return (
    <div className="flex flex-col items-center justify-center min-h-[50vh] gap-4 text-center">
      <p className="text-slate-400">No scan files loaded.</p>
      <div className="flex gap-3">
        <button onClick={openFiles} className="btn-primary">
          <FolderOpen size={14} /> Open File
        </button>
        <button onClick={() => navigate("/")} className="btn-secondary">
          Go to Dashboard
        </button>
      </div>
    </div>
  );
}// EmptyFilesNotice
