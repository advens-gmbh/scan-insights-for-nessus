import { useEffect } from "react";
import { useLocation } from "react-router-dom";
import { useScanStore } from "../stores/scanStore";
import { usePageState } from "../stores/pageStore";

// the file a table page shows ("all" for every open file)
export function useFileFilter(pageKey: string): [string, (id: string) => void] {
  const files = useScanStore((s) => s.files);
  const location = useLocation();
  const [chosen, setChosen] = usePageState(`${pageKey}:file`, "all");

  useEffect(() => {
    const handed = (location.state as { fileFilter?: string } | null)?.fileFilter;
    if (handed) {
      setChosen(handed);
    }
  }, [location.key, location.state, setChosen]);

  return [chosen === "all" || files.some((f) => f.id === chosen) ? chosen : "all", setChosen];
}// useFileFilter
