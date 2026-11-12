import { useNavigate, useRouteError } from "react-router-dom";
import { TriangleAlert } from "lucide-react";
import { useUiStore } from "../../stores/uiStore";

// shown instead of a page or panel that failed to render
export default function RouteError() {
  const error = useRouteError();
  const navigate = useNavigate();
  const { closeVulnPanel, closeHostPanel } = useUiStore();

  const goToDashboard = () => {
    closeVulnPanel();
    closeHostPanel();
    navigate("/");
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3 p-6 text-center">
      <TriangleAlert size={28} className="text-amber-500" />
      <h1 className="font-semibold text-ink-800 dark:text-ink-100">This page could not be displayed</h1>
      <p className="text-body text-ink-500 dark:text-ink-400 max-w-md">
        A damaged or unusual scan file can cause this. Your loaded files are still available on the other pages.
      </p>
      <p className="text-caption text-ink-400 max-w-md break-words">
        {error instanceof Error ? error.message : "Unknown error"}
      </p>
      <button onClick={goToDashboard} className="btn-primary mt-1">Go to Dashboard</button>
    </div>
  );
}// RouteError
