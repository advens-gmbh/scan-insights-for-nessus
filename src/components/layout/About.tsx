import { useEffect, useRef, useState } from "react";
import { ExternalLink } from "lucide-react";
import appIcon from "../../assets/app-icon.svg";
import CompanyLogo, { COMPANY_NAME, COMPANY_URL } from "../common/CompanyLogo";
import { openExternal } from "../../utils/openExternal";

export const APP_VERSION = typeof __APP_VERSION__ === "string" ? __APP_VERSION__ : "";

export default function About({ collapsed }: { collapsed: boolean }) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) {
      return;
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopImmediatePropagation(); // closes only the About box, not an open panel too
        setOpen(false);
      }
    };
    const onDown = (e: MouseEvent) => {
      const target = e.target as Node;
      if (!box.current?.contains(target) && !button.current?.contains(target)) {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", onKey, true);
    window.addEventListener("mousedown", onDown);
    return () => {
      window.removeEventListener("keydown", onKey, true);
      window.removeEventListener("mousedown", onDown);
    };
  }, [open]);

  const label = `Built by ${COMPANY_NAME}${APP_VERSION ? `, version ${APP_VERSION}` : ""}`;

  return (
    <>
      <button
        ref={button}
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-label={`About Scan Insights. ${label}`}
        title={collapsed ? label : undefined}
        className={`flex items-center h-11 shrink-0 overflow-hidden whitespace-nowrap border-t border-ink-700/50 text-white hover:bg-white/[0.04] transition-colors ${collapsed ? "justify-center" : "gap-2.5 px-4"}`}
      >
        {collapsed ? (
          <CompanyLogo mark className="h-[15px]" />
        ) : (
          <>
            <span className="text-[11px] font-semibold text-ink-500">Built by</span>
            <CompanyLogo className="h-[14px] shrink-0" />
            {APP_VERSION && <span className="ml-auto text-[11px] text-ink-500 tabular-nums">v{APP_VERSION}</span>}
          </>
        )}
      </button>

      {open && (
        <div
          ref={box}
          role="dialog"
          aria-label="About Scan Insights for Nessus"
          className="fixed left-3 bottom-[92px] z-50 w-[300px] rounded-lg border border-ink-200 dark:border-ink-700 bg-white dark:bg-ink-800 text-ink-800 dark:text-ink-100 shadow-xl p-4"
        >
          <div className="flex items-center gap-3">
            <img src={appIcon} alt="" className="w-10 h-10" />
            <div>
              <p className="text-[15px] font-semibold text-ink-900 dark:text-ink-50">Scan Insights for Nessus</p>
              {APP_VERSION && <p className="text-xs text-ink-500 dark:text-ink-400">Version {APP_VERSION}</p>}
            </div>
          </div>
          <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3.5 gap-y-1.5 my-3.5 text-[13px]">
            <dt className="text-ink-500 dark:text-ink-400">Built by</dt>
            <dd className="flex flex-col items-start gap-1">
              <CompanyLogo className="h-[15px] text-ink-900 dark:text-white" />
              <button
                onClick={() => openExternal(COMPANY_URL)}
                title={COMPANY_URL}
                className="inline-flex items-center gap-1 font-medium text-accent-700 dark:text-accent-400 hover:underline"
              >
                {COMPANY_URL.replace(/^https?:\/\/(www\.)?/, "").replace(/\/$/, "")} <ExternalLink size={11} />
              </button>
            </dd>
            <dt className="text-ink-500 dark:text-ink-400">Your data</dt>
            <dd>Stays on this computer. The app works offline.</dd>
          </dl>
          <p className="pt-3 border-t border-ink-200 dark:border-ink-700 text-xs text-ink-500 dark:text-ink-400">
            Not affiliated with Tenable. Nessus is a trademark of Tenable, Inc.
          </p>
        </div>
      )}
    </>
  );
}// About
