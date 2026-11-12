import { useMemo } from "react";
import { NavLink } from "react-router-dom";
import { LayoutDashboard, ShieldAlert, Server, Layers, Network, GitCompare, TrendingUp, FolderOpen, Download, ChevronLeft, ChevronRight,} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useUiStore } from "../../stores/uiStore";
import { useScanStore } from "../../stores/scanStore";
import { buildHostEntries, buildServiceEntries, buildVulnEntries } from "../../types/nessus";
import logo from "../../assets/app-icon.svg";
import About from "./About";

type Counted = "vulnerabilities" | "hosts" | "services";
interface Item { to: string; icon: LucideIcon; label: string; count?: Counted }

const NAV_GROUPS: { label: string | null; items: Item[] }[] = [
  { label: null, items: [{ to: "/", icon: LayoutDashboard, label: "Dashboard" }] },
  { label: "Findings", items: [
    { to: "/vulnerabilities", icon: ShieldAlert, label: "Vulnerabilities", count: "vulnerabilities" },
    { to: "/hosts",           icon: Server,      label: "Hosts",           count: "hosts" },
    { to: "/services",        icon: Layers,      label: "Services",        count: "services" },
  ] },
  { label: "Network", items: [{ to: "/topology", icon: Network, label: "Topology" }] },
  { label: "Over time", items: [
    { to: "/compare", icon: GitCompare, label: "Compare" },
    { to: "/trends",  icon: TrendingUp, label: "Trends" },
  ] },
  { label: "Files", items: [
    { to: "/projects", icon: FolderOpen, label: "Projects" },
    { to: "/export",   icon: Download,   label: "Export" },
  ] },
];// NAV_GROUPS

export default function Sidebar() {
  const { sidebarCollapsed, toggleSidebar } = useUiStore();
  const files = useScanStore((s) => s.files);
  const counts = useMemo<Record<Counted, number> | null>(() => files.length === 0 ? null : {
    vulnerabilities: buildVulnEntries(files).length,
    hosts: buildHostEntries(files).length,
    services: buildServiceEntries(files).length,
  }, [files]);

  return (
    <aside
      style={{ width: sidebarCollapsed ? "64px" : "240px" }}
      className="on-dark flex flex-col bg-ink-900 text-ink-300 transition-all duration-200 overflow-hidden shrink-0"
    >
      {/* Logo */}
      <div className={`flex items-center h-14 border-b border-ink-700/50 shrink-0 ${sidebarCollapsed ? "justify-center" : "gap-3 px-4"}`}>
        <img src={logo} alt="" className="w-7 h-7 shrink-0" />
        {!sidebarCollapsed && (
          <div className="overflow-hidden">
            <p className="text-white font-semibold text-body leading-tight truncate">Scan Insights</p>
            <p className="text-ink-500 text-tiny leading-tight truncate">for Nessus</p>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2 py-2.5 flex flex-col gap-0.5 overflow-y-auto overflow-x-hidden" aria-label="Pages">
        {NAV_GROUPS.map((group) => (
          <div key={group.label ?? "top"} className="flex flex-col gap-0.5">
            {group.label && (sidebarCollapsed
              ? <span className="mx-3 my-2 border-t border-ink-700/60" aria-hidden="true" />
              : <span className="px-3 pt-3.5 pb-1 text-tiny font-semibold text-ink-500">{group.label}</span>)}
            {group.items.map(({ to, icon: Icon, label, count }) => {
              const n = count && counts ? counts[count] : null;
              return (
                <NavLink
                  key={to}
                  to={to}
                  end={to === "/"}
                  className={({ isActive }) => `${isActive ? "nav-item-active" : "nav-item"}${sidebarCollapsed ? " justify-center px-0" : ""}`}
                  title={sidebarCollapsed ? (n !== null ? `${label} (${n.toLocaleString()})` : label) : undefined}
                >
                  <Icon className="w-4.5 h-4.5 shrink-0" size={18} />
                  {!sidebarCollapsed && (
                    <>
                      <span className="truncate">{label}</span>
                      {n !== null && <span className="ml-auto text-caption font-medium tabular-nums text-ink-400">{n.toLocaleString()}</span>}
                    </>
                  )}
                </NavLink>
              );
            })}
          </div>
        ))}
      </nav>

      <About collapsed={sidebarCollapsed} />

      {/* Collapse toggle */}
      <button
        onClick={toggleSidebar}
        className="flex items-center justify-center h-10 border-t border-ink-700/50 text-ink-500 hover:text-ink-300 transition-colors"
        title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
      >
        {sidebarCollapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
      </button>
    </aside>
  );
}// Sidebar
