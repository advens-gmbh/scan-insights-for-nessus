import { NavLink } from "react-router-dom";
import { LayoutDashboard, ShieldAlert, Server, Layers, Network, GitCompare, TrendingUp, FolderOpen, Download, ChevronLeft, ChevronRight,} from "lucide-react";
import { useUiStore } from "../../stores/uiStore";
import logo from "../../../src-tauri/icons/128x128.png";

const NAV_ITEMS = [
  { to: "/",              icon: LayoutDashboard, label: "Dashboard"       },
  { to: "/vulnerabilities", icon: ShieldAlert,   label: "Vulnerabilities" },
  { to: "/hosts",         icon: Server,          label: "Hosts"           },
  { to: "/services",      icon: Layers,          label: "Services"        },
  { to: "/topology",      icon: Network,         label: "Topology"        },
  { to: "/compare",       icon: GitCompare,      label: "Compare"         },
  { to: "/timeline",      icon: TrendingUp,      label: "Timeline"        },
  { to: "/projects",      icon: FolderOpen,      label: "Projects"        },
  { to: "/export",        icon: Download,        label: "Export"          },
];// NAV_ITEMS

export default function Sidebar() {
  const { sidebarCollapsed, toggleSidebar } = useUiStore();

  return (
    <aside
      style={{ width: sidebarCollapsed ? "64px" : "240px" }}
      className="flex flex-col bg-ink-900 text-ink-300 transition-all duration-200 overflow-hidden shrink-0"
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 h-14 border-b border-ink-700/50 shrink-0">
        <img src={logo} alt="" className="w-7 h-7 rounded-lg shrink-0" />
        {!sidebarCollapsed && (
          <div className="overflow-hidden">
            <p className="text-white font-semibold text-sm leading-tight truncate">Scan Insights</p>
            <p className="text-ink-500 text-[10px] leading-tight truncate">for Nessus</p>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2 py-3 flex flex-col gap-0.5 overflow-y-auto">
        {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              isActive ? "nav-item-active" : "nav-item"
            }
            title={sidebarCollapsed ? label : undefined}
          >
            <Icon className="w-4.5 h-4.5 shrink-0" size={18} />
            {!sidebarCollapsed && (
              <span className="truncate">{label}</span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Collapse toggle */}
      <button
        onClick={toggleSidebar}
        className="flex items-center justify-center h-10 border-t border-ink-700/50 text-ink-500 hover:text-ink-300 transition-colors"
        title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
      >
        {sidebarCollapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
      </button>
    </aside>
  );
}// Sidebar
