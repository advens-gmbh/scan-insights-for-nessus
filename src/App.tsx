import { lazy, useEffect } from "react";
import { createBrowserRouter, RouterProvider, Navigate } from "react-router-dom";
import { useUiStore } from "./stores/uiStore";
import { useScanStore } from "./stores/scanStore";
import { useProjectStore } from "./stores/projectStore";
import Layout from "./components/layout/Layout";
import RouteError from "./components/common/RouteError";

const Dashboard = lazy(() => import("./pages/Dashboard"));
const Vulnerabilities = lazy(() => import("./pages/Vulnerabilities"));
const Hosts = lazy(() => import("./pages/Hosts"));
const Services = lazy(() => import("./pages/Services"));
const Topology = lazy(() => import("./pages/Topology"));
const Compare = lazy(() => import("./pages/Compare"));
const Trends = lazy(() => import("./pages/Trends"));
const Projects = lazy(() => import("./pages/Projects"));
const Export = lazy(() => import("./pages/Export"));

const router = createBrowserRouter([
  {
    path: "/",
    element: <Layout />,
    errorElement: <RouteError />, // an error in the panels or the layout itself
    children: [
      {
        errorElement: <RouteError />, // an error in a page, which keeps the sidebar usable
        children: [
          { index: true, element: <Dashboard /> },
          { path: "vulnerabilities", element: <Vulnerabilities /> },
          { path: "hosts", element: <Hosts /> },
          { path: "services", element: <Services /> },
          { path: "topology", element: <Topology /> },
          { path: "compare", element: <Compare /> },
          { path: "trends", element: <Trends /> },
          { path: "projects", element: <Projects /> },
          { path: "export", element: <Export /> },
          { path: "*", element: <Navigate to="/" replace /> },
        ],
      },
    ],
  },
]);// createBrowserRouter

export default function App() {
  const loadSettings = useUiStore((s) => s.loadSettings);
  const loadRecentFiles = useScanStore((s) => s.loadRecentFiles);
  const loadProjects = useProjectStore((s) => s.load);

  useEffect(() => {
    loadSettings();
    loadRecentFiles();
    loadProjects();
  }, [loadSettings, loadRecentFiles, loadProjects]);

  return <RouterProvider router={router} />;
}// App
