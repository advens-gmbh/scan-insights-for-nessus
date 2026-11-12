import { useEffect, useState } from "react";
import { FolderOpen, Plus, Trash2, X, FileText, Download, Pencil } from "lucide-react";
import { useProjectStore } from "../stores/projectStore";
import { useScanStore } from "../stores/scanStore";
import { formatDate } from "../utils/format";
import { Tag } from "../panels/PanelParts";

export default function Projects() {
  const { projects, createProject, deleteProject, renameProject, addFileToProject, removeFileFromProject, markOpened } = useProjectStore();
  const { files, loadFiles, unloadAll } = useScanStore();
  const [newName, setNewName] = useState("");
  const [withLoaded, setWithLoaded] = useState(true);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [loadingId, setLoadingId] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  useEffect(() => {
    if (!confirmDelete) {
      return;
    }
    const timer = setTimeout(() => setConfirmDelete(null), 3000);

    return () => clearTimeout(timer);
  }, [confirmDelete]);

  const handleCreate = () => {
    const name = newName.trim();
    if (!name) {
      return;
    }

    createProject(name, withLoaded ? files.map((f) => ({ path: f.path, filename: f.filename })) : []);
    setNewName("");
  };

  const commitEdit = () => {
    if (editingId && editName.trim()) {
      renameProject(editingId, editName.trim());
    }
    setEditingId(null);
  };

  const handleLoadProject = async (projectId: string) => {
    const project = projects.find((p) => p.id === projectId);
    if (!project || project.file_paths.length === 0) {
      return;
    }

    setLoadingId(projectId);
    markOpened(projectId);
    await unloadAll();
    // one batch, so the progress reads "file 2 of 4"
    await loadFiles(project.file_paths.map((fp) => fp.path));
    setLoadingId(null);
  };

  const loadedPaths = new Set(files.map((f) => f.path));

  return (
    <div className="flex flex-col gap-4">
      {/* New project */}
      <section className="card p-4 flex flex-col gap-3">
        <div className="flex flex-wrap items-baseline gap-3">
          <h2 className="text-heading font-semibold text-ink-800 dark:text-ink-100">New project</h2>
          <span className="text-small text-ink-500 dark:text-ink-400">A project remembers a set of scan files so you can open them again with one click.</span>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <input
            type="text"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleCreate()}
            placeholder="Project name, e.g. the customer or the engagement"
            className="input flex-1 min-w-64"
          />
          {files.length > 0 && (
            <label className="flex items-center gap-1.5 text-small text-ink-600 dark:text-ink-300 cursor-pointer select-none">
              <input type="checkbox" checked={withLoaded} onChange={() => setWithLoaded((v) => !v)} className="rounded accent-accent-600" />
              With the {files.length} loaded {files.length === 1 ? "file" : "files"}
            </label>
          )}
          <button onClick={handleCreate} disabled={!newName.trim()} className="btn-primary h-9 px-4 disabled:opacity-50 disabled:cursor-not-allowed">
            <Plus size={15} /> Create
          </button>
        </div>
      </section>

      {projects.length === 0 ? (
        <section className="card p-10 flex flex-col items-center gap-2 text-center">
          <FolderOpen size={32} className="text-ink-300 dark:text-ink-600" />
          <p className="font-medium text-ink-700 dark:text-ink-200">No projects yet</p>
          <p className="max-w-md text-small text-ink-500 dark:text-ink-400">
            Load the scan files that belong together, for example every scan of one customer, then create a project above to reopen them all later.
          </p>
        </section>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {projects.map((project) => {
            const isLoading = loadingId === project.id;
            const count = project.file_paths.length;
            const notInProject = files.filter((f) => !project.file_paths.some((fp) => fp.path === f.path));

            return (
              <section key={project.id} className="card p-4 flex flex-col gap-3">
                <div className="flex items-start gap-2">
                  <div className="flex-1 min-w-0">
                    {editingId === project.id ? (
                      <input
                        autoFocus
                        value={editName}
                        onChange={(e) => setEditName(e.target.value)}
                        onBlur={commitEdit}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            commitEdit();
                          } else if (e.key === "Escape") {
                            setEditingId(null);
                          }
                        }}
                        className="input h-8 py-0 text-heading font-semibold w-full"
                      />
                    ) : (
                      <button
                        onClick={() => {
                          setEditingId(project.id);
                          setEditName(project.name);
                        }}
                        className="group flex items-center gap-1.5 max-w-full text-left text-heading font-semibold text-ink-800 dark:text-ink-100"
                        title="Rename"
                      >
                        <span className="truncate">{project.name}</span>
                        <Pencil size={13} className="shrink-0 text-ink-400 opacity-0 group-hover:opacity-100 group-focus-visible:opacity-100" />
                      </button>
                    )}
                    <p className="text-caption text-ink-500 dark:text-ink-400 mt-0.5">Created {formatDate(project.created_at)}</p>
                  </div>
                  {confirmDelete === project.id ? (
                    <button onClick={() => deleteProject(project.id)} className="btn-ghost h-7 px-2 text-caption font-semibold text-critical-fg shrink-0">
                      Delete project?
                    </button>
                  ) : (
                    <button onClick={() => setConfirmDelete(project.id)} className="btn-ghost h-7 w-7 p-0 justify-center shrink-0" title="Delete project" aria-label="Delete project">
                      <Trash2 size={14} />
                    </button>
                  )}
                </div>

                <ul className="flex flex-col gap-1 flex-1">
                  {count === 0 && <li className="text-small text-ink-500 dark:text-ink-400">No files yet. Add loaded files below.</li>}
                  {project.file_paths.map((fp) => (
                    <li key={fp.path} className="flex items-center gap-2.5 rounded-md bg-ink-50 dark:bg-ink-700/50 px-3 py-2">
                      <FileText size={14} className="text-ink-400 shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="flex items-center gap-2 text-body text-ink-800 dark:text-ink-100">
                          <span className="truncate">{fp.filename.replace(/\.nessus$/i, "")}</span>
                          {loadedPaths.has(fp.path) && <Tag>loaded</Tag>}
                        </p>
                        <p className="truncate text-caption text-ink-500 dark:text-ink-400" title={fp.path}>{fp.path}</p>
                      </div>
                      <button
                        onClick={() => removeFileFromProject(project.id, fp.path)}
                        className="btn-ghost h-7 w-7 p-0 justify-center shrink-0"
                        title="Remove from the project"
                        aria-label={`Remove ${fp.filename} from the project`}
                      >
                        <X size={14} />
                      </button>
                    </li>
                  ))}
                </ul>

                {notInProject.length > 0 && (
                  <select
                    onChange={(e) => {
                      const f = files.find((x) => x.id === e.target.value);
                      if (f) {
                        addFileToProject(project.id, { path: f.path, filename: f.filename });
                      }
                      e.target.value = "";
                    }}
                    className="input h-8 py-0 text-small"
                    defaultValue=""
                    aria-label="Add a loaded file"
                  >
                    <option value="">Add a loaded file…</option>
                    {notInProject.map((f) => <option key={f.id} value={f.id}>{f.filename}</option>)}
                  </select>
                )}

                <button
                  onClick={() => handleLoadProject(project.id)}
                  disabled={count === 0 || isLoading}
                  className="btn-primary h-9 justify-center disabled:opacity-50 disabled:cursor-not-allowed"
                  title="Unloads the current files and opens this project's files"
                >
                  <Download size={15} />
                  {isLoading ? "Opening…" : `Open ${count} ${count === 1 ? "file" : "files"}`}
                </button>
              </section>
            );
          })}
        </div>
      )}
    </div>
  );
}// Projects
