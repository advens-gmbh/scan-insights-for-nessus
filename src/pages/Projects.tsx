import { useEffect, useState } from "react";
import { ChevronRight, FolderOpen, Plus, Trash2, X, Pencil } from "lucide-react";
import { useProjectStore } from "../stores/projectStore";
import { useScanStore } from "../stores/scanStore";
import Select, { fileOption } from "../components/common/Select";
import { formatDate, timeAgo } from "../utils/format";
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
  const [expanded, setExpanded] = useState<string[]>([]);
  const toggle = (id: string) => setExpanded((now) => (now.includes(id) ? now.filter((x) => x !== id) : [...now, id]));

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

    const id = createProject(name, withLoaded ? files.map((f) => ({ path: f.path, filename: f.filename })) : []);
    setExpanded((now) => [...now, id]);
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
  // the ones used most recently first, like on the start screen
  const shown = [...projects].sort((a, b) => (b.last_opened ?? b.created_at).localeCompare(a.last_opened ?? a.created_at));

  return (
    <div className="flex flex-col gap-4">
      {/* New project */}
      <section className="card p-4 flex flex-col gap-3">
        <h2 className="text-heading font-semibold text-ink-800 dark:text-ink-100">New project</h2>
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
            A project keeps a set of scan files together. Load the files, then create one above.
          </p>
        </section>
      ) : (
        <div className="card overflow-hidden">
          {shown.map((project) => {
            const isLoading = loadingId === project.id;
            const count = project.file_paths.length;
            const isOpen = expanded.includes(project.id);
            const notInProject = files.filter((f) => !project.file_paths.some((fp) => fp.path === f.path));
            const names = project.file_paths.map((fp) => fp.filename.replace(/\.nessus$/i, ""));
            const summary = count === 0 ? "no files" : `${count} ${count === 1 ? "file" : "files"} · ${names.slice(0, 3).join(", ")}${count > 3 ? ` and ${count - 3} more` : ""}`;

            return (
              <section key={project.id} className="border-t border-ink-100 dark:border-ink-700/60 first:border-t-0">
                <div
                  onClick={(e) => (e.target as HTMLElement).closest("button, input") === null && toggle(project.id)}
                  className="grid grid-cols-[1.5rem_minmax(9rem,1fr)_minmax(0,2fr)_8rem_auto_auto] items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-ink-50 dark:hover:bg-ink-700/30"
                >
                  <button
                    onClick={() => toggle(project.id)}
                    aria-expanded={isOpen}
                    aria-label={isOpen ? `Hide the files of ${project.name}` : `Show the files of ${project.name}`}
                    className="h-6 w-6 inline-flex items-center justify-center rounded text-ink-500 dark:text-ink-400 hover:text-ink-800 dark:hover:text-ink-100"
                  >
                    <ChevronRight size={15} className={`transition-transform ${isOpen ? "rotate-90" : ""}`} />
                  </button>
                  <div className="min-w-0">
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
                        className="input h-8 py-0 font-semibold w-full"
                      />
                    ) : (
                      <button
                        onClick={() => {
                          setEditingId(project.id);
                          setEditName(project.name);
                        }}
                        className="group flex items-center gap-1.5 max-w-full text-left text-body font-semibold text-ink-800 dark:text-ink-100"
                        title="Rename"
                      >
                        <span className="truncate">{project.name}</span>
                        <Pencil size={13} className="shrink-0 text-ink-500 opacity-0 group-hover:opacity-100 group-focus-visible:opacity-100" />
                      </button>
                    )}
                  </div>
                  <span className="truncate text-small text-ink-500 dark:text-ink-400" title={names.join(", ")}>{summary}</span>
                  <span className="text-right whitespace-nowrap text-small text-ink-500 dark:text-ink-400" title={`Created ${formatDate(project.created_at)}`}>
                    {project.last_opened ? `opened ${timeAgo(project.last_opened)}` : `created ${timeAgo(project.created_at)}`}
                  </span>
                  <button
                    onClick={() => handleLoadProject(project.id)}
                    disabled={count === 0 || isLoading}
                    className="btn-ghost h-8 px-3 border border-ink-200 dark:border-ink-600 text-small font-semibold text-accent-700 dark:text-accent-400 disabled:opacity-50 disabled:cursor-not-allowed"
                    title="Closes the open files and opens this project's files"
                  >
                    {isLoading ? "Opening…" : `Open ${count} ${count === 1 ? "file" : "files"}`}
                  </button>
                  {confirmDelete === project.id ? (
                    <button onClick={() => deleteProject(project.id)} className="btn-ghost h-8 px-2 text-caption font-semibold text-critical-fg whitespace-nowrap">
                      Delete project?
                    </button>
                  ) : (
                    <button onClick={() => setConfirmDelete(project.id)} className="btn-ghost h-8 w-8 p-0 justify-center" title="Delete project" aria-label={`Delete ${project.name}`}>
                      <Trash2 size={14} />
                    </button>
                  )}
                </div>

                {isOpen && (
                  <div className="pl-14 pr-4 pb-4 pt-1 bg-ink-50 dark:bg-ink-900/40 border-t border-ink-100 dark:border-ink-700/60">
                    {count === 0 && <p className="py-2 text-small text-ink-500 dark:text-ink-400">No files yet.</p>}
                    <ul>
                      {project.file_paths.map((fp) => (
                        <li key={fp.path} className="grid grid-cols-[minmax(10rem,1fr)_minmax(0,2fr)_2rem] items-center gap-3 py-1.5 border-b border-ink-100 dark:border-ink-700/60">
                          <span className="flex items-center gap-2 min-w-0 text-body font-semibold text-ink-800 dark:text-ink-100">
                            <span className="truncate">{fp.filename.replace(/\.nessus$/i, "")}</span>
                            {loadedPaths.has(fp.path) && <Tag>loaded</Tag>}
                          </span>
                          <span className="truncate text-small text-ink-500 dark:text-ink-400" title={fp.path}>{fp.path}</span>
                          <button
                            onClick={() => removeFileFromProject(project.id, fp.path)}
                            className="btn-ghost h-7 w-7 p-0 justify-center"
                            title="Remove from the project"
                            aria-label={`Remove ${fp.filename} from the project`}
                          >
                            <X size={14} />
                          </button>
                        </li>
                      ))}
                    </ul>
                    {notInProject.length > 0 && (
                      <Select
                        value=""
                        onChange={(id) => {
                          const f = files.find((x) => x.id === id);
                          if (f) {
                            addFileToProject(project.id, { path: f.path, filename: f.filename });
                          }
                        }}
                        placeholder="Add a loaded file…"
                        ariaLabel="Add a loaded file"
                        className="w-64 mt-3"
                        options={notInProject.map(fileOption)}
                      />
                    )}
                  </div>
                )}
              </section>
            );
          })}
        </div>
      )}
    </div>
  );
}// Projects
