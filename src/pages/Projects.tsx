import { useState } from "react";
import { FolderOpen, Plus, Trash2, X, FileText, Download } from "lucide-react";
import { useProjectStore } from "../stores/projectStore";
import { useScanStore } from "../stores/scanStore";
import { formatDate } from "../utils/format";

export default function Projects() {
  const { projects, createProject, deleteProject, renameProject, addFileToProject, removeFileFromProject } = useProjectStore();
  const { files, loadFile, unloadAll } = useScanStore();
  const [newName, setNewName] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [loadingId, setLoadingId] = useState<string | null>(null);

  const handleCreate = () => {
    const name = newName.trim();
    if (!name) {
      return;
    }

    createProject(name);
    setNewName("");
  };

  const startEdit = (id: string, name: string) => {
    setEditingId(id);
    setEditName(name);
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
    await unloadAll();
    for (const fp of project.file_paths) {
      await loadFile(fp.path);
    }
    setLoadingId(null);
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="font-semibold text-slate-700 dark:text-slate-200">Projects</h2>
          <p className="text-xs text-slate-400">
            Group scan files by path. Use "Load" to unload all current files and reload the project's files.
          </p>
        </div>
      </div>

      {/* Create project */}
      <div className="card p-4 flex items-center gap-3">
        <input
          type="text"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleCreate()}
          placeholder="New project name…"
          className="input flex-1"
        />
        <button
          onClick={handleCreate}
          disabled={!newName.trim()}
          className="btn-primary disabled:opacity-50"
        >
          <Plus size={14} /> Create Project
        </button>
      </div>

      {/* Project grid */}
      {projects.length === 0 ? (
        <div className="card p-10 text-center text-slate-400">
          <FolderOpen size={32} className="mx-auto mb-3 opacity-40" />
          <p>No projects yet. Create one above.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {projects.map((project) => {
            const isLoading = loadingId === project.id;
            // Files currently loaded that aren't already in this project
            const unassignedLoadedFiles = files.filter(
              (f) => !project.file_paths.some((fp) => fp.path === f.path)
            );

            return (
              <div key={project.id} className="card p-5 flex flex-col gap-4">
                {/* Title + actions */}
                <div className="flex items-start justify-between gap-2">
                  {editingId === project.id ? (
                    <input
                      autoFocus
                      value={editName}
                      onChange={(e) => setEditName(e.target.value)}
                      onBlur={commitEdit}
                      onKeyDown={(e) => e.key === "Enter" && commitEdit()}
                      className="input flex-1 h-7 py-0 text-sm font-semibold"
                    />
                  ) : (
                    <h3
                      className="font-semibold text-slate-800 dark:text-slate-100 cursor-pointer hover:text-violet-600 dark:hover:text-violet-400 transition-colors"
                      onClick={() => startEdit(project.id, project.name)}
                      title="Click to rename"
                    >
                      {project.name}
                    </h3>
                  )}
                  <button onClick={() => deleteProject(project.id)} className="btn-danger p-1 h-7 w-7 shrink-0">
                    <Trash2 size={13} />
                  </button>
                </div>

                <p className="text-xs text-slate-400 -mt-2">
                  Created {formatDate(project.created_at)}
                </p>

                {/* Assigned file paths */}
                <div className="space-y-1.5 flex-1">
                  {project.file_paths.length === 0 ? (
                    <p className="text-xs text-slate-400 italic">No files in this project.</p>
                  ) : (
                    project.file_paths.map((fp) => (
                      <div key={fp.path} className="flex items-center gap-2 bg-slate-50 dark:bg-slate-700/50 rounded-lg px-3 py-2">
                        <FileText size={13} className="text-violet-500 shrink-0" />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs text-slate-700 dark:text-slate-300 truncate">{fp.filename}</p>
                          <p className="text-[10px] text-slate-400 truncate" title={fp.path}>{fp.path}</p>
                        </div>
                        <button
                          onClick={() => removeFileFromProject(project.id, fp.path)}
                          className="text-slate-400 hover:text-red-500 transition-colors shrink-0"
                        >
                          <X size={13} />
                        </button>
                      </div>
                    ))
                  )}
                </div>

                {/* Add currently-loaded file to project */}
                {unassignedLoadedFiles.length > 0 && (
                  <select
                    onChange={(e) => {
                      const f = files.find((f) => f.id === e.target.value);
                      if (f) addFileToProject(project.id, { path: f.path, filename: f.filename });
                      e.target.value = "";
                    }}
                    className="input text-xs h-8 py-0"
                    defaultValue=""
                  >
                    <option value="">+ Add loaded file to project…</option>
                    {unassignedLoadedFiles.map((f) => (
                      <option key={f.id} value={f.id}>{f.filename}</option>
                    ))}
                  </select>
                )}

                {/* Load project button */}
                <button
                  onClick={() => handleLoadProject(project.id)}
                  disabled={project.file_paths.length === 0 || isLoading}
                  className="btn-primary text-xs justify-center disabled:opacity-40"
                  title="Unload all current files and load this project's files"
                >
                  <Download size={13} />
                  {isLoading ? "Loading…" : `Load Project (${project.file_paths.length} file${project.file_paths.length !== 1 ? "s" : ""})`}
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}// Projects
