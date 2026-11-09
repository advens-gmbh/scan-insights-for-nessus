import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import type { Project, ProjectFilePath } from "../types/nessus";

function newId(): string {
  return typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}// newId

interface ProjectStore {
  projects: Project[];
  load: () => Promise<void>;
  save: (projects: Project[]) => Promise<void>;
  createProject: (name: string, files?: ProjectFilePath[]) => void;
  deleteProject: (id: string) => void;
  renameProject: (id: string, name: string) => void;
  addFileToProject: (projectId: string, file: ProjectFilePath) => void;
  removeFileFromProject: (projectId: string, filePath: string) => void;
}// ProjectStore

export const useProjectStore = create<ProjectStore>((set, get) => ({
  projects: [],

  load: async () => {
    try {
      const projects = await invoke<Project[]>("load_projects");
      // Ensure file_paths exists
      const migrated = projects.map((p) => ({ ...p, file_paths: p.file_paths ?? [] }));
      set({ projects: migrated });
    } catch {
      // first run
    }
  },

  save: async (projects: Project[]) => {
    set({ projects });
    try {
      await invoke("save_projects", { projects });
    } catch {
      // ignore
    }
  },

  createProject: (name, files = []) => {
    const project: Project = {
      id: newId(),
      name,
      description: null,
      file_ids: [],
      file_paths: files,
      created_at: new Date().toISOString(),
    };
    const updated = [...get().projects, project];
    get().save(updated);
  },

  deleteProject: (id) => {
    const updated = get().projects.filter((p) => p.id !== id);
    get().save(updated);
  },

  renameProject: (id, name) => {
    const updated = get().projects.map((p) => (p.id === id ? { ...p, name } : p));
    get().save(updated);
  },

  addFileToProject: (projectId, file) => {
    const updated = get().projects.map((p) =>
      p.id === projectId && !p.file_paths.some((fp) => fp.path === file.path)
        ? { ...p, file_paths: [...p.file_paths, file] }
        : p
    );
    get().save(updated);
  },

  removeFileFromProject: (projectId, filePath) => {
    const updated = get().projects.map((p) =>
      p.id === projectId
        ? { ...p, file_paths: p.file_paths.filter((fp) => fp.path !== filePath) }
        : p
    );
    get().save(updated);
  },
}));// useProjectStore
