import { create } from "zustand";

export type NotificationType = "info" | "warning" | "error";

interface Notification {
  id: string;
  message: string;
  type: NotificationType;
}// Notification

interface NotificationStore {
  notifications: Notification[];
  add: (message: string, type?: NotificationType) => void;
  remove: (id: string) => void;
}// NotificationStore

export const useNotificationStore = create<NotificationStore>((set) => ({
  notifications: [],

  add: (message, type = "info") => {
    const id = Math.random().toString(36).slice(2, 9);
    set((s) => ({ notifications: [...s.notifications, { id, message, type }] }));
    setTimeout(() => {
      set((s) => ({ notifications: s.notifications.filter((n) => n.id !== id) }));
    }, 4500);
  },

  remove: (id) =>
    set((s) => ({ notifications: s.notifications.filter((n) => n.id !== id) })),
}));// useNotificationStore
