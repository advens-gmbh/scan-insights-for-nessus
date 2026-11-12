// Every colour in the app comes from here: Tailwind (tailwind.config.js) and the charts both read this file.
// After changing it, restart `npm run tauri dev` so Tailwind picks it up.

// blue-grey neutrals (Tailwind: ink-50 … ink-950)
export const ink = {
  50: "#f4f6f9",
  100: "#eaeef3",
  200: "#dde2ea",
  300: "#c3cbd6",
  400: "#9aa5b3",
  500: "#65707f",
  600: "#535e6e",
  700: "#3b4555",
  800: "#2b3441",
  900: "#222a35",
  950: "#1b222c",
};

// links, buttons, selection (Tailwind: accent-50 … accent-950)
export const accent = {
  50: "#eafafe",
  100: "#cff5fc",
  200: "#a1ebf8",
  300: "#71e1f4",
  400: "#3dd3ea",
  500: "#00b6cc",
  600: "#00808f",
  700: "#00717f",
  800: "#005864",
  900: "#01434c",
  950: "#022c33",
};

// fill: bars, badges, charts; on: text on the fill; fg: coloured text on the page, per theme
export const severity = {
  critical: { fill: "#c81e48", on: "#ffffff", fg: { light: "#b8173f", dark: "#ff6f8e" } },
  high:     { fill: "#f25857", on: "#ffffff", fg: { light: "#c8302f", dark: "#ff7d7b" } },
  medium:   { fill: "#fb9d59", on: "#1d2530", fg: { light: "#b0520a", dark: "#ffae70" } },
  low:      { fill: "#fbd655", on: "#1d2530", fg: { light: "#8a6a00", dark: "#ffdc63" } },
  info:     { fill: "#4690c6", on: "#ffffff", fg: { light: "#2c6aa1", dark: "#76b6ea" } },
};

// status, not severity: good = fixed or better (Tailwind: good-50 … good-950),
// warn = needs a look, bad = failed. The same shades as Tailwind's emerald, amber and red.
export const good = {
  50: "#ecfdf5", 100: "#d1fae5", 200: "#a7f3d0", 300: "#6ee7b7", 400: "#34d399", 500: "#10b981",
  600: "#059669", 700: "#047857", 800: "#065f46", 900: "#064e3b", 950: "#022c22",
};
export const warn = {
  50: "#fffbeb", 100: "#fef3c7", 200: "#fde68a", 300: "#fcd34d", 400: "#fbbf24", 500: "#f59e0b",
  600: "#d97706", 700: "#b45309", 800: "#92400e", 900: "#78350f", 950: "#451a03",
};
export const bad = {
  50: "#fef2f2", 100: "#fee2e2", 200: "#fecaca", 300: "#fca5a5", 400: "#f87171", 500: "#ef4444",
  600: "#dc2626", 700: "#b91c1c", 800: "#991b1b", 900: "#7f1d1d", 950: "#450a0a",
};
