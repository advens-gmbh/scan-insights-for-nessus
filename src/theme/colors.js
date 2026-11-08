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
