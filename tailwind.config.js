import plugin from "tailwindcss/plugin";
import { accent, ink, severity } from "./src/theme/colors.js";

const levels = Object.keys(severity);

// bg-critical (fill), text-critical-on (text on the fill), text-critical-fg (coloured text, follows the theme)
const severityColors = Object.fromEntries(
  levels.map((k) => [k, { DEFAULT: severity[k].fill, on: severity[k].on, fg: `var(--sev-${k}-fg)` }])
);

const severityVariables = plugin(({ addBase }) => {
  addBase({
    ":root": Object.fromEntries(levels.map((k) => [`--sev-${k}-fg`, severity[k].fg.light])),
    ".dark": Object.fromEntries(levels.map((k) => [`--sev-${k}-fg`, severity[k].fg.dark])),
  });
});

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        ink,
        accent,
        ...severityColors,
      },
      fontFamily: {
        sans: ["Inter Variable", "system-ui", "sans-serif"],
      },
      animation: {
        "slide-in-right": "slideInRight 0.25s ease-out",
        "fade-in": "fadeIn 0.15s ease-out",
      },
      keyframes: {
        slideInRight: {
          from: { transform: "translateX(100%)", opacity: "0" },
          to:   { transform: "translateX(0)",    opacity: "1" },
        },
        fadeIn: {
          from: { opacity: "0" },
          to:   { opacity: "1" },
        },
      },
    },
  },
  plugins: [severityVariables],
};
