import plugin from "tailwindcss/plugin";
import { accent, bad, good, ink, severity, warn } from "./src/theme/colors.js";

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
    // one size per role, nothing in between. Tailwind's own sizes (text-sm, text-lg…) are switched off
    fontSize: {
      tiny: "11px",                                  // badges, tags, small labels
      caption: ["12px", { lineHeight: "16px" }],     // captions, column headers, meta
      small: "13px",                                 // secondary text, descriptions
      body: ["14px", { lineHeight: "20px" }],        // body text, table cells, buttons
      heading: "16px",                               // section and card headings
      title: ["20px", { lineHeight: "28px" }],       // page and panel titles
      "figure-sm": ["24px", { lineHeight: "32px" }], // Compare's before → after
      figure: ["30px", { lineHeight: "36px" }],      // the Dashboard numbers
    },
    // corners: 2 tiny marks, 4 tags and bars, 8 controls, 12 cards and panels, full pills and dots
    borderRadius: {
      none: "0",
      sm: "2px",
      DEFAULT: "4px",
      lg: "8px",
      xl: "12px",
      full: "9999px",
    },
    extend: {
      colors: {
        ink,
        accent,
        good,
        warn,
        bad,
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
