/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        critical: { DEFAULT: "#dc2626", light: "#fee2e2", dark: "#7f1d1d" },
        high:     { DEFAULT: "#f97316", light: "#ffedd5", dark: "#7c2d12" },
        medium:   { DEFAULT: "#eab308", light: "#fef9c3", dark: "#713f12" },
        low:      { DEFAULT: "#22c55e", light: "#dcfce7", dark: "#14532d" },
        info:     { DEFAULT: "#3b82f6", light: "#dbeafe", dark: "#1e3a8a" },
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
  plugins: [],
};
