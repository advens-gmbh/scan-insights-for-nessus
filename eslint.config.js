import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "src-tauri"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { files: ["scripts/**"], languageOptions: { globals: globals.node } },
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: { globals: globals.browser },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // Recharts' custom tooltip props are untyped in this project.
      "@typescript-eslint/no-explicit-any": "off",
      // `set.has(x) ? set.delete(x) : set.add(x)` is the toggle idiom used throughout.
      "@typescript-eslint/no-unused-expressions": ["error", { allowTernary: true }],
    },
  },
);
