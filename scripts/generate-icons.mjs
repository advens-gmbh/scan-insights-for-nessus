// Regenerates the app icons from src-tauri/icons/icon.svg. Run with: npm run icons
// `tauri icon` also creates Android, iOS and Store sizes this Windows app doesn't use,
// so it writes to a temporary folder and only the files in tauri.conf.json are kept.
import { execSync } from "node:child_process";
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ICONS = "src-tauri/icons";
const USED = ["32x32.png", "128x128.png", "128x128@2x.png", "icon.ico"];

const out = mkdtempSync(join(tmpdir(), "tauri-icons-"));
try {
  execSync(`npx tauri icon "${ICONS}/icon.svg" -o "${out}"`, { stdio: ["ignore", "ignore", "inherit"] });
  for (const file of USED) {
    copyFileSync(join(out, file), join(ICONS, file));
    console.log(`updated ${ICONS}/${file}`);
  }
} finally {
  rmSync(out, { recursive: true, force: true });
}
