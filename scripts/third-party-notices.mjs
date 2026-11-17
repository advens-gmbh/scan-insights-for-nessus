// Writes THIRD-PARTY-NOTICES.txt: the licenses and copyright notices of every library the app ships.
// The window's libraries come from node_modules, the Rust crates from cargo's registry, as cargo metadata lists them.
//
//   npm run notices
import { execFileSync, execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const LICENSE_FILE = /^(licen[sc]e|copying|notice)([-._].*)?$/i;

// the same license text is printed once, with every package that uses it
const groups = new Map(); // text -> { license, packages: Set }
function add(text, license, pkg) {
  const key = text.trim().replace(/\r\n/g, "\n");
  if (!groups.has(key)) {
    groups.set(key, { license, packages: new Set() });
  }
  groups.get(key).packages.add(pkg);
}

// ── the window's libraries: what npm installs without the development tools ──
const tree = JSON.parse(execSync("npm ls --omit=dev --all --long --json", { cwd: root, maxBuffer: 1 << 28 }).toString());
const npm = new Map();
(function walk(deps) {
  for (const [name, d] of Object.entries(deps ?? {})) {
    if (d.path && !npm.has(`${name}@${d.version}`)) {
      npm.set(`${name}@${d.version}`, d.path);
      walk(d.dependencies);
    }
  }
})(tree.dependencies);
for (const [pkg, dir] of npm) {
  const meta = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  const license = typeof meta.license === "string" ? meta.license : (meta.licenses ?? []).map((l) => l.type ?? l).join(" OR ") || "unknown";
  const files = fs.readdirSync(dir).filter((f) => LICENSE_FILE.test(f) && fs.statSync(path.join(dir, f)).isFile());
  if (files.length === 0) {
    add(`${license} (the package has no license file)`, license, pkg);
  }
  for (const f of files) {
    add(fs.readFileSync(path.join(dir, f), "utf8"), license, pkg);
  }
}

// ── the Rust crates compiled into the app for Windows and Linux: normal dependencies only, no build or development tools ──
const crates = new Map(); // name@version -> package
for (const target of ["x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu"]) {
  const meta = JSON.parse(execFileSync("cargo", ["metadata", "--format-version", "1", "--locked", "--filter-platform", target],
    { cwd: path.join(root, "src-tauri"), maxBuffer: 1 << 28 }).toString());
  const packages = new Map(meta.packages.map((p) => [p.id, p]));
  const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
  const todo = [meta.resolve.root];
  const seen = new Set(todo);
  while (todo.length) {
    for (const dep of nodes.get(todo.pop()).deps) {
      if (dep.dep_kinds.some((k) => k.kind === null) && !seen.has(dep.pkg)) {
        seen.add(dep.pkg);
        todo.push(dep.pkg);
      }
    }
  }
  seen.delete(meta.resolve.root);
  for (const id of seen) {
    const p = packages.get(id);
    crates.set(`${p.name}@${p.version}`, p);
  }
}
for (const [name, p] of crates) {
  const dir = path.dirname(p.manifest_path);
  const license = p.license ?? "unknown";
  const files = new Set(fs.readdirSync(dir).filter((f) => LICENSE_FILE.test(f) && fs.statSync(path.join(dir, f)).isFile()).map((f) => path.join(dir, f)));
  if (p.license_file) {
    files.add(path.resolve(dir, p.license_file));
  }
  if (files.size === 0) {
    const authors = p.authors?.length ? `\nAuthors: ${p.authors.join(", ")}` : "";
    add(`${license} (the crate has no license file)${authors}`, license, name);
  }
  for (const f of files) {
    add(fs.readFileSync(f, "utf8"), license, name);
  }
}

// ── the file ──
const rule = "=".repeat(78);
const parts = [
  "Scan Insights for Nessus - third-party software",
  "",
  "The app includes the open source libraries listed below. Each section names the",
  "packages and gives the license text and copyright notice they come with.",
  `${npm.size} npm packages and ${crates.size} Rust crates.`,
  "",
];
const sorted = [...groups.entries()].sort((a, b) => a[1].license.localeCompare(b[1].license) || [...a[1].packages][0].localeCompare([...b[1].packages][0]));
for (const [text, { license, packages }] of sorted) {
  parts.push(rule, `${license}: ${[...packages].sort().join(", ")}`, rule, "", text, "");
}
fs.writeFileSync(path.join(root, "THIRD-PARTY-NOTICES.txt"), parts.join("\n"), "utf8");
console.log(`THIRD-PARTY-NOTICES.txt: ${npm.size} npm packages, ${crates.size} crates, ${groups.size} license texts`);
