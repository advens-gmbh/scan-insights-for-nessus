# Scan Insights for Nessus

Scan Insights for Nessus is a simple tool for displaying data from a Nessus scan file (`.nessus`). It is ideal after an internal (or external) Nessus scan was conducted to display the found vulnerabilities. It offers many filtering and search options, and makes copying the data easier than Nessus does.

It also focuses on privacy. Scan contents stay in memory and are never written to disk, unless you export them. The app only stores its settings, your projects, and your list of recently opened files in the app data folder (`%APPDATA%\com.scaninsights.nessus` on Windows, `~/.local/share/com.scaninsights.nessus` on Linux). Projects and recent files contain the full paths and names of your scan files. On Linux, new files the app creates, including exports, can only be read by your user. The app makes no network connections of its own: it only opens your browser when you click a reference or CVE link.

The app is built with Tauri (Rust), React, TypeScript and Tailwind CSS.

## Installation

Download the file for your system from the [Releases](../../releases) page.

| System | File | Notes |
|---|---|---|
| Windows | `-setup.exe` or `.msi` | Installers |
| Windows | `_portable.exe` | Runs without installing |
| Ubuntu, Debian | `.deb` | Installs its dependencies automatically |
| Fedora | `.rpm` | Installs its dependencies automatically |
| Other Linux | `.AppImage` | Runs without installing, after `chmod +x` |

**Windows:** the app needs the WebView2 Runtime, which is pre-installed on Windows 10 21H2+ and Windows 11. The files aren't signed yet, so SmartScreen may show a warning.

**Linux:** the packages need Ubuntu 24.04, Debian 13, Fedora 40 or newer. If the window stays blank, which is a known WebKitGTK problem on some graphics setups, start the app with `WEBKIT_DISABLE_DMABUF_RENDERER=1 scan-insights-for-nessus`.

## Features

The app has the below main features:
- dark/light mode
- filtering options everywhere (by host, by vulnerability, etc.)
- multiple copy options (copy single or multiple affected hosts with or without ports etc.)
- merge and export
- vulnerability details
- host details
- services overview
- Info findings hidden by default, with one option to show them on every page
- compare scan files
- topology overview

## Info findings

Info findings are mostly noise, so they start hidden on every page and the `Show Info findings` option brings them back. Hosts and services with nothing but Info findings stay listed, because they are still machines and open ports in the scan. `Export` is the exception: it has its own severity selection, which includes Info unless you turn it off.

## Dashboard

The app gives the ability to open one or multiple files at once. After opening a file the `Dashboard` menu gives an overview of the vulnerabilities. A file with no scanned hosts, such as one holding only a scan policy, isn't loaded.

// image

## Vulnerabilities

The `Vulnerabilities` menu offers a more detailed overview of the vulnerabilities. You can sort them by clicking on the appropriate column (Severity, Name, Family, CVSS etc.).

The severity comes from the scan file, and the table shows the CVSS score that fits it, with its version (`9.3 v2`). Nessus only counts a CVSS v2 score of 10.0 as Critical, so a finding rated High with a v2 score of 9.3 is correct. A scan file rarely states which version its severities are based on, so the label describes the score shown. Clicking a vulnerability shows all its scores.

With several files loaded, a finding rated differently between them shows its worst rating and that rating's scores, and its details say which file rated it how. Filtering to one file shows that file's own rating.

// image

Clicking on a vulnerability gives an overview on which hosts the vulnerability is present, and a short description of it.

// image

## Hosts

The `Hosts` menu gives an overview of which host how many vulnerabilities has.  Clicking a host shows what other vulnerabilities are present on that system, and some basic information of the host itself.

// image

## Services

The `Services` menu lists every port and protocol that has at least one finding, with how many hosts have it and how severe its findings are. Clicking one shows those hosts and findings. A port counts as a service only because Nessus reported something on it, so a port with no findings doesn't appear.

## Topology

The `Topology` menu draws the scanned hosts as a graph, grouped by /24 subnet and colored by their worst severity. Clicking a host shows its details.

The graph is inferred from the scan data, so it is not a map of the real network. Solid teal links come from traceroute data (plugin 10287). Dashed links only mean that two subnets appeared in the same scan file. Hosts are matched by IP address alone, so only load files from the same network environment.

## Compare

In the `Compare` menu two scan files can be selected for comparison. This is ideal if you do scans in intervals (e.g. every month or every 3 month etc.). Selecting two files will compare them and inspect which vulnerabilities are resolved, or which vulnerabilities are new, or which persisted. Findings are matched by plugin, host, port and protocol.

A finding only counts as resolved if its host was scanned again without losing credentials. Otherwise it is listed as `Not verified`, because the second scan cannot confirm a fix. A different scan policy can still hide a finding, so compare scans that used the same policy.

// image

## Timeline

The `Timeline` menu displays a trend, how the vulnerabilities have changed between scans.

// image

## Projects

Under the `Projects` menu you can create a "Project". This is basically a group where you can assign multiple files. This is ideal if you want to work with multiple scan files (e.g. analyte the trend of vulnerabilities during quarterly scans). This makes it easier to load the selected files. Loading a project means that all the currently loaded files be unloaded.

// image

## Export

The `Export` menu gives multiple options to export vulnerabilities. You can select to only export vulnerabilities with a specific criticality. The resulting file can be a `.nessus` or `.csv` according to your needs. A `.nessus` export keeps everything the app reads from a scan, but only the targets from the original scan policy. When exporting several files, a host with the same IP becomes one entry and a finding seen in more than one file is kept once, with its worst rating. In a `.csv`, cells that a spreadsheet would run as a formula start with an added `'`.

// image

## Development

If you'd like to help in development install the prerequisites then clone the repository and run the below commands.

**Prerequisites**
- [Rust](https://rustup.rs/) (current stable)
- [Node.js](https://nodejs.org/) (20+)
- Windows: WebView2 Runtime (pre-installed on Windows 10 21H2+ and Windows 11)
- Linux: the libraries Tauri compiles against. On Ubuntu or Debian:
  ```bash
  sudo apt install build-essential curl wget file pkg-config libwebkit2gtk-4.1-dev \
    libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
  ```

**Start developing**
```bash
# install dependencies
npm i
# run in development mode
npm run tauri dev
```

**Checks** (CI runs these on Windows and Ubuntu on every push to `main` and every pull request)
```bash
npm run lint
npm test
npm run build
cd src-tauri
cargo clippy --all-targets -- -D warnings
cargo test
```

The npm `@tauri-apps/*` packages and the Rust `tauri*` crates must stay on the same minor version, so upgrade them together.

**App logo:** replace `src-tauri/icons/icon.svg`, run `npm run icons`, then rebuild. This updates the exe, the window and the sidebar, which all use the PNG and ICO files generated from it. A square SVG with a transparent background works best.

### Building

A build only produces files for the system it runs on, so Linux packages can't be built on Windows or the other way around.

#### App only (simplest)

```bash
npm run tauri build -- --no-bundle
```

The app will be located at `src-tauri/target/release/scan-insights-for-nessus.exe` on Windows and `src-tauri/target/release/scan-insights-for-nessus` on Linux. The Linux file only runs where WebKitGTK is installed. Use this command rather than plain `cargo build --release`, which skips the frontend build and produces an app that looks for the development server.

#### Installers

```bash
npm run tauri build
```

This produces the installers in `src-tauri/target/release/bundle/`: MSI and NSIS on Windows, and `.deb`, `.rpm` and AppImage on Linux. On Ubuntu or Debian, the AppImage also needs the `file`, `xdg-utils` and `libfuse2t64` packages.

PRs are welcome :)
