# PloitMalper

[![Crates.io](https://img.shields.io/crates/v/ploit-malper.svg)](https://crates.io/crates/ploit-malper)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org)
[![CI](https://github.com/MKMithun2806/ploitmalper/actions/workflows/ci.yml/badge.svg)](https://github.com/MKMithun2806/ploitmalper/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/release-manual-blueviolet)](https://github.com/MKMithun2806/ploitmalper/actions/workflows/release.yml)

**PloitMalper** is a high-performance vulnerability post-processing and analysis toolkit written in Rust. It streamlines the transition from raw scan data to actionable exploitation intelligence by deduplicating results, enriching CVE data, and suggesting Metasploit modules. Scan artifacts are stored in a queryable intelligence database (PocketBase or SQLite) with full history tracking and cross-run diffing.

---

## Key Features

- **Intelligent Deduplication**: Uses a specialized Rust engine to normalize and deduplicate findings using composite keys.
- **NVD CVE Enrichment**: Automatically fetches CVSS scores, severities, and descriptions from the NVD API with aggressive local caching.
- **Metasploit Integration**: Connects via MSF-RPC to verify existing hosts in workspaces and match findings to live sessions.
- **Automated Module Suggestions**: Analyzes service banners and titles against an internal expert system to suggest relevant Metasploit modules.
- **Payload Recipe Builder**: Generates ready-to-use `msfvenom` commands for various platforms (Windows, Linux, macOS, etc.).
- **Flexible Reporting**: Produces clean, professional Markdown reports with summary tables and deep-dive findings.
- **Intelligence Database**: Stores assets, services, findings, and observations from Malper scan artifacts in PocketBase or SQLite, with re-ingest deduplication and change tracking.
- **History & Diffing**: Explore per-asset timelines and compare scan runs to see what was newly discovered, removed, or changed.

---

## Prerequisites

PloitMalper leverages system utilities for lightweight HTTP transport:

- **Rust 1.70+**
- **curl**: Used for MSF-RPC and PocketBase communication.
- **Metasploit Framework** (Recommended, for MSF-RPC integration).
- **PocketBase** (Optional, for the remote intelligence database backend).

---

## Installation

### Prebuilt Binaries (Linux, macOS, Windows)

Download the latest release archive for your platform from the [Releases page](https://github.com/MKMithun2806/ploitmalper/releases). Each archive contains a single statically-linked binary.


### Using Cargo (Recommended)

```bash
cargo install ploit-malper
```

### From Source

```bash
git clone https://github.com/MKMithun2806/ploitmalper.git
cd ploitmalper
cargo build --release
cp target/release/ploit-malper /usr/local/bin/
```

---

## 🏁 Quick Start

### 1. Initial Setup
Configure your NVD API key and Metasploit RPC credentials:
```bash
ploit-malper setup
```

### 2. Configure the Intelligence Database
Choose a backend (PocketBase or SQLite) and create the schema:
```bash
ploit-malper db_setup
```

### 3. Ingest Scan Artifacts
Import a Malper scan output folder (NetMalper/VulnMalper/PloitMalper):
```bash
ploit-malper ingest ./results
```

Use `--process` (`-p`) to first run every VulnMalper JSON in the folder through
the PloitMalper pipeline and write a fresh PloitMalper report next to it, so the
intelligence database always ingests the analyzed report (including flagged
injectable endpoints like SQLi):
```bash
ploit-malper ingest ./results --process
```

### 4. Explore and Compare
```bash
ploit-malper assets                 # list assets
ploit-malper findings --severity high
ploit-malper history 192.168.1.14   # asset timeline
ploit-malper diff                   # compare the two most recent runs
```

### 5. Process a Single Scan File (Legacy Pipeline)
Feed in a JSON scan file (e.g., from VulnMalper) to deduplicate and enrich:
```bash
ploit-malper process results.json
```

---

## Command Reference

| Command | Description |
| :--- | :--- |
| `process <file>` | Parse, deduplicate, and enrich scan results. |
| `db_setup` | Configure the intelligence database (PocketBase or SQLite) and create the schema. |
| `ingest <folder>` | Import Malper scan artifacts into the intelligence database (`-p/--process` to pre-process VulnMalper JSONs first). |
| `assets` | List assets with lifecycle state and service summary. |
| `services` | List discovered services across assets. |
| `findings` | List vulnerability findings. |
| `history <id>` | Show the observation timeline for an asset, service, or finding. |
| `runs` | List all recorded scan runs. |
| `diff [run-a] [run-b]` | Compare two scan runs (defaults to the two most recent). |
| `del <run_id>` | Delete a scan run and its observations and exploit executions. |
| `setup` | Interactive wizard for MSF-RPC and NVD API configuration. |
| `reset-config` | Wipe all stored credentials and local cache. |

Run `ploit-malper` (or `ploit-malper --help`) for a summary of all commands.

---

## Intelligence Database

The intelligence database stores normalized records from Malper scan artifacts and tracks how they evolve across re-scans:

| Collection | Contents |
| :--- | :--- |
| **Assets** | Hosts (IP, FQDN, reverse DNS) with lifecycle state. |
| **Services** | Open ports, protocols, banners, products, technologies, CPEs. |
| **Findings** | Vulnerabilities with severity, CVEs, exploitability, tool. |
| **Observations** | Event timeline (`*_discovered`, `*_changed`, `*_removed`) per record. |
| **ScanRuns** | Import metadata per ingested folder: target, timestamps, artifacts, tools. |

Finding report bodies are deduplicated in a content store; findings reference them via `detail_path`. Run `ploit-malper db_setup` to create the schema against your chosen backend.

### Backends

- **PocketBase** (remote): requires a running PocketBase instance and superuser credentials.
- **SQLite** (local): a single database file, no external services.

Frontend commands default to the configured backend and accept `--backend pocketbase|sqlite` to override. `ingest` additionally accepts `--pocketbase-url` and `--sqlite-path` to point at a specific instance.

### Re-ingestion

Re-importing the same folder or re-scanned target is idempotent: records already seen are upserted (no duplicates) and only genuine changes emit new observations. If the raw scan content is byte-identical, ingestion is skipped entirely unless `--force` is passed.

---

## Exploring Results

All exploration commands are read-only. They share three flags:

- `--verbose` / `-v` — print full record details (IDs, metadata, banners, before/after diffs).
- `--json` — emit machine-readable JSON instead of the table view.
- `--backend pocketbase|sqlite` — override the configured backend.

### assets

```bash
ploit-malper assets
ploit-malper assets --new --since 2026-08-01
ploit-malper assets --changed --target 192.168.1
ploit-malper assets --json
```

| Flag | Description |
| :--- | :--- |
| `--new` | Only assets discovered in the latest run. |
| `--changed` | Only assets whose state changed in the latest run. |
| `--since DATE` | Only assets last seen at or after DATE (`YYYY-MM-DD` or RFC3339). |
| `--target TERM` | Filter by substring of name, IP, FQDN, or reverse DNS. |

### services

```bash
ploit-malper services --port 80
ploit-malper services --product nginx --asset 192.168.1.14
ploit-malper services --changed
```

| Flag | Description |
| :--- | :--- |
| `--port N` | Only services on a given TCP port. |
| `--product TERM` | Filter by product, version, or service name substring. |
| `--asset TERM` | Filter by asset name substring. |
| `--changed` | Only services whose state changed in the latest run. |

### findings

```bash
ploit-malper findings
ploit-malper findings --severity critical
ploit-malper findings --cve CVE-2021-44228
ploit-malper findings --fixed --asset 192.168.1.14
```

| Flag | Description |
| :--- | :--- |
| `--severity LEVEL` | `critical`, `high`, `medium`, `low`, or `info`. |
| `--cve ID` | Filter by CVE ID substring. |
| `--asset TERM` | Filter by asset name substring. |
| `--new` | Only findings discovered in the latest run. |
| `--fixed` | Only findings no longer present in the latest run. |
| `--since DATE` | Only findings last seen at or after DATE. |

### history

```bash
ploit-malper history 192.168.1.14        # asset by IP
ploit-malper history 192.168.1.14:22     # service by asset:port
ploit-malper history heartbleed          # finding by title
ploit-malper history <id> --verbose      # raw before/after JSON
```

Prints a chronological observation timeline for the given asset, service, or finding. IDs/names are resolved by exact match, unique prefix, or unambiguous substring.

### runs

```bash
ploit-malper runs
ploit-malper runs --verbose
```

Lists every scan run with target, start/finish times, artifact count, tools, and per-type record stats (`a:` assets, `s:` services, `f:` findings, `o:` observations).

### diff

```bash
ploit-malper diff                 # two most recent runs
ploit-malper diff run_a run_b     # by full/unique-prefix run id or unique target
ploit-malper diff --json
```

Compares the newer run against the older one and reports **added** / **removed** / **changed** records with per-type counts. `--verbose` shows the before/after value diff for every changed record; `--json` emits the full structured diff.

### del

```bash
ploit-malper del <run_id>        # prompts for confirmation
ploit-malper del <run_id> --yes  # skip the confirmation prompt
```

Deletes a scan run (matched by full id or unique prefix) together with the observations and exploit executions recorded under it. Assets, services, and findings are shared across runs and are left untouched. Use `ploit-malper runs` to list run ids first.

---

## Configuration

Configuration and caches are stored in:
- **Linux/macOS**: `~/.config/ploit_malper/`
- **Windows**: `%USERPROFILE%\.config\ploit_malper\`

This includes MSF-RPC/NVD credentials, the database backend settings (PocketBase URL/credentials or SQLite path), and the last scan file path. Use `setup` for credentials and `db_setup` for database settings; `reset-config` wipes everything.
