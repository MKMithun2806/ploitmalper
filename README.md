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
- **Interactive TUI**: Terminal-native module picker (circular selector with arrow keys and space toggles) and scrollable table viewers for runs and findings.
- **Payload Recipe Builder**: Generates ready-to-use `msfvenom` commands for various platforms (Windows, Linux, macOS, etc.).
- **Flexible Reporting**: Produces clean, professional Markdown reports with summary tables and deep-dive findings.
- **Intelligence Database**: Stores assets, services, findings, and observations from Malper scan artifacts in PocketBase or SQLite, with re-ingest deduplication and change tracking.
- **History & Diffing**: Explore per-asset timelines and compare scan runs to see what was newly discovered, removed, or changed.

---

## Prerequisites

- **Rust 1.70+**
- **Metasploit Framework** (Recommended, for MSF-RPC integration).
- **PocketBase** (Optional, for the remote intelligence database backend).

All HTTP/TLS is handled natively via `rustls`; no curl or OpenSSL installation required.

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

## Quick Start

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

Use `--process` (`-p`) to first run every VulnMalper JSON in the folder through the PloitMalper pipeline and write a fresh PloitMalper report next to it:

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

## Documentation

For the full CLI reference — every subcommand, flag, and the intelligence database schema — see **[docs/cli.md](docs/cli.md)**.

---

## Configuration

Configuration and caches are stored in:
- **Linux/macOS**: `~/.config/ploit_malper/`
- **Windows**: `%USERPROFILE%\.config\ploit_malper\`

This includes MSF-RPC/NVD credentials, the database backend settings (PocketBase URL/credentials or SQLite path), and the last scan file path. Use `setup` for credentials and `db_setup` for database settings; `reset-config` wipes everything.
