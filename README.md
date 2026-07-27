# PloitMalper

[![Crates.io](https://img.shields.io/crates/v/ploit-malper.svg)](https://crates.io/crates/ploit-malper)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org)
[![CI](https://github.com/MKMithun2806/ploitmalper/actions/workflows/ci.yml/badge.svg)](https://github.com/MKMithun2806/ploitmalper/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/release-manual-blueviolet)](https://github.com/MKMithun2806/ploitmalper/actions/workflows/release.yml)

**PloitMalper** is a high-performance vulnerability post-processing and analysis toolkit written in Rust. It streamlines the transition from raw scan data to actionable exploitation intelligence by deduplicating results, enriching CVE data, and suggesting Metasploit modules.

---

## Key Features

- **Intelligent Deduplication**: Uses a specialized Rust engine to normalize and deduplicate findings using composite keys.
- **NVD CVE Enrichment**: Automatically fetches CVSS scores, severities, and descriptions from the NVD API with aggressive local caching.
- **Metasploit Integration**: Connects via MSF-RPC to verify existing hosts in workspaces and match findings to live sessions.
- **Automated Module Suggestions**: Analyzes service banners and titles against an internal expert system to suggest relevant Metasploit modules.
- **Payload Recipe Builder**: Generates ready-to-use `msfvenom` commands for various platforms (Windows, Linux, macOS, etc.).
- **Flexible Reporting**: Produces clean, professional Markdown reports with summary tables and deep-dive findings.
- **Instant Sharing**: Includes a built-in temporary file server to share reports across a network instantly.

---

## Prerequisites

PloitMalper leverages system utilities for lightweight HTTP transport:

- **Rust 1.70+**
- **curl**: Used for NVD API and MSF-RPC communication.
- **Metasploit Framework** (Recommended, for MSF-RPC integration).

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

### 2. Process Scan Results
Feed in a JSON scan file (e.g., from VulnMalper) to deduplicate and enrich:
```bash
ploit-malper process results.json
```

### 3. Share Your Report
Host the generated `report.md` on a temporary local server:
```bash
ploit-malper share --port 8888
```

---

## Command Reference

| Command | Description |
| :--- | :--- |
| `process <file>` | Parse, deduplicate, and enrich scan results. |
| `setup` | Interactive wizard for MSF-RPC and NVD API configuration. |
| `share` | Start a temporary web server to serve reports (`-p` for port, `-d` for dir). |
| `reset-config` | Wipe all stored credentials and local cache. |

---

## Configuration

Configuration and caches are stored in:
- **Linux/macOS**: `~/.config/ploit_malper/`
- **Windows**: `%USERPROFILE%\.config\ploit_malper\`

