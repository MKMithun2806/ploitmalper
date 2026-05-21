# PloitMalper

**Vulnerability Post-Processing and Analysis Toolkit**

PloitMalper processes, deduplicates, and organizes vulnerability scan results from VulnMalper. It provides structural analysis, smart matching, NVD CVE enrichment, state tracking, and professional technical reporting.

## Features

- **Advanced Deduplication Engine** — Rust-powered deep deduplication based on composite keys (target + tool + normalized title)
- **NVD CVE Enrichment** — Fetches CVSS v3 scores, severity ratings, descriptions, and references from the National Vulnerability Database API
- **Target Recon & Module Suggestion** — Maps service banners and CVE IDs to Metasploit modules
- **MSF-RPC Integration** — Cross-references target hosts against Metasploit workspace database
- **Persistent State Configuration** — Securely caches MSF-RPC and NVD API credentials
- **Command Recipe Builder** — Generates syntax-valid `msfvenom` reference commands for 6 platforms
- **Rich Terminal Experience** — Color-coded severity tables, progress tracking, and Markdown reporting

## Architecture

| Layer        | Technology          |
|-------------|---------------------|
| Core Engine | Rust (PyO3 + maturin) |
| CLI / UI    | Python + Rich       |
| Build       | uv + maturin        |

## Installation

```bash
uv sync
maturin develop
```

## MSF-RPC Setup

```bash
load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=ploituder Pass=Mithun2806 SSL=false
```

## Usage

```bash
ploit-malper                    # Launch interactive CLI
ploit-malper setup              # Configure MSF-RPC and NVD API credentials
ploit-malper process scan.json  # Process, deduplicate, and enrich scan results
ploit-malper share              # Start temporary file server for reports
ploit-malper reset-config       # Reset all stored credentials and NVD cache
```

## NVD API

Get a free API key at https://nvd.nist.gov/developers/request-an-api-key

Without an API key, the NVD API rate limits to 5 requests/30 seconds. With a key, you get 50 requests/30 seconds.

## Development

```bash
uv run maturin develop --release
cargo test
```

## License

MIT
