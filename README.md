# PloitMalper

**Vulnerability Post-Processing and Analysis Toolkit**

PloitMalper processes, deduplicates, and organizes vulnerability scan results from VulnMalper. It provides structural analysis, smart matching, state tracking, and professional technical reporting.

## Features

- **Advanced Deduplication Engine** — Rust-powered deep deduplication based on composite keys (target + tool + normalized title)
- **Target Recon & Module Suggestion** — Maps service banners and CVE IDs to Metasploit modules
- **Persistent State Configuration** — Securely caches MSF-RPC connectivity details
- **Command Recipe Builder** — Generates syntax-valid `msfvenom` reference commands
- **Rich Terminal Experience** — Beautiful tables, progress tracking, and Markdown reporting

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

## Usage

```bash
ploit-malper                    # Launch interactive CLI
ploit-malper --reset-config     # Reset stored MSF-RPC credentials
ploit-malper share              # Start temporary file server
```

## Development

```bash
uv run maturin develop --release
cargo test
```

## License

MIT
