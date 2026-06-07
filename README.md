# PloitMalper

Vulnerability post-processing and analysis toolkit written entirely in Rust.

## Features

- Deduplicates VulnMalper scan results using a normalized composite key
- Enriches CVEs from the NVD API with local caching
- Suggests Metasploit modules from service banners and titles
- Talks to Metasploit RPC for workspace and host verification
- Generates Markdown reports
- Serves reports over a temporary local file server
- Builds `msfvenom` payload recipes

## Build

```bash
cargo build --release
```

## Run

```bash
cargo run -- process scan.json
cargo run -- setup
cargo run -- share
cargo run -- reset-config
```

## Notes

- The `process` and `share` commands are implemented in Rust.
- Live NVD and MSF-RPC requests use the system `curl` executable for HTTP transport.
- Configuration is stored under `~/.config/ploit_malper/`.

## Development

```bash
cargo test
cargo fmt
```
