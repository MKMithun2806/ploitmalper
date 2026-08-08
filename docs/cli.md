# CLI Reference

Full documentation for every `ploit-malper` subcommand.

---

## Command Overview

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
| `exploit <run_id>` | Plan and run exploits from a scan run against an MSF-RPC framework. |
| `setup` | Interactive wizard for MSF-RPC and NVD API configuration. |
| `reset-config` | Wipe all stored credentials and local cache. |

Run `ploit-malper` (or `ploit-malper --help`) for a summary of all commands.

---

## Global Flags

All exploration commands (`assets`, `services`, `findings`, `runs`, `diff`) are read-only and share:

| Flag | Description |
| :--- | :--- |
| `--verbose` / `-v` | Print full record details (IDs, metadata, banners, before/after diffs). |
| `--json` | Emit machine-readable JSON instead of the table view. |
| `--backend pocketbase\|sqlite` | Override the configured backend. |
| `--tui` | Open an interactive terminal viewer (runs, findings). Only on a real terminal; silently ignored in pipes. |

---

## process

```bash
ploit-malper process <file.json>
ploit-malper process results.json --verbose
```

Parse a VulnMalper JSON scan file, deduplicate findings, enrich CVEs from the NVD cache, and produce a Markdown report. This is the legacy single-file pipeline; for bulk imports use `ingest` instead.

---

## db_setup

```bash
ploit-malper db_setup
```

Interactive wizard that lets you choose a backend (PocketBase or SQLite), configure connection details, and create the required collections/tables.

---

## ingest

```bash
ploit-malper ingest <folder>
ploit-malper ingest ./results --process --force
```

Import a folder of Malper scan artifacts (NetMalper, VulnMalper, PloitMalper JSONs) into the intelligence database. Re-importing the same folder is idempotent: records already seen are upserted and only genuine changes emit new observations. Pass `--force` to re-import even when the content hash matches.

| Flag | Description |
| :--- | :--- |
| `-p, --process` | Run every VulnMalper JSON through the PloitMalper pipeline before ingesting. |
| `-f, --force` | Re-import even if the content hash matches a previous import. |
| `--dry-run` | Show what would be imported without writing to the database. |
| `--backend pocketbase\|sqlite\|auto` | Backend selection (default: configured backend). |
| `--pocketbase-url URL` | Override PocketBase instance URL. |
| `--sqlite-path PATH` | Override SQLite database file path. |

---

## assets

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

---

## services

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

---

## findings

```bash
ploit-malper findings
ploit-malper findings --severity critical
ploit-malper findings --cve CVE-2021-44228
ploit-malper findings --fixed --asset 192.168.1.14
ploit-malper findings --tui        # interactive scrollable viewer
```

| Flag | Description |
| :--- | :--- |
| `--severity LEVEL` | `critical`, `high`, `medium`, `low`, or `info`. |
| `--cve ID` | Filter by CVE ID substring. |
| `--asset TERM` | Filter by asset name substring. |
| `--new` | Only findings discovered in the latest run. |
| `--fixed` | Only findings no longer present in the latest run. |
| `--since DATE` | Only findings last seen at or after DATE. |

---

## history

```bash
ploit-malper history 192.168.1.14        # asset by IP
ploit-malper history 192.168.1.14:22     # service by asset:port
ploit-malper history heartbleed          # finding by title
ploit-malper history <id> --verbose      # raw before/after JSON
```

Prints a chronological observation timeline for the given asset, service, or finding. IDs/names are resolved by exact match, unique prefix, or unambiguous substring.

---

## runs

```bash
ploit-malper runs
ploit-malper runs --verbose
ploit-malper runs --tui            # interactive scrollable viewer
```

Lists every scan run with target, start/finish times, artifact count, tools, and per-type record stats (`a:` assets, `s:` services, `f:` findings, `o:` observations).

---

## diff

```bash
ploit-malper diff                 # two most recent runs
ploit-malper diff run_a run_b     # by full/unique-prefix run id or unique target
ploit-malper diff --json
```

Compares the newer run against the older one and reports **added** / **removed** / **changed** records with per-type counts. `--verbose` shows the before/after value diff for every changed record; `--json` emits the full structured diff.

---

## del

```bash
ploit-malper del <run_id>        # prompts for confirmation
ploit-malper del <run_id> --yes  # skip the confirmation prompt
```

Deletes a scan run (matched by full id or unique prefix) together with the observations and exploit executions recorded under it. Assets, services, and findings are shared across runs and are left untouched. Use `ploit-malper runs` to list run ids first.

---

## exploit

```bash
ploit-malper exploit <run_id>             # interactive module picker (on a tty)
ploit-malper exploit <run_id> --dry-run   # preview plan, no execution
ploit-malper exploit <run_id> --yes       # skip prompts, select all modules
ploit-malper exploit <run_id> --module exploit/windows/smb/ms17_010_eternalblue
```

Plans and executes exploits from a scan run against a connected MSF-RPC instance. Steps:

1. Resolves the run by id/unique-prefix, builds a module plan from findings.
2. Connects to MSF-RPC and verifies each planned module exists on the instance (missing modules are marked skipped, auditable).
3. Shows the verified plan and lets you select which modules to run (circular picker on a tty, classic checklist otherwise).
4. Executes each selected step, records job/session/loot/error back to the database.

| Flag | Description |
| :--- | :--- |
| `--dry-run` | Preview the plan without contacting the framework. |
| `--yes` | Skip all prompts; select all modules and accept defaults. |
| `--module NAME` | Only include modules whose name contains NAME. |
| `--target HOST` | Only include steps targeting HOST. |
| `--payload NAME` | Override the payload used for each step. |
| `--workspace NAME` | Use a different MSF workspace than the configured one. |
| `--job-timeout SECS` | Per-step execution timeout (default 300). |
| `--verbose` | Print extra RPC diagnostics. |

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
