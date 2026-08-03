# PloitMalper Intelligence Database & Exploration

This document describes the intelligence database layer and the read-only exploration
commands. It is the authoritative reference for `db_setup`, `ingest`, and the six
frontend commands (`assets`, `services`, `findings`, `history`, `runs`, `diff`).

## Architecture

```
Malper scan artifacts
   (netmalper graph, vulnmalper json/markdown, ploitmalper output)
                |
                v
   +----------------------------+
   |  ingest <folder>           |
   |  (src/ingest/importer)     |
   +----------------------------+
                |
                v
   +----------------------------+     +---------------------------+
   |  Storage trait             |---->| PocketBaseStorage (remote) |
   |  (src/db/mod.rs)           |     +---------------------------+
   +----------------------------+     | SqliteStorage (local)     |
        | assets / services /          +---------------------------+
        | findings / observations /
        | scan_runs / content store
        v
   +----------------------------+
   |  frontend commands         |
   |  (src/frontend/*.rs)       |
   +----------------------------+
```

The frontend reads exclusively through the `Storage` trait, so every command works
identically against either backend.

## Collections

Five collections hold normalized records. Records are content-addressed: `stable_id`
is a hash of the record's normalized content, so re-ingesting an unchanged record
upserts in place instead of creating duplicates.

### Assets

| Field | Notes |
| :--- | :--- |
| `stable_id` | content hash |
| `name` | display name (IP or URL) |
| `asset_type` | `ip` |
| `ip` / `fqdn` / `reverse_dns` | identity fields (nullable) |
| `metadata` | JSON blob (endpoints, etc.) |
| `status` | `active` / `removed` |
| `first_seen` / `last_seen` | RFC3339 timestamps |
| `scan_run_ids` | runs that observed this asset |

### Services

| Field | Notes |
| :--- | :--- |
| `stable_id` | content hash |
| `asset_id` | parent asset |
| `port` / `protocol` | e.g. `22` / `tcp` |
| `service_name` | e.g. `ssh` |
| `product` / `version` / `version_str` | banner parsing (nullable) |
| `banner` | raw banner text |
| `technologies` / `cpes` | arrays |
| `status` / `first_seen` / `last_seen` | lifecycle + timing |

### Findings

| Field | Notes |
| :--- | :--- |
| `stable_id` | content hash |
| `asset_id` / `service_id` | parents |
| `title` / `severity` | severity: critical/high/medium/low/info |
| `cves` | array of CVE IDs |
| `target_url` / `reference` / `exploitability` | contextual detail |
| `tool` | producing scanner |
| `detail_path` | path into the content store (bulk report body) |
| `status` / `first_seen` / `last_seen` | lifecycle + timing |

### Observations

Immutable event log. One row per recorded change:

| Field | Notes |
| :--- | :--- |
| `stable_id` | content hash |
| `run_id` | originating scan run |
| `subject_type` / `subject_id` | which record changed |
| `kind` | `*_discovered`, `*_changed`, `*_removed` |
| `detail` | human-readable description |
| `before` / `after` | JSON snapshots for diffs |
| `observed_at` | RFC3339 |

### ScanRuns

| Field | Notes |
| :--- | :--- |
| `stable_id` | `run_<hash>` |
| `target` | primary target |
| `folder` | ingested folder |
| `started` / `finished` / `imported_at` | timestamps |
| `content_hash` | hash of all raw artifact content |
| `artifact_kinds` / `tools` | arrays |
| `artifacts` | per-artifact records (kind, path, hash, size, content_path) |

Bulk report bodies live in the **content store** (keyed by content hash); findings and
artifacts reference them via `detail_path` / `content_path`.

## Backends

### PocketBase

Configured via `db_setup`. Requires a reachable instance and superuser credentials.
The client authenticates once, caches the token, verifies it before each command, and
auto-re-authenticates from stored credentials when the token has expired. All listing
endpoints paginate (500 records per page).

### SQLite

Configured via `db_setup` with a file path. No external dependencies. Useful for
offline work and CI.

### Overrides

Every command honours `--backend pocketbase|sqlite`. `ingest` also accepts
`--pocketbase-url` and `--sqlite-path` to target a specific instance without
rewriting the saved config.

## Idempotent Ingestion

`ingest <folder>` scans the folder for Malper artifacts and derives records:

1. **Content hash** — the raw artifact bytes are hashed. If the scan run already
   exists with an identical `content_hash`, ingestion is skipped (unless `--force`).
2. **Upsert** — existing assets/services/findings are updated in place; new ones are
   inserted.
3. **Observations** — only genuine state transitions emit rows:
   - new record → `*_discovered` (before: none, after: record)
   - changed fields → `*_changed` (before/after JSON snapshots)
   - no longer seen → `*_removed`
4. A **ScanRun** row records the import metadata (target, timestamps, artifacts, tools).

`--dry-run` reports what would change without touching the database.

## Exploration Commands

All commands are read-only. Shared flags:

| Flag | Effect |
| :--- | :--- |
| `--verbose` / `-v` | Full record detail (IDs, metadata, banners, before/after). |
| `--json` | Machine-readable JSON output. |
| `--backend pocketbase\|sqlite` | Override the configured backend. |
| `--help` / `-h` | Print the command usage. |

If no database is configured, commands fail with a pointer to `db_setup`. Empty
results print `No X found.`.

### assets

```
ploit-malper assets [--new] [--changed] [--since DATE] [--target TERM]
                    [--verbose] [--json] [--backend pocketbase|sqlite]
```

- `--new` / `--changed` — filter on the asset's state change in the latest run.
- `--since DATE` — only assets with `last_seen >= DATE` (`YYYY-MM-DD`, RFC3339,
  space-separated importer timestamps, or unix epoch seconds).
- `--target TERM` — case-insensitive substring over name / IP / FQDN / reverse DNS.

Columns: NAME, TYPE, SERVICES (sorted port list), FIRST SEEN, LAST SEEN, CHANGE.
`--verbose` adds `ip`, `fqdn`, `reverse_dns`, `status`, `metadata`, and the last
observation (`kind` + timestamp).

### services

```
ploit-malper services [--port N] [--product TERM] [--asset TERM] [--changed]
                      [--verbose] [--json] [--backend pocketbase|sqlite]
```

- `--port N` — exact TCP port.
- `--product TERM` — substring over product, version, version_str, or service name.
- `--asset TERM` — substring over the owning asset's name.
- `--changed` — only services whose state changed in the latest run.

Columns: ASSET, PORT, PROTO, SERVICE, PRODUCT/VERSION, FIRST SEEN, LAST SEEN, CHANGE.
`--verbose` adds technologies, CPEs, and the raw banner.

### findings

```
ploit-malper findings [--severity LEVEL] [--cve ID] [--asset TERM] [--new]
                      [--fixed] [--since DATE]
                      [--verbose] [--json] [--backend pocketbase|sqlite]
```

- `--severity LEVEL` — `critical` | `high` | `medium` | `low` | `info`.
- `--cve ID` — substring over CVEs or title.
- `--asset TERM` — substring over the owning asset's name.
- `--new` — only findings newly discovered in the latest run.
- `--fixed` — only findings no longer present in the latest run.
- `--since DATE` — only findings with `last_seen >= DATE`.

Rows are sorted by severity rank then title. Columns: SEVERITY, TITLE (+ CVEs),
ASSET, PORT, FIRST SEEN, LAST SEEN, CHANGE. `--verbose` adds tool, exploitability,
target_url, reference, and detail (truncated).

### history

```
ploit-malper history <id-or-name> [--verbose] [--json]
                                   [--backend pocketbase|sqlite]
```

Resolves the subject against assets (exact id/name/IP/FQDN/reverse-DNS, unique
prefix, or unambiguous substring), services (`asset:port`, e.g. `192.168.1.14:22`),
and findings (exact title or substring). Prints a chronological timeline:

WHEN | RUN | KIND | DETAIL

`--verbose` prints the before/after JSON snapshots per observation; `--json` emits
the raw observation list.

### runs

```
ploit-malper runs [--verbose] [--json] [--backend pocketbase|sqlite]
```

Columns: RUN ID, TARGET, STARTED, FINISHED, ARTIFACTS, TOOLS, STATS. Stats are
per-type record counts of the form `a:N/s:N/f:N/o:N` (assets/services/findings/
observations). `--verbose` prints folder, imported_at, content_hash, and each
artifact record.

### diff

```
ploit-malper diff [run-a] [run-b] [--verbose] [--json]
                  [--backend pocketbase|sqlite]
```

Compares two scan runs (default: the two most recent by `imported_at`, older as
`run-a`, newer as `run-b`). Run ids are resolved by full id, unique id prefix, or
unique target name.

Output sections:

- **Added** — records with `*_discovered` observations in `run-b`.
- **Removed** — records with `*_removed` observations in `run-b`.
- **Changed** — records with `*_changed` observations in `run-b`.

Each section renders a TYPE/SUBJECT/KIND/WHEN table plus per-type counts. `--verbose`
adds the before/after value diff per record. `--json` emits `run_a`, `run_b`,
`content_changed`, a summary, and the full added/removed/changed deltas.

## Reference: model fields

- **Asset**: `stable_id`, `name`, `asset_type`, `ip`, `fqdn`, `reverse_dns`,
  `metadata`, `status`, `first_seen`, `last_seen`, `scan_run_ids`.
- **Service**: `stable_id`, `asset_id`, `port`, `protocol`, `service_name`,
  `product`, `version`, `version_str`, `banner`, `technologies`, `cpes`, `status`,
  `first_seen`, `last_seen`.
- **Finding**: `stable_id`, `asset_id`, `service_id`, `title`, `severity`, `cves`,
  `target_url`, `reference`, `exploitability`, `tool`, `detail_path`, `status`,
  `first_seen`, `last_seen`.
- **Observation**: `stable_id`, `run_id`, `subject_type`, `subject_id`, `kind`,
  `detail`, `before`, `after`, `observed_at`.
- **ScanRun**: `stable_id`, `target`, `folder`, `started`, `finished`, `imported_at`,
  `content_hash`, `artifact_kinds`, `tools`, `artifacts`.
