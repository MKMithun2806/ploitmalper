use crate::config::db_schema_file;
use crate::error::Result;

/// Canonical PBSL schema shipped with PloitMalper. Written to the config
/// directory so `pbctl` can be pointed at it.
pub const SCHEMA_PBSL: &str = include_str!("../../schema/schema.pbsl");

/// Collection names and their field definitions used by the direct
/// PocketBase REST path.
pub const REQUIRED_COLLECTIONS: [&str; 6] = [
    "Assets",
    "Services",
    "Findings",
    "Observations",
    "ScanRuns",
    "ExploitExecutions",
];

pub struct FieldDef {
    pub name: &'static str,
    pub kind: &'static str,
    pub required: bool,
    pub unique: bool,
}

pub fn field_defs(collection: &str) -> &'static [FieldDef] {
    match collection {
        "Assets" => &[
            FieldDef {
                name: "stable_id",
                kind: "text",
                required: true,
                unique: true,
            },
            FieldDef {
                name: "asset_type",
                kind: "select",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "name",
                kind: "text",
                required: true,
                unique: false,
            },
            FieldDef {
                name: "ip",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "fqdn",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "reverse_dns",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "first_seen",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "last_seen",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "status",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "metadata",
                kind: "json",
                required: false,
                unique: false,
            },
        ],
        "Services" => &[
            FieldDef {
                name: "stable_id",
                kind: "text",
                required: true,
                unique: true,
            },
            FieldDef {
                name: "asset_id",
                kind: "text",
                required: true,
                unique: false,
            },
            FieldDef {
                name: "port",
                kind: "number",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "protocol",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "service_name",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "product",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "version",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "version_str",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "banner",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "technologies",
                kind: "json",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "cpes",
                kind: "json",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "first_seen",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "last_seen",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "status",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "metadata",
                kind: "json",
                required: false,
                unique: false,
            },
        ],
        "Findings" => &[
            FieldDef {
                name: "stable_id",
                kind: "text",
                required: true,
                unique: true,
            },
            FieldDef {
                name: "asset_id",
                kind: "text",
                required: true,
                unique: false,
            },
            FieldDef {
                name: "service_id",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "title",
                kind: "text",
                required: true,
                unique: false,
            },
            FieldDef {
                name: "severity",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "tool",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "target_url",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "detail",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "detail_path",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "reference",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "cves",
                kind: "json",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "endpoints",
                kind: "json",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "technologies",
                kind: "json",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "first_seen",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "last_seen",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "status",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "exploitability",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "metadata",
                kind: "json",
                required: false,
                unique: false,
            },
        ],
        "Observations" => &[
            FieldDef {
                name: "stable_id",
                kind: "text",
                required: true,
                unique: true,
            },
            FieldDef {
                name: "run_id",
                kind: "text",
                required: true,
                unique: false,
            },
            FieldDef {
                name: "subject_type",
                kind: "text",
                required: true,
                unique: false,
            },
            FieldDef {
                name: "subject_id",
                kind: "text",
                required: true,
                unique: false,
            },
            FieldDef {
                name: "kind",
                kind: "text",
                required: true,
                unique: false,
            },
            FieldDef {
                name: "before",
                kind: "json",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "after",
                kind: "json",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "detail",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "observed_at",
                kind: "text",
                required: false,
                unique: false,
            },
        ],
        "ScanRuns" => &[
            FieldDef {
                name: "stable_id",
                kind: "text",
                required: true,
                unique: true,
            },
            FieldDef {
                name: "target",
                kind: "text",
                required: true,
                unique: false,
            },
            FieldDef {
                name: "folder",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "started_at",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "finished_at",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "tools",
                kind: "json",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "artifacts",
                kind: "json",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "content_hash",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "imported_at",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "stats",
                kind: "json",
                required: false,
                unique: false,
            },
        ],
        "ExploitExecutions" => &[
            FieldDef {
                name: "execution_id",
                kind: "text",
                required: true,
                unique: true,
            },
            FieldDef {
                name: "run_id",
                kind: "text",
                required: true,
                unique: false,
            },
            FieldDef {
                name: "asset_id",
                kind: "text",
                required: true,
                unique: false,
            },
            FieldDef {
                name: "vulnerability_id",
                kind: "text",
                required: true,
                unique: false,
            },
            FieldDef {
                name: "module_type",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "module",
                kind: "text",
                required: true,
                unique: false,
            },
            FieldDef {
                name: "host",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "payload",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "status",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "start_time",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "finish_time",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "job_id",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "session_id",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "error",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "loot",
                kind: "json",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "options",
                kind: "json",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "selected",
                kind: "bool",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "created_at",
                kind: "text",
                required: false,
                unique: false,
            },
        ],
        _ => &[],
    }
}

/// Write the canonical PBSL schema into the config directory and return its
/// path. This file documents the intended schema; the actual schema is
/// created directly via the PocketBase REST API (no pbctl required).
pub fn write_schema_file() -> Result<std::path::PathBuf> {
    let path = db_schema_file();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, SCHEMA_PBSL)?;
    Ok(path)
}
