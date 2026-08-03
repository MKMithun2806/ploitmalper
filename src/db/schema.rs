use std::process::Command;

use crate::config::{db_schema_file, DatabaseConfig};
use crate::error::{AppError, Result};

/// Canonical PBSL schema shipped with PloitMalper. Written to the config
/// directory so `pbctl` can be pointed at it.
pub const SCHEMA_PBSL: &str = include_str!("../../schema/schema.pbsl");

/// Collection names and their field definitions used for the direct
/// PocketBase REST fallback when `pbctl` is not available.
pub const REQUIRED_COLLECTIONS: [&str; 7] = [
    "Assets",
    "Services",
    "Findings",
    "Observations",
    "Relationships",
    "ScanRuns",
    "Reports",
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
        "Relationships" => &[
            FieldDef {
                name: "stable_id",
                kind: "text",
                required: true,
                unique: true,
            },
            FieldDef {
                name: "run_id",
                kind: "text",
                required: false,
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
                name: "object_type",
                kind: "text",
                required: true,
                unique: false,
            },
            FieldDef {
                name: "object_id",
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
                name: "detail",
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
        "Reports" => &[
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
                name: "tool",
                kind: "text",
                required: true,
                unique: false,
            },
            FieldDef {
                name: "format",
                kind: "text",
                required: true,
                unique: false,
            },
            FieldDef {
                name: "title",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "source_path",
                kind: "text",
                required: false,
                unique: false,
            },
            FieldDef {
                name: "content",
                kind: "text",
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
        ],
        _ => &[],
    }
}

/// Write the canonical PBSL schema into the config directory and return its
/// path.
pub fn write_schema_file() -> Result<std::path::PathBuf> {
    let path = db_schema_file();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, SCHEMA_PBSL)?;
    Ok(path)
}

/// Whether the `pbctl` binary is available on PATH.
pub fn pbctl_available() -> bool {
    Command::new("pbctl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Combined output of an external command.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

impl CommandOutput {
    pub fn combined(&self) -> String {
        let mut out = self.stdout.clone();
        if !self.stderr.trim().is_empty() {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&self.stderr);
        }
        out
    }

    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Build a `pbctl` command with environment overrides so it talks to the
/// configured instance without needing an interactive login.
fn pbctl_command(config: &DatabaseConfig) -> Command {
    let mut command = Command::new("pbctl");
    command
        .env("PBSL_BASE_URL", &config.pocketbase_url)
        .env("PBSL_ADMIN_EMAIL", &config.pocketbase_admin_email)
        .env("PBSL_ADMIN_PASSWORD", &config.pocketbase_admin_password);
    if !config.pocketbase_token.is_empty() {
        command.env("PBSL_TOKEN", &config.pocketbase_token);
    }
    command
}

fn run(command: &mut Command, verbose: bool) -> Result<CommandOutput> {
    let output = command
        .output()
        .map_err(|e| AppError::Network(format!("failed to run pbctl: {e}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if verbose {
        if !stdout.is_empty() {
            println!("{}", stdout);
        }
        if !stderr.is_empty() {
            eprintln!("{}", stderr);
        }
    }
    Ok(CommandOutput {
        stdout,
        stderr,
        exit_code: output.status.code(),
    })
}

/// Run `pbctl plan` against the shipped PBSL schema. Never mutates the
/// remote instance. Returns the full plan output for the caller to display.
pub fn pbctl_plan(config: &DatabaseConfig, verbose: bool) -> Result<CommandOutput> {
    if !pbctl_available() {
        return Err(AppError::Message(
            "pbctl is not installed. Install it with `cargo install pbctl`.".to_string(),
        ));
    }
    let schema_path = write_schema_file()?;
    let mut command = pbctl_command(config);
    command.arg("plan").arg("-f").arg(&schema_path);
    run(&mut command, verbose)
}

/// Run `pbctl apply` against the shipped PBSL schema. Only called after the
/// user has reviewed the plan output from `pbctl_plan`.
pub fn pbctl_apply(config: &DatabaseConfig, verbose: bool) -> Result<CommandOutput> {
    if !pbctl_available() {
        return Err(AppError::Message(
            "pbctl is not installed. Install it with `cargo install pbctl`.".to_string(),
        ));
    }
    let schema_path = write_schema_file()?;
    let mut command = pbctl_command(config);
    command.arg("apply").arg("-f").arg(&schema_path);
    run(&mut command, verbose)
}

/// Run `pbctl validate` to sanity-check the shipped schema file locally.
pub fn pbctl_validate(verbose: bool) -> Result<CommandOutput> {
    if !pbctl_available() {
        return Err(AppError::Message(
            "pbctl is not installed. Install it with `cargo install pbctl`.".to_string(),
        ));
    }
    let schema_path = write_schema_file()?;
    let mut command = Command::new("pbctl");
    command.arg("validate").arg("-f").arg(&schema_path);
    run(&mut command, verbose)
}
