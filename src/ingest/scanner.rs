use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::db::models::sha256_hex;

/// Maximum size (bytes) a single artifact file may be. Anything larger is
/// rejected as unlikely to be a Malper scan artifact.
pub const MAX_ARTIFACT_SIZE: u64 = 16 * 1024 * 1024;

/// The recognised Malper artifact kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    NetMalperGraph,
    VulnMalperJson,
    VulnMalperMarkdown,
    PloitMalperReport,
    /// A `Malper analyse` report: recognised but intentionally ignored.
    MalperAnalyse,
}

impl ArtifactKind {
    pub fn label(&self) -> &'static str {
        match self {
            ArtifactKind::NetMalperGraph => "netmalper graph",
            ArtifactKind::VulnMalperJson => "vulnmalper json",
            ArtifactKind::VulnMalperMarkdown => "vulnmalper markdown",
            ArtifactKind::PloitMalperReport => "ploitmalper report",
            ArtifactKind::MalperAnalyse => "malper analyse report",
        }
    }
}

/// An accepted scan artifact.
#[derive(Debug, Clone)]
pub struct Artifact {
    pub kind: ArtifactKind,
    pub path: PathBuf,
    pub content: String,
    pub size: u64,
    pub hash: String,
}

/// A file that was scanned and rejected, with the reason.
#[derive(Debug, Clone)]
pub struct RejectedFile {
    pub path: PathBuf,
    pub reason: String,
}

/// The outcome of scanning a folder.
#[derive(Debug, Default)]
pub struct ScanResult {
    pub artifacts: Vec<Artifact>,
    pub rejected: Vec<RejectedFile>,
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Detect the artifact kind from content only. `None` means the file is not a
/// recognised Malper artifact and should be rejected.
pub fn detect_kind(content: &str) -> Option<ArtifactKind> {
    if content.trim().is_empty() {
        return None;
    }

    // Try JSON first.
    if let Ok(value) = serde_json::from_str::<Value>(content) {
        return detect_json(&value);
    }

    // Non-JSON: markdown report detection from content markers.
    if content.contains("# PloitMalper - Vulnerability Analysis Report") {
        return Some(ArtifactKind::PloitMalperReport);
    }
    if content.contains("VulnMalper Report") {
        return Some(ArtifactKind::VulnMalperMarkdown);
    }
    if content.contains("Malper Analyse Report") || content.contains("Malper Analysis Report") {
        return Some(ArtifactKind::MalperAnalyse);
    }

    None
}

fn detect_json(value: &Value) -> Option<ArtifactKind> {
    let object = value.as_object()?;

    // NetMalper graph: meta + nodes + edges.
    let has_meta = object
        .get("meta")
        .and_then(Value::as_object)
        .and_then(|m| m.get("target"))
        .and_then(Value::as_str)
        .map(|t| !t.is_empty())
        .unwrap_or(false);
    let has_nodes = object.get("nodes").and_then(Value::as_array).is_some();
    let has_edges = object.get("edges").and_then(Value::as_array).is_some();
    if has_meta && has_nodes && has_edges {
        return Some(ArtifactKind::NetMalperGraph);
    }

    // VulnMalper export: vulnmalper metadata + findings or hosts.
    let has_vulnmeta = object
        .get("vulnmalper")
        .and_then(Value::as_object)
        .map(|m| m.contains_key("version") || m.contains_key("source_target"))
        .unwrap_or(false);
    let has_findings = object.get("findings").and_then(Value::as_array).is_some();
    let has_hosts = object.get("hosts").and_then(Value::as_array).is_some();
    if has_vulnmeta && (has_findings || has_hosts) {
        return Some(ArtifactKind::VulnMalperJson);
    }

    // Unknown JSON with a run_id marker but no structural match.
    None
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// Recursively scan `root` and classify every file. Never relies on file
/// names alone — detection is content based.
pub fn scan_folder(root: &Path, verbose: bool) -> crate::error::Result<ScanResult> {
    if !root.exists() {
        return Err(crate::error::AppError::Message(format!(
            "scan folder does not exist: {}",
            root.display()
        )));
    }
    if !root.is_dir() {
        return Err(crate::error::AppError::Message(format!(
            "ingest path is not a directory: {}",
            root.display()
        )));
    }

    let mut result = ScanResult::default();
    walk(root, &mut result, verbose)?;

    if verbose {
        println!(
            "[dbg] scan complete: {} artifact(s), {} rejected file(s)",
            result.artifacts.len(),
            result.rejected.len()
        );
    }
    Ok(result)
}

fn walk(dir: &Path, result: &mut ScanResult, verbose: bool) -> crate::error::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            walk(&path, result, verbose)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        process_file(&path, result, verbose);
    }
    Ok(())
}

fn process_file(path: &Path, result: &mut ScanResult, verbose: bool) {
    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            result.rejected.push(RejectedFile {
                path: path.to_path_buf(),
                reason: format!("unreadable metadata: {e}"),
            });
            return;
        }
    };

    if metadata.len() == 0 {
        result.rejected.push(RejectedFile {
            path: path.to_path_buf(),
            reason: "empty file".to_string(),
        });
        return;
    }
    if metadata.len() > MAX_ARTIFACT_SIZE {
        result.rejected.push(RejectedFile {
            path: path.to_path_buf(),
            reason: format!(
                "file too large ({} bytes) to be a Malper artifact",
                metadata.len()
            ),
        });
        return;
    }

    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            result.rejected.push(RejectedFile {
                path: path.to_path_buf(),
                reason: format!("unreadable: {e}"),
            });
            return;
        }
    };

    let content = match std::str::from_utf8(&bytes) {
        Ok(s) => s.to_string(),
        Err(_) => {
            result.rejected.push(RejectedFile {
                path: path.to_path_buf(),
                reason: "binary or non-UTF-8 file".to_string(),
            });
            return;
        }
    };

    match detect_kind(&content) {
        Some(kind) => {
            let hash = sha256_hex(&content);
            if verbose {
                println!(
                    "[dbg] detected {} -> {} ({} bytes)",
                    path.display(),
                    kind.label(),
                    metadata.len()
                );
            }
            result.artifacts.push(Artifact {
                kind,
                path: path.to_path_buf(),
                content,
                size: metadata.len(),
                hash,
            });
        }
        None => {
            let reason = if content.starts_with('{') || content.starts_with('[') {
                "JSON content does not match any known Malper artifact"
            } else {
                "text file is not a recognized Malper artifact"
            };
            if verbose {
                println!("[dbg] rejected {} -> {}", path.display(), reason);
            }
            result.rejected.push(RejectedFile {
                path: path.to_path_buf(),
                reason: reason.to_string(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETMALPER: &str = r#"{
        "meta": {"target": "192.168.1.14", "timestamp": "2026-08-01T07:39:22Z", "version": "8.0.0"},
        "nodes": [{"id": "ip:192.168.1.14", "type": "ip", "data": {"ip": "192.168.1.14"}}],
        "edges": [{"source": "ip:192.168.1.14", "target": "ip:192.168.1.14", "label": "x"}]
    }"#;

    const VULN_JSON: &str = r#"{
        "vulnmalper": {"version": "8.0.0", "source_target": "192.168.1.14"},
        "findings": [{"tool": "nikto", "severity": "low", "title": "x"}]
    }"#;

    #[test]
    fn detects_netmalper_json() {
        assert_eq!(detect_kind(NETMALPER), Some(ArtifactKind::NetMalperGraph));
    }

    #[test]
    fn detects_vulnmalper_json() {
        assert_eq!(detect_kind(VULN_JSON), Some(ArtifactKind::VulnMalperJson));
    }

    #[test]
    fn rejects_unrelated_json() {
        assert_eq!(detect_kind(r#"{"hello": "world"}"#), None);
        assert_eq!(detect_kind("[1,2,3]"), None);
    }

    #[test]
    fn detects_markdown_reports() {
        assert_eq!(
            detect_kind("# 🛡️  VulnMalper Report\n\n> **Target:** `x`"),
            Some(ArtifactKind::VulnMalperMarkdown)
        );
        assert_eq!(
            detect_kind("# PloitMalper - Vulnerability Analysis Report\n\n## Executive Summary"),
            Some(ArtifactKind::PloitMalperReport)
        );
    }

    #[test]
    fn rejects_random_markdown_and_binary() {
        assert_eq!(detect_kind("# Random Notes\n\nhello world"), None);
        assert_eq!(detect_kind("plain text log line"), None);
    }

    #[test]
    fn name_is_never_used_for_detection() {
        // A file named like an artifact but with unrelated content is rejected.
        let content = r#"{"anything": "else"}"#;
        assert_eq!(detect_kind(content), None);
    }
}
