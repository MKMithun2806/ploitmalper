use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub fn now_utc() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| format!("{:?}", std::time::SystemTime::now()))
}

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn stable_id(prefix: &str, key: &str) -> String {
    sha256_hex(&format!("{}:{}", prefix, key))
}

pub const ASSET_ACTIVE: &str = "active";
pub const ASSET_REMOVED: &str = "removed";

/// A scannable target (IP, hostname, or root domain) with lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Asset {
    pub stable_id: String,
    pub asset_type: String,
    pub name: String,
    pub ip: Option<String>,
    pub fqdn: Option<String>,
    pub reverse_dns: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub status: String,
    #[serde(default)]
    pub metadata: Value,
}

impl Asset {
    pub fn new(name: &str, asset_type: &str) -> Self {
        let mut asset = Self {
            stable_id: stable_id("asset", name),
            asset_type: asset_type.to_string(),
            name: name.to_string(),
            ..Default::default()
        };
        asset.metadata = Value::Object(Default::default());
        let now = now_utc();
        asset.first_seen = now.clone();
        asset.last_seen = now;
        asset.status = ASSET_ACTIVE.to_string();
        asset
    }
}

/// A network service discovered on an asset (open port + protocol + product).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Service {
    pub stable_id: String,
    pub asset_id: String,
    pub port: u16,
    pub protocol: String,
    pub service_name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub version_str: Option<String>,
    pub banner: Option<String>,
    #[serde(default)]
    pub technologies: Vec<String>,
    #[serde(default)]
    pub cpes: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub status: String,
    #[serde(default)]
    pub metadata: Value,
}

impl Service {
    pub fn new(asset_id: &str, port: u16, protocol: &str, service_name: &str) -> Self {
        let key = format!("{}:{}:{}:{}", asset_id, port, protocol, service_name);
        let mut service = Self {
            stable_id: stable_id("service", &key),
            asset_id: asset_id.to_string(),
            port,
            protocol: protocol.to_string(),
            service_name: service_name.to_string(),
            ..Default::default()
        };
        service.metadata = Value::Object(Default::default());
        let now = now_utc();
        service.first_seen = now.clone();
        service.last_seen = now;
        service.status = ASSET_ACTIVE.to_string();
        service
    }
}

/// A vulnerability / security finding on an asset with exploitability tracking.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Finding {
    pub stable_id: String,
    pub asset_id: String,
    pub service_id: Option<String>,
    pub title: String,
    pub severity: String,
    pub tool: String,
    pub target_url: Option<String>,
    /// Short excerpt kept in the database; full evidence lives in a file
    /// referenced by `detail_path`.
    pub detail: Option<String>,
    /// Relative path into the content store holding the full detail/evidence.
    pub detail_path: Option<String>,
    pub reference: Option<String>,
    #[serde(default)]
    pub cves: Vec<String>,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub technologies: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub status: String,
    pub exploitability: Option<String>,
    #[serde(default)]
    pub metadata: Value,
}

impl Finding {
    /// Build a finding with a stable identity.
    ///
    /// The identity key deliberately folds only scanner *framing* differences
    /// (surrounding whitespace, repeated/pipe-separated delimiters) so that the
    /// same logical finding never forks into two database rows across scans.
    /// Case and spelling are left untouched so previously imported rows keep
    /// their existing stable_id (backward compatibility).
    pub fn new(asset_id: &str, tool: &str, title: &str) -> Self {
        let key = format!("{}:{}:{}", asset_id, tool, stable_title_identity(title));
        let mut finding = Self {
            stable_id: stable_id("finding", &key),
            asset_id: asset_id.to_string(),
            tool: tool.to_string(),
            title: title.to_string(),
            ..Default::default()
        };
        finding.metadata = Value::Object(Default::default());
        let now = now_utc();
        finding.first_seen = now.clone();
        finding.last_seen = now;
        finding.status = ASSET_ACTIVE.to_string();
        finding
    }
}

/// Collapse scanner framing around a finding title for identity purposes:
/// surrounding whitespace, consecutive delimiters (`|`, `/`, `:`), and any
/// stray pipe-separated empty fields. Content and case are preserved.
fn stable_title_identity(title: &str) -> String {
    let collapsed = title.split_whitespace().collect::<Vec<_>>().join(" ");
    let parts: Vec<&str> = collapsed
        .split('|')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    let joined = parts.join("|");
    joined
        .trim_end_matches(|c: char| ".,:;\\/|".contains(c))
        .trim()
        .to_string()
}

/// A historical observation recording how intelligence changed across runs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Observation {
    pub stable_id: String,
    pub run_id: String,
    pub subject_type: String,
    pub subject_id: String,
    pub kind: String,
    #[serde(default)]
    pub before: Value,
    #[serde(default)]
    pub after: Value,
    pub detail: String,
    pub observed_at: String,
}

impl Observation {
    pub fn new(
        run_id: &str,
        subject_type: &str,
        subject_id: &str,
        kind: &str,
        before: Value,
        after: Value,
        detail: &str,
    ) -> Self {
        let before_s = before.to_string();
        let after_s = after.to_string();
        let key = format!(
            "{}:{}:{}:{}:{}:{}",
            run_id, subject_type, subject_id, kind, before_s, after_s
        );
        Self {
            stable_id: stable_id("observation", &key),
            run_id: run_id.to_string(),
            subject_type: subject_type.to_string(),
            subject_id: subject_id.to_string(),
            kind: kind.to_string(),
            before,
            after,
            detail: detail.to_string(),
            observed_at: now_utc(),
        }
    }
}

/// Metadata describing one logical scan run over a target.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanRun {
    pub stable_id: String,
    pub target: String,
    pub folder: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub artifacts: Vec<Value>,
    pub content_hash: String,
    pub imported_at: String,
    #[serde(default)]
    pub stats: Value,
}

impl ScanRun {
    pub fn new(
        run_id: &str,
        target: &str,
        folder: &str,
        content_hash: &str,
        started_at: Option<String>,
    ) -> Self {
        Self {
            stable_id: run_id.to_string(),
            target: target.to_string(),
            folder: folder.to_string(),
            started_at,
            finished_at: None,
            content_hash: content_hash.to_string(),
            imported_at: now_utc(),
            stats: Value::Object(Default::default()),
            ..Default::default()
        }
    }
}

/// A single recorded module execution against a target. History is append-only
/// so that every attempt — including dry runs, skipped steps, and failures —
/// is preserved alongside the run it was planned from.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExploitExecution {
    pub execution_id: String,
    pub run_id: String,
    pub asset_id: String,
    pub vulnerability_id: String,
    pub module_type: String,
    pub module: String,
    pub host: String,
    pub payload: Option<String>,
    pub status: String,
    pub start_time: String,
    pub finish_time: Option<String>,
    pub job_id: Option<String>,
    pub session_id: Option<String>,
    pub error: Option<String>,
    #[serde(default)]
    pub loot: Vec<String>,
    #[serde(default)]
    pub options: BTreeMap<String, String>,
    /// Whether the operator selected this step in the checklist.
    pub selected: bool,
    pub created_at: String,
}

impl ExploitExecution {
    pub fn new(run_id: &str, asset_id: &str, vulnerability_id: &str, module: &str) -> Self {
        let key = format!("{}:{}:{}:{}", run_id, asset_id, vulnerability_id, module);
        let now = now_utc();
        Self {
            execution_id: sha256_hex(&format!("exploit_exec:{}:{}", key, now)),
            run_id: run_id.to_string(),
            asset_id: asset_id.to_string(),
            vulnerability_id: vulnerability_id.to_string(),
            module: module.to_string(),
            module_type: String::new(),
            host: String::new(),
            payload: None,
            status: String::new(),
            start_time: now.clone(),
            finish_time: None,
            job_id: None,
            session_id: None,
            error: None,
            loot: Vec::new(),
            options: BTreeMap::new(),
            selected: false,
            created_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_identity_is_stable_across_framing() {
        let a = Finding::new("asset", "nmap", "Apache Version /");
        let b = Finding::new("asset", "nmap", "Apache Version | ");
        assert_eq!(a.stable_id, b.stable_id);
        let c = Finding::new("asset", "nmap", "Apache Version");
        assert_eq!(a.stable_id, c.stable_id);
    }

    #[test]
    fn finding_identity_keeps_distinct_titles_separate() {
        let a = Finding::new("asset", "nmap", "Apache 2.4");
        let b = Finding::new("asset", "nmap", "Apache 2.2");
        assert_ne!(a.stable_id, b.stable_id);
    }

    #[test]
    fn finding_identity_is_scoped_by_tool_and_asset() {
        let a = Finding::new("asset", "nmap", "Apache");
        let b = Finding::new("asset", "nikto", "Apache");
        let c = Finding::new("asset2", "nmap", "Apache");
        assert_ne!(a.stable_id, b.stable_id);
        assert_ne!(a.stable_id, c.stable_id);
    }
}
