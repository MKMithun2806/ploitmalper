use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanRecord {
    pub target: String,
    pub tool: String,
    pub title: String,
    pub severity: String,
    pub port: Option<u16>,
    pub cve: Option<String>,
    pub service: Option<String>,
    pub raw: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvd_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvd_cvss_v3: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvd_cvss_v3_severity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvd_cvss_v2: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvd_published: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvd_last_modified: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nvd_references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupResult {
    pub unique_count: usize,
    pub removed_count: usize,
    pub records: Vec<ScanRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupStats {
    pub total: usize,
    pub unique: usize,
    pub removed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleSuggestion {
    pub service_banner: String,
    pub suggested_module: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadRecipe {
    pub platform: String,
    pub architecture: String,
    pub lhost: String,
    pub lport: u16,
    pub format: String,
    pub output_path: String,
    pub encoder: Option<String>,
    pub iterations: Option<u32>,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NVDCVEInfo {
    pub cve_id: String,
    pub description: String,
    pub cvss_v3_score: Option<f32>,
    pub cvss_v3_severity: Option<String>,
    pub cvss_v2_score: Option<f32>,
    pub published: String,
    pub last_modified: String,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSFWorkspaceInfo {
    pub name: String,
    pub scope: String,
    pub host_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSFHostInfo {
    pub address: String,
    pub os_name: String,
    pub os_flavor: String,
    pub state: String,
    pub notes_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSFLoginResult {
    pub success: bool,
    pub token: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSFWorkspacesResult {
    pub workspaces: Vec<MSFWorkspaceInfo>,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSFHostsResult {
    pub hosts: Vec<MSFHostInfo>,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSFHostCheckResult {
    pub exists: bool,
    pub error: String,
}

/// A vulnerability grouped across multiple affected endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingGroup {
    pub title: String,
    pub severity: String,
    pub count: usize,
    pub target: String,
    pub affected_endpoints: Vec<String>,
    pub cves: Vec<String>,
    pub ports: Vec<String>,
    pub tools: Vec<String>,
}

/// High-level executive summary of a scan.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanSummary {
    pub host: String,
    pub server: Option<String>,
    pub framework: Option<String>,
    pub severity_counts: BTreeMap<String, usize>,
    pub top_risks: Vec<String>,
}

/// Weighted overall risk score with a rendered bar and justification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub score: u32,
    pub bar: String,
    pub reasons: Vec<String>,
}

/// Metasploit suggestions grouped by purpose.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModuleCategories {
    pub enumeration: Vec<ModuleSuggestion>,
    pub validation: Vec<ModuleSuggestion>,
    pub exploitation: Vec<ModuleSuggestion>,
    pub manual_notes: Vec<String>,
}

/// A single MITRE ATT&CK tactic with matching techniques and evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTactic {
    pub tactic: String,
    pub techniques: Vec<String>,
    pub findings: Vec<String>,
}

/// Additional CVE intelligence beyond raw NVD data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CVEExtraInfo {
    pub epss: Option<f32>,
    pub in_kev: bool,
    pub public_exploit: bool,
    pub metasploit_modules: Vec<String>,
}
