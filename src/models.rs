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
    /// Original finding description (never discarded, used for traceability).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// Original finding reference link (never discarded).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reference: String,
    /// Every CVE id discovered in title/detail/reference/raw (deduplicated).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cves: Vec<String>,
    /// Normalized representation used for deduplication.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub normalized_title: String,
    /// Original raw finding titles merged into this record (traceability).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw_findings: Vec<String>,
    /// Number of scanner findings merged into this record (1 = unique).
    #[serde(default)]
    pub merged_count: usize,
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
    pub nvd_weaknesses: Vec<String>,
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
    pub weaknesses: Vec<String>,
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
    /// Intelligence family the records collapsed into (e.g. "Missing Security Headers").
    pub family: String,
    /// Specific sub-items for the family (e.g. the individual missing headers).
    pub details: Vec<String>,
    /// Original scanner evidence lines (raw findings) for traceability.
    pub evidence: Vec<String>,
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

/// An endpoint flagged by the scanner as a potential injection point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectableEndpoint {
    /// Affected host (e.g. the host URL or IP the scanner associated it with).
    pub target: String,
    /// The injectable endpoint itself (URL including query parameters).
    pub endpoint: String,
}

/// Parsed VulnMalper scan: normalized findings plus injectable endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParsedScan {
    pub records: Vec<ScanRecord>,
    pub injectable_endpoints: Vec<InjectableEndpoint>,
}

/// A Metasploit module recommendation with exploit-intelligence metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSFModule {
    pub name: String,
    /// CVE this module maps to, if any.
    pub cve: Option<String>,
    /// Rank: excellent / great / good / normal / average / low / manual.
    pub rank: String,
    /// Disclosure date (YYYY-MM-DD) or unknown.
    pub disclosure_date: String,
    /// Supported platforms.
    pub platforms: Vec<String>,
    /// Required options the operator must fill in.
    pub required_options: Vec<String>,
}

/// Why no Metasploit module is available for a given CVE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSFNoModuleReason {
    pub cve: String,
    pub reason: String,
}

/// Exploitability assessment derived from evidence in the scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitabilityInfo {
    /// Overall rating: Informational / Low / Moderate / High / Very High.
    pub rating: String,
    /// Numeric 0-100.
    pub score: u32,
    /// CVEs with known public exploits or KEV listing.
    pub exploitable_cves: Vec<String>,
    /// Injectable endpoint count.
    pub injectable_count: usize,
    /// Human-readable evidence trail.
    pub reasons: Vec<String>,
}
