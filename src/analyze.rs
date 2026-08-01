use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde_json::Value;

use crate::models::{
    FindingGroup, MitreTactic, ModuleCategories, ModuleSuggestion, RiskScore, ScanRecord,
    ScanSummary,
};

const SEVERITY_RANK: &[&str] = &["critical", "high", "medium", "low", "info", "unknown"];

pub fn severity_rank(severity: &str) -> usize {
    let severity = severity.to_lowercase();
    SEVERITY_RANK
        .iter()
        .position(|candidate| *candidate == severity)
        .unwrap_or(SEVERITY_RANK.len() - 1)
}

pub fn severity_counts(records: &[ScanRecord]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for record in records {
        let severity = record.severity.to_lowercase();
        *counts.entry(severity).or_insert(0) += 1;
    }
    counts
}

// ---------------------------------------------------------------------------
// Endpoint extraction
// ---------------------------------------------------------------------------

fn normalize_endpoint(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let path = match trimmed.split_once("://") {
        Some((_, rest)) => match rest.find('/') {
            Some(idx) => &rest[idx..],
            None => "/",
        },
        None => trimmed,
    };
    let path = path.trim().trim_end_matches(|c: char| c.is_whitespace());
    if path.is_empty() {
        Some("/".to_string())
    } else {
        Some(path.to_string())
    }
}

fn endpoint_from_raw(raw: &Value) -> Option<String> {
    for key in [
        "url",
        "endpoint",
        "uri",
        "location",
        "request_url",
        "url_path",
        "full_url",
        "request_uri",
        "vuln_url",
        "absolute_url",
    ] {
        if let Some(value) = raw.get(key).and_then(Value::as_str) {
            if let Some(endpoint) = normalize_endpoint(value) {
                return Some(endpoint);
            }
        }
    }

    for key in ["raw", "data", "details", "result", "vuln_data"] {
        if let Some(nested) = raw.get(key) {
            if let Some(endpoint) = endpoint_from_raw(nested) {
                return Some(endpoint);
            }
        }
    }

    for key in ["urls", "endpoints", "paths"] {
        if let Some(arr) = raw.get(key).and_then(Value::as_array) {
            for value in arr {
                if let Some(endpoint) = value.as_str().and_then(normalize_endpoint) {
                    return Some(endpoint);
                }
            }
        }
    }

    let path = raw
        .get("path")
        .and_then(Value::as_str)
        .or_else(|| raw.get("url_path").and_then(Value::as_str));
    if let Some(path) = path {
        let mut endpoint = path.to_string();
        if let Some(query) = raw
            .get("query_string")
            .and_then(Value::as_str)
            .or_else(|| raw.get("query").and_then(Value::as_str))
            .or_else(|| raw.get("params").and_then(Value::as_str))
        {
            let query = query.trim();
            if !query.is_empty() {
                endpoint.push('?');
                endpoint.push_str(query);
            }
        }
        if let Some(normalized) = normalize_endpoint(&endpoint) {
            return Some(normalized);
        }
    }

    None
}

fn endpoint_from_title(title: &str) -> Option<String> {
    let re = Regex::new(r"(?:https?://[^\s/]+)?(/[^\s>]+)").expect("valid regex");
    for captures in re.captures_iter(title) {
        if let Some(value) = captures.get(1) {
            if let Some(endpoint) = normalize_endpoint(value.as_str()) {
                return Some(endpoint);
            }
        }
    }
    None
}

/// Extract a normalized endpoint (path + query) from a record if possible.
pub fn extract_endpoint(record: &ScanRecord) -> Option<String> {
    if let Some(endpoint) = endpoint_from_raw(&record.raw) {
        return Some(endpoint);
    }
    if let Some(endpoint) = endpoint_from_title(&record.title) {
        return Some(endpoint);
    }
    None
}

// ---------------------------------------------------------------------------
// Smart grouping
// ---------------------------------------------------------------------------

fn vuln_type_title(title: &str) -> String {
    let cleaned = title.trim().to_lowercase();
    let cleaned = cleaned
        .strip_prefix("vulnerability: ")
        .or_else(|| cleaned.strip_prefix("vulnerability "))
        .or_else(|| cleaned.strip_prefix("found: "))
        .or_else(|| cleaned.strip_prefix("found "))
        .or_else(|| cleaned.strip_prefix("possible "))
        .unwrap_or(&cleaned)
        .trim()
        .to_string();

    for separator in [" on ", " in ", " at ", " via ", " - ", ": ", " - "] {
        if let Some((head, _)) = cleaned.split_once(separator) {
            let head = head.trim();
            if !head.is_empty() && head.chars().count() > 1 {
                return head.to_string();
            }
        }
    }

    cleaned
}

pub fn display_title(title: &str) -> String {
    format_type_title(&vuln_type_title(title))
}

const ACRONYMS: &[&str] = &[
    "ldap", "sql", "xss", "iis", "api", "http", "https", "xxe", "csrf", "ftp", "smtp", "dns",
    "tls", "ssl", "rce", "lfi", "rfi", "xml", "url", "php", "asp", "os", "json", "csp", "hsts",
    "xpath", "html", "css", "js", "db", "id", "ui",
];

fn format_type_title(lowercased: &str) -> String {
    lowercased
        .split(|c: char| c.is_whitespace() || c == '_')
        .filter(|segment| !segment.is_empty())
        .map(|word| {
            if word.starts_with("cve-") || ACRONYMS.contains(&word) {
                word.to_uppercase()
            } else {
                let mut chars = word.chars();
                match chars.next() {
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                    None => String::new(),
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Group records by (target, normalized vulnerability) and merge locations.
pub fn group_findings(records: &[ScanRecord]) -> Vec<FindingGroup> {
    let mut groups: BTreeMap<(String, String), FindingGroup> = BTreeMap::new();

    for record in records {
        let title = display_title(&record.title);
        let key = (record.target.clone(), title.clone());
        let entry = groups.entry(key).or_insert_with(|| FindingGroup {
            title: title.clone(),
            severity: record.severity.to_lowercase(),
            count: 0,
            target: record.target.clone(),
            affected_endpoints: record.affected_endpoints.clone(),
            cves: Vec::new(),
            ports: Vec::new(),
            tools: Vec::new(),
        });

        entry.count += 1;
        if severity_rank(&record.severity) < severity_rank(&entry.severity) {
            entry.severity = record.severity.to_lowercase();
        }
        if let Some(endpoint) = extract_endpoint(record) {
            if !entry.affected_endpoints.contains(&endpoint) {
                entry.affected_endpoints.push(endpoint);
            }
        }
        if let Some(cve) = record.cve.as_ref() {
            if !entry.cves.contains(cve) {
                entry.cves.push(cve.clone());
            }
        }
        if let Some(port) = record.port {
            let port_str = port.to_string();
            if !entry.ports.contains(&port_str) {
                entry.ports.push(port_str);
            }
        }
        if !entry.tools.contains(&record.tool) {
            entry.tools.push(record.tool.clone());
        }
    }

    let mut groups = groups.into_values().collect::<Vec<_>>();
    groups.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then(b.count.cmp(&a.count))
            .then(a.title.cmp(&b.title))
    });
    groups
}

// ---------------------------------------------------------------------------
// Server / framework inference
// ---------------------------------------------------------------------------

fn banner_texts(records: &[ScanRecord]) -> Vec<String> {
    let mut texts = Vec::new();
    for record in records {
        if let Some(service) = record.service.as_ref() {
            texts.push(service.clone());
        }
        texts.push(record.title.clone());
        for key in [
            "server",
            "banner",
            "software",
            "product",
            "version",
            "http_server",
            "app",
            "technology",
        ] {
            if let Some(value) = record.raw.get(key).and_then(Value::as_str) {
                texts.push(value.to_string());
            }
        }
    }
    texts
}

fn server_label(name: &str, texts: &[String], keywords: &[&str]) -> Option<String> {
    let version_re = Regex::new(r"\d+(?:\.\d+){0,3}").expect("valid regex");
    for text in texts {
        let lower = text.to_lowercase();
        if keywords.iter().any(|keyword| lower.contains(keyword)) {
            if let Some(capture) = version_re.captures(text) {
                return Some(format!("{} {}", name, &capture[0]));
            }
            return Some(name.to_string());
        }
    }
    None
}

pub fn infer_server(records: &[ScanRecord]) -> Option<String> {
    let texts = banner_texts(records);
    if let Some(label) = server_label("Microsoft IIS", &texts, &["microsoft-iis", "iis"]) {
        return Some(label);
    }
    if let Some(label) = server_label("Apache", &texts, &["apache"]) {
        return Some(label);
    }
    if let Some(label) = server_label("Nginx", &texts, &["nginx"]) {
        return Some(label);
    }
    if let Some(label) = server_label("Tomcat", &texts, &["tomcat"]) {
        return Some(label);
    }
    if let Some(label) = server_label("Jetty", &texts, &["jetty"]) {
        return Some(label);
    }
    None
}

pub fn infer_framework(records: &[ScanRecord]) -> Option<String> {
    let texts = banner_texts(records);
    for text in &texts {
        let lower = text.to_lowercase();
        if lower.contains("asp.net") || lower.contains("aspx") || lower.contains(".net core") {
            return Some("ASP.NET".to_string());
        }
        if lower.contains("php") {
            return Some("PHP".to_string());
        }
        if lower.contains("spring") || lower.contains("struts") || lower.contains("java ee") {
            return Some("Java".to_string());
        }
        if lower.contains("node.js") || lower.contains("express") {
            return Some("Node.js".to_string());
        }
        if lower.contains("django") || lower.contains("flask") {
            return Some("Python".to_string());
        }
        if lower.contains("rails") || lower.contains("ruby on rails") {
            return Some("Ruby on Rails".to_string());
        }
        if lower.contains("wordpress") {
            return Some("WordPress".to_string());
        }
        if lower.contains("drupal") {
            return Some("Drupal".to_string());
        }
        if lower.contains("iis") {
            return Some("ASP.NET".to_string());
        }
    }
    None
}

pub fn build_scan_summary(records: &[ScanRecord]) -> ScanSummary {
    let host = records
        .first()
        .map(|record| record.target.clone())
        .unwrap_or_else(|| "N/A".to_string());

    let mut top_risks = detect_vuln_kinds(records);
    let mut sorted = records.to_vec();
    sorted.sort_by_key(|record| severity_rank(&record.severity));
    for record in sorted {
        if record.severity.to_lowercase() == "info" {
            continue;
        }
        let title = display_title(&record.title);
        if !title.is_empty()
            && !top_risks
                .iter()
                .any(|risk| risk.eq_ignore_ascii_case(&title))
            && !top_risks
                .iter()
                .any(|risk| risk.to_lowercase().contains(&title.to_lowercase()))
        {
            top_risks.push(title);
        }
    }

    ScanSummary {
        host,
        server: infer_server(records),
        framework: infer_framework(records),
        severity_counts: severity_counts(records),
        top_risks,
    }
}

// ---------------------------------------------------------------------------
// Vulnerability detection
// ---------------------------------------------------------------------------

const VULN_KEYWORDS: &[(&str, &[&str])] = &[
    ("SQL Injection", &["sql injection", "sqli", "sql_injection"]),
    ("LDAP Injection", &["ldap injection", "ldap_injection"]),
    (
        "Command Injection",
        &[
            "command injection",
            "remote code execution",
            " rce",
            "os injection",
        ],
    ),
    (
        "XSS",
        &[
            "cross-site scripting",
            " xss",
            "reflected xss",
            "stored xss",
        ],
    ),
    (
        "Path Traversal",
        &[
            "path traversal",
            "directory traversal",
            "local file inclusion",
            "remote file inclusion",
            " lfi",
            " rfi",
        ],
    ),
    (
        "File Upload",
        &["file upload", "arbitrary file upload", "upload bypass"],
    ),
    ("XXE", &["xml external entity", " xxe"]),
    (
        "Weak Credentials",
        &[
            "weak password",
            "default password",
            "weak credential",
            "brute force",
            "weak authentication",
        ],
    ),
    (
        "Information Disclosure",
        &[
            "information disclosure",
            "info disclosure",
            "directory listing",
            "sensitive data",
            "verbose error",
            "trace.axd",
            "debug page",
        ],
    ),
    (
        "Missing Security Headers",
        &[
            "missing security header",
            "missing header",
            "clickjacking",
            "x-frame-options",
            "hsts",
            "content-security-policy",
            "security header",
        ],
    ),
    ("Open Redirect", &["open redirect", "unvalidated redirect"]),
    ("CSRF", &["csrf", "cross-site request forgery"]),
    (
        "Deserialization",
        &["deserialization", "insecure deserialization"],
    ),
    (
        "SSL/TLS Weakness",
        &[
            "ssl",
            "tls",
            "weak cipher",
            "obsolete protocol",
            "heartbleed",
            "poodle",
        ],
    ),
];

pub fn detect_vuln_kinds(records: &[ScanRecord]) -> Vec<String> {
    let mut kinds = Vec::new();
    let mut seen = BTreeSet::new();
    for record in records {
        let text = format!(
            "{} {}",
            record.title.to_lowercase(),
            raw_text(&record.raw).to_lowercase()
        );
        for (name, keywords) in VULN_KEYWORDS {
            if !seen.contains(*name) && keywords.iter().any(|keyword| text.contains(keyword)) {
                seen.insert(*name);
                kinds.push((*name).to_string());
            }
        }
    }
    kinds
}

fn raw_text(raw: &Value) -> String {
    match raw {
        Value::String(value) => value.clone(),
        Value::Object(map) => map
            .values()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>()
            .join(" "),
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Risk score
// ---------------------------------------------------------------------------

pub fn compute_risk_score(records: &[ScanRecord]) -> RiskScore {
    let counts = severity_counts(records);
    let mut score: u32 = 0;
    score += counts.get("critical").copied().unwrap_or(0) as u32 * 10;
    score += counts.get("high").copied().unwrap_or(0) as u32 * 7;
    score += counts.get("medium").copied().unwrap_or(0) as u32 * 4;
    score += counts.get("low").copied().unwrap_or(0) as u32;
    score = score.min(100);

    let filled = (score / 10) as usize;
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(10 - filled));

    let mut reasons = Vec::new();
    for kind in detect_vuln_kinds(records).iter().take(3) {
        reasons.push(kind.clone());
    }
    let injection_kinds = reasons
        .iter()
        .filter(|reason| {
            ["SQL Injection", "LDAP Injection", "Command Injection"].contains(&reason.as_str())
        })
        .count();
    if injection_kinds > 1 {
        reasons.push("Multiple injection points".to_string());
    }
    if records.len() >= 5 {
        reasons.push(format!("{} findings to review", records.len()));
    }
    if reasons.is_empty() {
        reasons.push("No critical or high severity findings".to_string());
    }

    RiskScore {
        score,
        bar,
        reasons,
    }
}

// ---------------------------------------------------------------------------
// Metasploit module categorization
// ---------------------------------------------------------------------------

pub fn categorize_modules(suggestions: &[ModuleSuggestion]) -> ModuleCategories {
    let mut categories = ModuleCategories::default();
    let mut best: BTreeMap<String, ModuleSuggestion> = BTreeMap::new();
    for suggestion in suggestions {
        let key = suggestion.suggested_module.clone();
        let entry = best.entry(key).or_insert_with(|| suggestion.clone());
        if confidence_rank(&suggestion.confidence) > confidence_rank(&entry.confidence) {
            *entry = suggestion.clone();
        }
    }
    for suggestion in best.values() {
        match classify_module(&suggestion.suggested_module) {
            ModuleKind::Enumeration => categories.enumeration.push(suggestion.clone()),
            ModuleKind::Validation => categories.validation.push(suggestion.clone()),
            ModuleKind::Exploitation => categories.exploitation.push(suggestion.clone()),
        }
    }
    categories
}

fn confidence_rank(confidence: &str) -> u8 {
    match confidence.to_lowercase().as_str() {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

enum ModuleKind {
    Enumeration,
    Validation,
    Exploitation,
}

/// Group Metasploit modules by intent: version/banner discovery is
/// enumeration, content/behaviour checks are validation, and `exploit/`
/// modules are potential exploitation.
fn classify_module(module: &str) -> ModuleKind {
    if module.starts_with("exploit/") {
        return ModuleKind::Exploitation;
    }
    let last = module.rsplit('/').next().unwrap_or(module);
    if last.ends_with("_version") || last.ends_with("_scanner") {
        ModuleKind::Enumeration
    } else {
        ModuleKind::Validation
    }
}

/// Flag application-specific vulnerabilities that have no generic Metasploit
/// module so the report can call them out for manual validation instead of
/// inventing a module.
pub fn manual_exploitation_notes(records: &[ScanRecord]) -> Vec<String> {
    const MANUAL_ONLY: &[(&str, &[&str])] = &[
        (
            "Application-specific SQL Injection",
            &["sql injection", "sqli"],
        ),
        ("Application-specific LDAP Injection", &["ldap injection"]),
        (
            "Application-specific XSS",
            &["cross-site scripting", " xss"],
        ),
        (
            "Application-specific CSRF",
            &["csrf", "cross-site request forgery"],
        ),
        ("Application-specific XXE", &["xml external entity", " xxe"]),
        (
            "Application-specific Authentication Flaws",
            &[
                "authentication bypass",
                "session fixation",
                "weak authentication",
            ],
        ),
        (
            "Application-specific Business Logic Flaws",
            &[
                "business logic",
                "privilege escalation",
                "authorization bypass",
            ],
        ),
    ];

    let mut notes = Vec::new();
    let mut seen = BTreeSet::new();
    for record in records {
        let text = format!(
            "{} {}",
            record.title.to_lowercase(),
            raw_text(&record.raw).to_lowercase()
        );
        for (name, keywords) in MANUAL_ONLY {
            if !seen.contains(*name) && keywords.iter().any(|keyword| text.contains(keyword)) {
                seen.insert(*name);
                notes.push((*name).to_string());
            }
        }
    }
    notes
}

// ---------------------------------------------------------------------------
// Attack path
// ---------------------------------------------------------------------------

pub fn build_attack_path(records: &[ScanRecord]) -> Vec<String> {
    let mut steps = Vec::new();
    steps.push("Internet".to_string());

    if let Some(server) = infer_server(records) {
        steps.push(server);
    } else if let Some(host) = records.first().map(|record| record.target.clone()) {
        steps.push(host);
    }
    if let Some(framework) = infer_framework(records) {
        steps.push(framework);
    }

    let kinds = detect_vuln_kinds(records);
    if !kinds.is_empty() {
        steps.push(kinds[0].clone());
    } else if let Some(record) = highest_severity_record(records) {
        steps.push(display_title(&record.title));
    }

    steps.push(impact_for(&kinds));
    steps
}

fn impact_for(kinds: &[String]) -> String {
    let all = kinds.join(" ");
    let all = all.to_lowercase();
    if all.contains("sql injection") || all.contains("ldap injection") {
        "Database Access".to_string()
    } else if all.contains("command injection")
        || all.contains("remote code execution")
        || all.contains("deserialization")
    {
        "Remote Code Execution".to_string()
    } else if all.contains("file upload") {
        "Web Shell / RCE".to_string()
    } else if all.contains("path traversal") {
        "Sensitive File Disclosure".to_string()
    } else if all.contains("weak credential") || all.contains("brute force") {
        "Account Takeover".to_string()
    } else if all.contains("xss") {
        "Session Hijacking".to_string()
    } else {
        "Privilege Escalation".to_string()
    }
}

fn highest_severity_record(records: &[ScanRecord]) -> Option<&ScanRecord> {
    records
        .iter()
        .min_by_key(|record| severity_rank(&record.severity))
}

// ---------------------------------------------------------------------------
// MITRE ATT&CK mapping
// ---------------------------------------------------------------------------

const MITRE_RULES: &[(&str, &str, &[&str])] = &[
    (
        "Discovery",
        "T1046 Network Service Discovery",
        &[
            "banner",
            "version disclosure",
            "service detection",
            "robots.txt",
            "directory listing",
            "trace.axd",
            "debug page",
            "information disclosure",
        ],
    ),
    (
        "Discovery",
        "T1595 Active Scanning",
        &["scan", "enumeration", "fingerprint"],
    ),
    (
        "Initial Access",
        "T1190 Exploit Public-Facing Application",
        &[
            "exploit",
            "cve-",
            "injection",
            "xss",
            "upload",
            "path traversal",
            "open redirect",
            "csrf",
            "deserialization",
            "xxe",
            "rce",
            "remote code",
            "vulnerable",
            "weak authentication",
        ],
    ),
    (
        "Execution",
        "T1203 Exploitation for Client Execution",
        &[
            "xss",
            "rce",
            "command injection",
            "upload",
            "deserialization",
            "webshell",
            "web shell",
        ],
    ),
    (
        "Persistence",
        "T1505 Web Shell",
        &["upload", "webshell", "web shell", "persistence"],
    ),
    (
        "Credential Access",
        "T1110 Brute Force",
        &[
            "brute force",
            "weak password",
            "default password",
            "weak credential",
        ],
    ),
    (
        "Credential Access",
        "T1003 OS Credential Dumping",
        &[
            "credential",
            "sql injection",
            "ldap injection",
            "database",
            "authentication bypass",
            "session fixation",
        ],
    ),
    (
        "Credential Access",
        "T1557 Adversary-in-the-Middle",
        &["clickjacking", "x-frame-options", "frame injection"],
    ),
    (
        "Collection",
        "T1071 Application Layer Protocol",
        &[
            "sensitive data",
            "information disclosure",
            "info disclosure",
            "data exposure",
        ],
    ),
    (
        "Defense Evasion",
        "T1078 Valid Accounts",
        &["default password", "weak credential", "valid account"],
    ),
    (
        "Lateral Movement",
        "T1210 Exploitation of Remote Services",
        &[
            "smb",
            "rdp",
            "eternalblue",
            "bluekeep",
            "remote service",
            "ms17-010",
        ],
    ),
];

pub fn map_mitre(records: &[ScanRecord]) -> Vec<MitreTactic> {
    if records.is_empty() {
        return Vec::new();
    }

    let mut tactics: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();

    // Web scanning is always present when any scan data was processed.
    tactics
        .entry("Discovery".to_string())
        .or_default()
        .0
        .insert("T1595 Active Scanning".to_string());

    for record in records {
        let text = format!(
            "{} {}",
            record.title.to_lowercase(),
            raw_text(&record.raw).to_lowercase()
        );
        for (tactic, technique, keywords) in MITRE_RULES {
            if keywords.iter().any(|keyword| text.contains(keyword)) {
                let entry = tactics.entry((*tactic).to_string()).or_default();
                entry.0.insert((*technique).to_string());
                entry.1.insert(record.title.clone());
            }
        }
    }

    let mut ordered = tactics
        .into_iter()
        .map(|(tactic, (techniques, findings))| MitreTactic {
            tactic,
            techniques: techniques.into_iter().collect(),
            findings: findings.into_iter().collect(),
        })
        .collect::<Vec<_>>();
    ordered.sort_by_key(|entry| tactic_rank(&entry.tactic));
    ordered
}

const TACTIC_ORDER: &[&str] = &[
    "Discovery",
    "Initial Access",
    "Execution",
    "Persistence",
    "Credential Access",
    "Defense Evasion",
    "Collection",
    "Lateral Movement",
];

fn tactic_rank(tactic: &str) -> usize {
    TACTIC_ORDER
        .iter()
        .position(|known| *known == tactic)
        .unwrap_or(usize::MAX)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record(title: &str, severity: &str, url: &str) -> ScanRecord {
        ScanRecord {
            target: "testasp.vulnweb.com".into(),
            tool: "vulnmalper".into(),
            title: title.into(),
            severity: severity.into(),
            port: Some(80),
            cve: None,
            service: Some("Microsoft-IIS/8.5".into()),
            raw: json!({ "url": url }),
            ..Default::default()
        }
    }

    #[test]
    fn groups_findings_and_merges_endpoints() {
        let records = vec![
            record(
                "LDAP Injection on QUERY_STRING",
                "critical",
                "http://h/search?q=",
            ),
            record(
                "LDAP Injection on QUERY_STRING",
                "critical",
                "http://h/products?id=",
            ),
            record(
                "LDAP Injection on QUERY_STRING",
                "critical",
                "http://h/login?user=",
            ),
        ];
        let groups = group_findings(&records);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].title, "LDAP Injection");
        assert_eq!(groups[0].severity, "critical");
        assert_eq!(groups[0].count, 3);
        assert_eq!(groups[0].affected_endpoints.len(), 3);
        assert!(groups[0]
            .affected_endpoints
            .contains(&"/search?q=".to_string()));
    }

    #[test]
    fn keeps_distinct_vuln_types_separate() {
        let records = vec![
            record(
                "SQL Injection on QUERY_STRING",
                "critical",
                "http://h/search?q=",
            ),
            record(
                "LDAP Injection on QUERY_STRING",
                "critical",
                "http://h/search?q=",
            ),
        ];
        let groups = group_findings(&records);
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn infers_server_and_framework() {
        let records = vec![record("Trace.axd exposed", "medium", "http://h/trace.axd")];
        assert_eq!(infer_server(&records).as_deref(), Some("Microsoft IIS 8.5"));
        assert_eq!(infer_framework(&records).as_deref(), Some("ASP.NET"));
    }

    #[test]
    fn risk_score_reflects_severity() {
        let records = vec![
            record(
                "SQL Injection on QUERY_STRING",
                "critical",
                "http://h/search?q=",
            ),
            record(
                "LDAP Injection on QUERY_STRING",
                "critical",
                "http://h/login?user=",
            ),
        ];
        let risk = compute_risk_score(&records);
        assert_eq!(risk.score, 20);
        assert_eq!(risk.bar.chars().count(), 10);
        assert!(risk
            .reasons
            .iter()
            .any(|reason| reason.contains("SQL Injection")));
    }

    #[test]
    fn categories_modules() {
        let suggestions = vec![
            ModuleSuggestion {
                service_banner: "IIS".into(),
                suggested_module: "auxiliary/scanner/http/iis_version".into(),
                confidence: "high".into(),
            },
            ModuleSuggestion {
                service_banner: "robots.txt".into(),
                suggested_module: "auxiliary/scanner/http/robots_txt".into(),
                confidence: "high".into(),
            },
            ModuleSuggestion {
                service_banner: "tomcat".into(),
                suggested_module: "exploit/multi/http/tomcat_jsp_upload_bypass".into(),
                confidence: "high".into(),
            },
        ];
        let categories = categorize_modules(&suggestions);
        assert_eq!(categories.enumeration.len(), 1);
        assert_eq!(categories.validation.len(), 1);
        assert_eq!(categories.exploitation.len(), 1);
    }

    #[test]
    fn attack_path_ends_in_database_access_for_injection() {
        let records = vec![record(
            "SQL Injection on QUERY_STRING",
            "critical",
            "http://h/search?q=",
        )];
        let path = build_attack_path(&records);
        assert_eq!(path.first().map(String::as_str), Some("Internet"));
        assert_eq!(path.last().map(String::as_str), Some("Database Access"));
        assert!(path.iter().any(|step| step == "SQL Injection"));
    }

    #[test]
    fn mitre_mapping_flags_injection() {
        let records = vec![record(
            "SQL Injection on QUERY_STRING",
            "critical",
            "http://h/search?q=",
        )];
        let tactics = map_mitre(&records);
        assert!(tactics
            .iter()
            .any(|tactic| tactic.tactic == "Credential Access"));
    }

    #[test]
    fn endpoint_extracted_from_title() {
        let rec = ScanRecord {
            target: "h".into(),
            tool: "t".into(),
            title: "SQL Injection at /products?id=1".into(),
            severity: "high".into(),
            port: None,
            cve: None,
            service: None,
            raw: json!({}),
            ..Default::default()
        };
        assert_eq!(extract_endpoint(&rec).as_deref(), Some("/products?id=1"));
    }
}
