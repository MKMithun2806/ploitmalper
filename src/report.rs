use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::analyze::{
    build_attack_chain, build_scan_summary, categorize_modules, compute_risk_score,
    exploitability_assessment, group_findings, manual_exploitation_notes, map_mitre,
};
use crate::enrich;
use crate::error::Result;
use crate::models::{
    DedupStats, ExploitabilityInfo, FindingGroup, InjectableEndpoint, ModuleCategories,
    ModuleSuggestion, PayloadRecipe, ScanRecord, ScanSummary,
};

fn truncate(value: &str, limit: usize) -> String {
    let count = value.chars().count();
    if count <= limit {
        value.to_string()
    } else if limit <= 1 {
        "…".to_string()
    } else {
        let mut truncated = value.chars().take(limit - 1).collect::<String>();
        truncated.push('…');
        truncated
    }
}

fn pad(value: &str, width: usize) -> String {
    let visible = value.chars().count();
    if visible >= width {
        value.to_string()
    } else {
        format!("{}{}", value, " ".repeat(width - visible))
    }
}

fn ascii_table(title: &str, headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths = headers
        .iter()
        .map(|h| h.chars().count())
        .collect::<Vec<_>>();
    for row in rows {
        for (idx, cell) in row.iter().enumerate() {
            widths[idx] = widths[idx].max(cell.chars().count());
        }
    }

    let separator = {
        let mut s = String::from("+");
        for width in &widths {
            s.push_str(&"-".repeat(*width + 2));
            s.push('+');
        }
        s
    };

    let mut out = String::new();
    out.push_str(title);
    out.push('\n');
    out.push_str(&separator);
    out.push('\n');
    out.push('|');
    for (idx, header) in headers.iter().enumerate() {
        out.push(' ');
        out.push_str(&pad(header, widths[idx]));
        out.push(' ');
        out.push('|');
    }
    out.push('\n');
    out.push_str(&separator);
    out.push('\n');
    for row in rows {
        out.push('|');
        for (idx, cell) in row.iter().enumerate() {
            out.push(' ');
            out.push_str(&pad(cell, widths[idx]));
            out.push(' ');
            out.push('|');
        }
        out.push('\n');
    }
    out.push_str(&separator);
    out
}

fn unique_cves(records: &[ScanRecord]) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for cve in records.iter().flat_map(|record| record.cves.iter()) {
        let key = cve.trim().to_uppercase();
        if seen.insert(key.clone()) {
            out.push(key);
        }
    }
    out
}

fn technologies(records: &[ScanRecord]) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for record in records {
        let mut candidates = Vec::new();
        if let Some(service) = record.service.as_deref() {
            candidates.push(service.to_string());
        }
        for key in [
            "server",
            "banner",
            "software",
            "product",
            "app",
            "technology",
        ] {
            if let Some(value) = record.raw.get(key).and_then(serde_json::Value::as_str) {
                candidates.push(value.to_string());
            }
        }
        for candidate in candidates {
            let lower = candidate.to_lowercase();
            if seen.insert(lower.clone()) {
                out.push(lower);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Console rendering
// ---------------------------------------------------------------------------

fn console_executive_summary(
    summary: &ScanSummary,
    dedup_stats: &DedupStats,
    injectable: &[InjectableEndpoint],
    cve_count: usize,
) -> String {
    let mut out = String::new();
    out.push_str("Executive Summary\n");
    out.push_str("─────────────────\n");
    out.push_str(&format!("Host: {}\n", summary.host));
    if let Some(server) = &summary.server {
        out.push_str(&format!("Server: {}\n", server));
    }
    if let Some(framework) = &summary.framework {
        out.push_str(&format!("Framework: {}\n", framework));
    }
    out.push_str(&format!("Records processed: {}\n", dedup_stats.total));
    out.push_str(&format!("Unique findings: {}\n", dedup_stats.unique));
    out.push_str(&format!("Duplicates merged: {}\n", dedup_stats.removed));
    out.push_str(&format!("Injectable endpoints: {}\n", injectable.len()));
    out.push_str(&format!("CVE ids discovered: {}\n", cve_count));
    out.push('\n');
    for severity in ["critical", "high", "medium", "low", "info"] {
        if let Some(count) = summary.severity_counts.get(severity) {
            if *count > 0 {
                out.push_str(&format!(
                    "{:<9}: {}\n",
                    format!("{}", severity.to_uppercase()),
                    count
                ));
            }
        }
    }
    out
}

fn console_risk_overview(records: &[ScanRecord], injectable: &[InjectableEndpoint]) -> String {
    let risk = compute_risk_score(records, injectable);
    let mut out = String::new();
    out.push_str(&format!("Overall Risk: {}/100\n", risk.score));
    out.push_str(&risk.bar);
    out.push_str("\n\nReason:\n");
    for reason in &risk.reasons {
        out.push_str(&format!("• {}\n", reason));
    }
    out
}

fn console_key_findings(groups: &[FindingGroup]) -> String {
    let mut out = String::new();
    out.push_str("Key Findings\n");
    out.push_str("────────────\n");
    let actionable: Vec<&FindingGroup> = groups
        .iter()
        .filter(|group| group.family != "Reconnaissance / Informational")
        .collect();
    let selection: Vec<&FindingGroup> = if actionable.is_empty() {
        groups.iter().take(5).collect()
    } else {
        actionable.iter().take(6).cloned().collect()
    };
    if selection.is_empty() {
        out.push_str("(none)\n");
        return out;
    }
    for (idx, group) in selection.iter().enumerate() {
        let cve_part = if group.cves.is_empty() {
            String::new()
        } else {
            format!(" [{}]", group.cves.join(", "))
        };
        out.push_str(&format!(
            "{}. {} — {} ({} finding{}){}\n",
            idx + 1,
            group.title,
            group.severity.to_uppercase(),
            group.count,
            if group.count == 1 { "" } else { "s" },
            cve_part
        ));
    }
    out
}

fn console_injectable(injectable: &[InjectableEndpoint]) -> String {
    let mut out = String::new();
    out.push_str("Injectable Endpoints\n");
    out.push_str("────────────────────\n");
    if injectable.is_empty() {
        out.push_str("No injectable endpoints flagged by the scanner.\n");
        return out;
    }
    out.push_str(&format!(
        "{} potential injection point(s) reported:\n",
        injectable.len()
    ));
    for (idx, entry) in injectable.iter().enumerate() {
        out.push_str(&format!("  {}. {}\n", idx + 1, entry.endpoint));
        out.push_str(&format!("     (affected host: {})\n", entry.target));
    }
    out
}

fn console_cve_intelligence(records: &[ScanRecord]) -> String {
    let mut out = String::new();
    out.push_str("CVE Intelligence\n");
    out.push_str("────────────────\n");
    let cves = unique_cves(records);
    if cves.is_empty() {
        out.push_str("No CVEs discovered in this scan.\n");
        return out;
    }
    for cve in &cves {
        let record = records.iter().find(|record| {
            record
                .cves
                .iter()
                .any(|known| known.eq_ignore_ascii_case(cve))
        });
        out.push_str(&format!("{}\n", cve));
        if let Some(record) = record {
            if let Some(cvss) = record.nvd_cvss_v3 {
                out.push_str(&format!("  CVSS v3: {:.1}", cvss));
                if let Some(severity) = record.nvd_cvss_v3_severity.as_deref() {
                    out.push_str(&format!(" ({})", severity.to_uppercase()));
                }
                out.push('\n');
            }
            if let Some(cvss) = record.nvd_cvss_v2 {
                out.push_str(&format!("  CVSS v2: {:.1}\n", cvss));
            }
            if !record.nvd_weaknesses.is_empty() {
                out.push_str(&format!("  CWE: {}\n", record.nvd_weaknesses.join(", ")));
            }
            if let Some(published) = record.nvd_published.as_deref() {
                if !published.is_empty() {
                    out.push_str(&format!("  Published: {}\n", published));
                }
            }
        }
        if let Some(extra) = enrich::enrich_cve(cve) {
            out.push_str(&format!("  EPSS: {}\n", enrich::epss_percent(extra.epss)));
            out.push_str(&format!(
                "  Known Exploited: {}\n",
                if extra.in_kev { "YES" } else { "NO" }
            ));
            out.push_str(&format!(
                "  Public exploit: {}\n",
                if extra.public_exploit { "YES" } else { "NO" }
            ));
        }
        if let Some(record) = record {
            if let Some(description) = record.nvd_description.as_deref() {
                if !description.is_empty() {
                    out.push_str(&format!("  Description: {}\n", truncate(description, 120)));
                }
            }
        }
        out.push('\n');
    }
    out
}

fn console_exploitability(assessment: &ExploitabilityInfo) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Exploitability Assessment: {} ({}/100)\n",
        assessment.rating, assessment.score
    ));
    out.push_str("────────────────────────────────────────────\n");
    for reason in &assessment.reasons {
        out.push_str(&format!("• {}\n", reason));
    }
    out
}

fn console_msf(records: &[ScanRecord], injectable: &[InjectableEndpoint]) -> String {
    let mut out = String::new();
    out.push_str("Metasploit Recommendations\n");
    out.push_str("──────────────────────────\n");

    let cves = unique_cves(records);
    let mut any = false;
    for cve in &cves {
        let modules = crate::msf::modules_for_cve(cve);
        if modules.is_empty() {
            let reason = crate::msf::no_module_reason(cve);
            out.push_str(&format!("• {} — {}\n", cve, reason.reason));
            any = true;
            continue;
        }
        any = true;
        out.push_str(&format!("{}\n", cve));
        for module in &modules {
            out.push_str(&format!("  ✓ {} (rank: {})\n", module.name, module.rank));
            out.push_str(&format!("     disclosure: {}\n", module.disclosure_date));
            out.push_str(&format!(
                "     platforms: {}\n",
                if module.platforms.is_empty() {
                    "any".to_string()
                } else {
                    module.platforms.join(", ")
                }
            ));
            if !module.required_options.is_empty() {
                out.push_str(&format!(
                    "     required options: {}\n",
                    module.required_options.join(", ")
                ));
            }
        }
    }

    let tech = technologies(records);
    if !tech.is_empty() {
        let modules = crate::msf::modules_for_technology(&tech);
        if !modules.is_empty() {
            out.push_str("Technology-driven modules:\n");
            for module in &modules {
                out.push_str(&format!(
                    "  ✓ {} (rank: {}, disclosure: {})\n",
                    module.name, module.rank, module.disclosure_date
                ));
                out.push_str(&format!(
                    "     platforms: {}\n",
                    if module.platforms.is_empty() {
                        "any".to_string()
                    } else {
                        module.platforms.join(", ")
                    }
                ));
            }
            any = true;
        }
    }

    if !injectable.is_empty() {
        out.push_str("• Injectable endpoints: no Metasploit module can validate an application\n");
        out.push_str(
            "  injection point automatically — manual testing is required (see Attack Chain).\n",
        );
        any = true;
    }

    if !any {
        out.push_str("(no CVEs or recognized technologies warrant a Metasploit module)\n");
    }
    out
}

fn console_attack_chain(records: &[ScanRecord], injectable: &[InjectableEndpoint]) -> String {
    let mut out = String::new();
    out.push_str("Attack Chain\n");
    out.push_str("────────────\n");
    match build_attack_chain(records, injectable) {
        Some(steps) => {
            for (idx, step) in steps.iter().enumerate() {
                if idx > 0 {
                    out.push_str("     │\n     ▼\n");
                }
                out.push_str(&format!("{}\n", step));
            }
        }
        None => {
            out.push_str("No credible automated attack chain identified.\n");
            out.push_str(
                "No injectable endpoints or known-exploitable CVEs were found in this scan.\n",
            );
        }
    }
    out
}

fn console_full_findings(groups: &[FindingGroup]) -> String {
    let mut out = String::new();
    out.push_str("Full Findings\n");
    out.push_str("─────────────\n");

    let rows = groups
        .iter()
        .enumerate()
        .map(|(idx, group)| {
            vec![
                (idx + 1).to_string(),
                truncate(&group.title, 34),
                group.severity.to_uppercase(),
                group.count.to_string(),
                group.affected_endpoints.len().to_string(),
                if group.cves.is_empty() {
                    "—".to_string()
                } else {
                    group.cves.join(", ")
                },
            ]
        })
        .collect::<Vec<_>>();

    if !rows.is_empty() {
        out.push_str(&ascii_table(
            "Grouped Intelligence Findings",
            &["#", "Finding", "Severity", "Count", "Endpoints", "CVE"],
            &rows,
        ));
        out.push('\n');
    }

    for group in groups {
        out.push_str(&format!(
            "{} — {} ({} finding{})\n",
            group.title,
            group.severity.to_uppercase(),
            group.count,
            if group.count == 1 { "" } else { "s" }
        ));
        if !group.details.is_empty() {
            for detail in &group.details {
                out.push_str(&format!("  • {}\n", detail));
            }
        }
        if !group.affected_endpoints.is_empty() {
            out.push_str("  endpoints:\n");
            for endpoint in &group.affected_endpoints {
                out.push_str(&format!("     {}\n", endpoint));
            }
        }
        if !group.cves.is_empty() {
            out.push_str(&format!("  cves: {}\n", group.cves.join(", ")));
        }
        if !group.ports.is_empty() {
            out.push_str(&format!("  ports: {}\n", group.ports.join(", ")));
        }
        if !group.tools.is_empty() {
            out.push_str(&format!("  tools: {}\n", group.tools.join(", ")));
        }
        out.push_str(&format!("  target: {}\n", group.target));
        if !group.evidence.is_empty() {
            out.push_str("  evidence:\n");
            for evidence in &group.evidence {
                out.push_str(&format!("     - {}\n", evidence));
            }
        }
        out.push('\n');
    }
    out
}

fn record_evidence(record: &ScanRecord) -> String {
    let mut lines = Vec::new();
    lines.push(format!("tool: {}", record.tool));
    lines.push(format!("target: {}", record.target));
    if !record.raw_findings.is_empty() {
        for raw in &record.raw_findings {
            lines.push(format!("raw finding: {}", raw));
        }
    } else {
        lines.push(format!("title: {}", record.title));
    }
    if !record.detail.is_empty() {
        lines.push(format!("detail: {}", record.detail));
    }
    if !record.reference.is_empty() {
        lines.push(format!("reference: {}", record.reference));
    }
    if !record.normalized_title.is_empty() {
        lines.push(format!("normalized: {}", record.normalized_title));
    }
    lines.push(format!("raw json: {}", record.raw));
    lines.join("\n")
}

fn console_raw_evidence(records: &[ScanRecord]) -> String {
    let mut out = String::new();
    out.push_str("Raw Evidence\n");
    out.push_str("────────────\n");
    for (idx, record) in records.iter().enumerate() {
        out.push_str(&format!("[{}]\n", idx + 1));
        for line in record_evidence(record).lines() {
            out.push_str(&format!("  {}\n", line));
        }
        out.push('\n');
    }
    out
}

pub fn render_console_report(
    records: &[ScanRecord],
    injectable: &[InjectableEndpoint],
    _suggestions: &[ModuleSuggestion],
    recipes: &[PayloadRecipe],
    dedup_stats: &DedupStats,
) -> String {
    let summary = build_scan_summary(records);
    let groups = group_findings(records);
    let assessment = exploitability_assessment(records, injectable);
    let cve_count = unique_cves(records).len();

    let mut out = String::new();
    out.push_str(&console_executive_summary(
        &summary,
        dedup_stats,
        injectable,
        cve_count,
    ));
    out.push('\n');
    out.push_str(&console_risk_overview(records, injectable));
    out.push('\n');
    out.push_str(&console_key_findings(&groups));
    out.push('\n');
    out.push_str(&console_injectable(injectable));
    out.push('\n');
    out.push_str(&console_cve_intelligence(records));
    out.push('\n');
    out.push_str(&console_exploitability(&assessment));
    out.push('\n');
    out.push_str(&console_msf(records, injectable));
    out.push('\n');
    out.push_str(&console_attack_chain(records, injectable));
    out.push('\n');
    out.push_str(&console_full_findings(&groups));
    out.push('\n');
    out.push_str(&console_raw_evidence(records));
    if !recipes.is_empty() {
        out.push('\n');
        out.push_str(&render_recipes(recipes));
    }
    out
}

fn render_recipes(recipes: &[PayloadRecipe]) -> String {
    let mut out = String::new();
    out.push_str("Payload Command Recipes\n");
    for recipe in recipes {
        out.push_str(&format!(
            "{} / {}\n  LHOST: {}\n  LPORT: {}\n  Format: {}\n  Output: {}\n\n  {}\n\n",
            recipe.platform,
            recipe.architecture,
            recipe.lhost,
            recipe.lport,
            recipe.format,
            recipe.output_path,
            recipe.command
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Markdown report
// ---------------------------------------------------------------------------

fn md_escape(value: &str) -> String {
    value.replace('|', r"\|")
}

fn title_case(value: &str) -> String {
    value
        .split(|c: char| c == '-' || c == '_' || c.is_whitespace())
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let mut chars = segment.chars();
            match chars.next() {
                Some(first) => {
                    let first = first.to_uppercase().collect::<String>();
                    format!("{}{}", first, chars.as_str().to_lowercase())
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Derive the markdown report output path from a scan JSON input path.
/// `results/scan.json` becomes `results/scan_ploitmalper.md` in the same
/// directory as the input.
pub fn derive_report_path(input_path: &Path) -> PathBuf {
    let stem = input_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "report".to_string());
    let directory = input_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    directory.join(format!("{}_ploitmalper.md", stem))
}

pub fn generate_markdown_report(
    records: &[ScanRecord],
    injectable: &[InjectableEndpoint],
    _suggestions: &[ModuleSuggestion],
    recipes: &[PayloadRecipe],
    dedup_stats: &DedupStats,
    output_path: &str,
) -> Result<PathBuf> {
    let mut lines = Vec::new();
    let has_nvd = records.iter().any(|record| record.nvd_cvss_v3.is_some());

    lines.push("# PloitMalper - Vulnerability Analysis Report".to_string());
    lines.push(String::new());
    lines.push(format!(
        "**Generated:** {}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    ));
    lines.push(format!("**Tool Version:** {}", env!("CARGO_PKG_VERSION")));
    lines.push(String::new());

    // 1. Executive Summary
    let summary = build_scan_summary(records);
    lines.push("## 1. Executive Summary".to_string());
    lines.push(String::new());
    lines.push(format!("- **Host:** {}", md_escape(&summary.host)));
    if let Some(server) = &summary.server {
        lines.push(format!("- **Server:** {}", md_escape(server)));
    }
    if let Some(framework) = &summary.framework {
        lines.push(format!("- **Framework:** {}", md_escape(framework)));
    }
    lines.push(format!(
        "- **Total records processed:** {}",
        dedup_stats.total
    ));
    lines.push(format!("- **Unique findings:** {}", dedup_stats.unique));
    lines.push(format!("- **Duplicates merged:** {}", dedup_stats.removed));
    lines.push(format!("- **Injectable endpoints:** {}", injectable.len()));
    lines.push(format!(
        "- **CVE ids discovered:** {}",
        unique_cves(records).len()
    ));
    if has_nvd {
        lines.push("- **NVD enrichment:** Enabled".to_string());
    }
    lines.push(String::new());

    lines.push("### Severity Distribution".to_string());
    lines.push(String::new());
    for severity in ["critical", "high", "medium", "low", "info", "unknown"] {
        if let Some(count) = summary.severity_counts.get(severity) {
            if *count > 0 {
                lines.push(format!("- **{}:** {}", severity.to_uppercase(), count));
            }
        }
    }
    lines.push(String::new());

    // 2. Risk Overview
    let risk = compute_risk_score(records, injectable);
    lines.push("## 2. Risk Overview".to_string());
    lines.push(String::new());
    lines.push(format!("### Overall Risk: {}/100", risk.score));
    lines.push(String::new());
    lines.push(format!("`{}`", risk.bar));
    lines.push(String::new());
    for reason in &risk.reasons {
        lines.push(format!("- {}", reason));
    }
    lines.push(String::new());

    // 3. Key Findings
    let groups = group_findings(records);
    lines.push("## 3. Key Findings".to_string());
    lines.push(String::new());
    let actionable: Vec<&FindingGroup> = groups
        .iter()
        .filter(|group| group.family != "Reconnaissance / Informational")
        .collect();
    let selection: Vec<&FindingGroup> = if actionable.is_empty() {
        groups.iter().take(5).collect()
    } else {
        actionable.iter().take(6).cloned().collect()
    };
    if selection.is_empty() {
        lines.push("No significant findings to highlight.".to_string());
    } else {
        for (idx, group) in selection.iter().enumerate() {
            let cve_part = if group.cves.is_empty() {
                String::new()
            } else {
                format!(" `{}`", group.cves.join(", "))
            };
            lines.push(format!(
                "{}. **{}** — {} ({} finding{}){}",
                idx + 1,
                group.title,
                group.severity.to_uppercase(),
                group.count,
                if group.count == 1 { "" } else { "s" },
                cve_part
            ));
        }
    }
    lines.push(String::new());

    // 4. Injectable Endpoints
    lines.push("## 4. Injectable Endpoints".to_string());
    lines.push(String::new());
    if injectable.is_empty() {
        lines.push("No injectable endpoints flagged by the scanner.".to_string());
    } else {
        lines.push(format!(
            "{} potential injection point(s) reported:",
            injectable.len()
        ));
        lines.push(String::new());
        lines.push("| # | Endpoint | Affected Host |".to_string());
        lines.push("|---|----------|---------------|".to_string());
        for (idx, entry) in injectable.iter().enumerate() {
            lines.push(format!(
                "| {} | `{}` | {} |",
                idx + 1,
                md_escape(&entry.endpoint),
                md_escape(&entry.target)
            ));
        }
    }
    lines.push(String::new());

    // 5. CVE Intelligence
    lines.push("## 5. CVE Intelligence".to_string());
    lines.push(String::new());
    let cves = unique_cves(records);
    if cves.is_empty() {
        lines.push("No CVEs were discovered in this scan.".to_string());
    } else {
        for cve in &cves {
            let record = records.iter().find(|record| {
                record
                    .cves
                    .iter()
                    .any(|known| known.eq_ignore_ascii_case(cve))
            });
            lines.push(format!("### {}", cve));
            lines.push(String::new());
            if let Some(record) = record {
                if let Some(cvss) = record.nvd_cvss_v3 {
                    let severity = record
                        .nvd_cvss_v3_severity
                        .as_deref()
                        .map(|s| format!(" ({})", s.to_uppercase()))
                        .unwrap_or_default();
                    lines.push(format!("- **CVSS v3 Score:** {:.1}{}", cvss, severity));
                }
                if let Some(cvss) = record.nvd_cvss_v2 {
                    lines.push(format!("- **CVSS v2 Score:** {:.1}", cvss));
                }
                if !record.nvd_weaknesses.is_empty() {
                    lines.push(format!("- **CWE:** {}", record.nvd_weaknesses.join(", ")));
                }
                if let Some(published) = record.nvd_published.as_deref() {
                    if !published.is_empty() {
                        lines.push(format!("- **Published:** {}", published));
                    }
                }
                if let Some(description) = record.nvd_description.as_deref() {
                    if !description.is_empty() {
                        lines.push(format!("- **Description:** {}", description));
                    }
                }
            }
            if let Some(extra) = enrich::enrich_cve(cve) {
                lines.push(format!("- **EPSS:** {}", enrich::epss_percent(extra.epss)));
                lines.push(format!(
                    "- **Known Exploited (CISA KEV):** {}",
                    if extra.in_kev { "YES" } else { "NO" }
                ));
                lines.push(format!(
                    "- **Public exploit:** {}",
                    if extra.public_exploit { "YES" } else { "NO" }
                ));
            }
            if let Some(record) = record {
                if !record.nvd_references.is_empty() {
                    lines.push("- **References:**".to_string());
                    for reference in &record.nvd_references {
                        lines.push(format!("  - {}", reference));
                    }
                }
            }
            lines.push(String::new());
        }
    }

    // 6. Exploitability Assessment
    let assessment = exploitability_assessment(records, injectable);
    lines.push("## 6. Exploitability Assessment".to_string());
    lines.push(String::new());
    lines.push(format!(
        "**Rating:** {} ({}/100)",
        assessment.rating, assessment.score
    ));
    lines.push(String::new());
    for reason in &assessment.reasons {
        lines.push(format!("- {}", reason));
    }
    lines.push(String::new());

    // 7. Metasploit Recommendations
    lines.push("## 7. Metasploit Recommendations".to_string());
    lines.push(String::new());
    let mut msf_any = false;
    for cve in &cves {
        let modules = crate::msf::modules_for_cve(cve);
        if modules.is_empty() {
            let reason = crate::msf::no_module_reason(cve);
            lines.push(format!("**{}** — {}", cve, reason.reason));
            lines.push(String::new());
            msf_any = true;
            continue;
        }
        msf_any = true;
        lines.push(format!("### {}", cve));
        lines.push(String::new());
        for module in &modules {
            lines.push(format!("- **Module:** `{}`", module.name));
            lines.push(format!("  - **Rank:** {}", module.rank));
            lines.push(format!("  - **Disclosure:** {}", module.disclosure_date));
            lines.push(format!(
                "  - **Platforms:** {}",
                if module.platforms.is_empty() {
                    "any".to_string()
                } else {
                    module.platforms.join(", ")
                }
            ));
            lines.push(format!(
                "  - **Required options:** {}",
                if module.required_options.is_empty() {
                    "none".to_string()
                } else {
                    module.required_options.join(", ")
                }
            ));
        }
        lines.push(String::new());
    }
    let tech = technologies(records);
    if !tech.is_empty() {
        let modules = crate::msf::modules_for_technology(&tech);
        if !modules.is_empty() {
            lines.push("### Technology-driven".to_string());
            lines.push(String::new());
            for module in &modules {
                lines.push(format!(
                    "- `{}` (rank: {}, disclosure: {})",
                    module.name, module.rank, module.disclosure_date
                ));
            }
            lines.push(String::new());
            msf_any = true;
        }
    }
    if !injectable.is_empty() {
        lines.push(
            "- **Injectable endpoints:** no Metasploit module can validate an application"
                .to_string(),
        );
        lines.push(
            "  injection point automatically — manual testing is required (see Attack Chain)."
                .to_string(),
        );
        lines.push(String::new());
        msf_any = true;
    }
    if !msf_any {
        lines.push("No CVEs or recognized technologies warrant a Metasploit module.".to_string());
        lines.push(String::new());
    }

    // 8. MITRE ATT&CK Mapping
    let tactics = map_mitre(records);
    lines.push("## 8. MITRE ATT&CK Mapping".to_string());
    lines.push(String::new());
    if tactics.is_empty() {
        lines.push("No applicable tactics.".to_string());
    } else {
        for tactic in &tactics {
            lines.push(format!("### {}", tactic.tactic));
            lines.push(String::new());
            for technique in &tactic.techniques {
                lines.push(format!("- ✓ {}", technique));
            }
            lines.push(String::new());
        }
    }

    // 9. Attack Chain
    lines.push("## 9. Attack Chain".to_string());
    lines.push(String::new());
    match build_attack_chain(records, injectable) {
        Some(steps) => {
            lines.push("```text".to_string());
            for (idx, step) in steps.iter().enumerate() {
                if idx > 0 {
                    lines.push("     │".to_string());
                    lines.push("     ▼".to_string());
                }
                lines.push(step.clone());
            }
            lines.push("```".to_string());
        }
        None => {
            lines.push("**No credible automated attack chain identified.**".to_string());
            lines.push(String::new());
            lines.push(
                "No injectable endpoints or known-exploitable CVEs were found in this scan; chaining steps without evidence would be speculative.".to_string(),
            );
        }
    }
    lines.push(String::new());

    // 10. Full Findings
    lines.push("## 10. Full Findings".to_string());
    lines.push(String::new());
    lines.push("| # | Finding | Severity | Count | Endpoints | CVE |".to_string());
    lines.push("|---|---------|----------|-------|-----------|-----|".to_string());
    for (idx, group) in groups.iter().enumerate() {
        lines.push(format!(
            "| {} | {} | {} | {} | {} | {} |",
            idx + 1,
            md_escape(&group.title),
            group.severity.to_uppercase(),
            group.count,
            if group.affected_endpoints.is_empty() {
                "—".to_string()
            } else {
                group.affected_endpoints.len().to_string()
            },
            if group.cves.is_empty() {
                "—".to_string()
            } else {
                group.cves.join(", ")
            }
        ));
    }
    lines.push(String::new());
    for group in &groups {
        lines.push(format!(
            "### {} — {}",
            group.title,
            group.severity.to_uppercase()
        ));
        lines.push(String::new());
        lines.push(format!("- **Count:** {}", group.count));
        lines.push(format!("- **Target:** {}", md_escape(&group.target)));
        if !group.ports.is_empty() {
            lines.push(format!("- **Ports:** {}", group.ports.join(", ")));
        }
        if !group.tools.is_empty() {
            lines.push(format!("- **Tools:** {}", group.tools.join(", ")));
        }
        if !group.cves.is_empty() {
            lines.push(format!("- **CVEs:** {}", group.cves.join(", ")));
        }
        if !group.details.is_empty() {
            lines.push("- **Details:**".to_string());
            for detail in &group.details {
                lines.push(format!("  - {}", md_escape(detail)));
            }
        }
        if !group.affected_endpoints.is_empty() {
            lines.push("- **Affected endpoints:**".to_string());
            for endpoint in &group.affected_endpoints {
                lines.push(format!("  - `{}`", md_escape(endpoint)));
            }
        }
        if !group.evidence.is_empty() {
            lines.push("- **Scanner evidence:**".to_string());
            for evidence in &group.evidence {
                lines.push(format!("  - {}", md_escape(evidence)));
            }
        }
        lines.push(String::new());
    }

    // 11. Raw Evidence
    lines.push("## 11. Raw Evidence".to_string());
    lines.push(String::new());
    lines.push(
        "Every scanner finding below maps back to the original VulnMalper output for full traceability.".to_string(),
    );
    lines.push(String::new());
    for (idx, record) in records.iter().enumerate() {
        lines.push(format!("### {}. {}", idx + 1, md_escape(&record.title)));
        lines.push(String::new());
        lines.push(format!("- **Tool:** {}", record.tool));
        lines.push(format!("- **Target:** {}", md_escape(&record.target)));
        if !record.normalized_title.is_empty() {
            lines.push(format!(
                "- **Normalized:** `{}`",
                md_escape(&record.normalized_title)
            ));
        }
        if !record.detail.is_empty() {
            lines.push(format!("- **Detail:** {}", md_escape(&record.detail)));
        }
        if !record.reference.is_empty() {
            lines.push(format!("- **Reference:** {}", md_escape(&record.reference)));
        }
        if !record.raw_findings.is_empty() && record.raw_findings.len() > 1 {
            lines.push("- **Merged raw findings:**".to_string());
            for raw in &record.raw_findings {
                lines.push(format!("  - {}", md_escape(raw)));
            }
        }
        if !record.cves.is_empty() {
            lines.push(format!("- **CVEs:** {}", record.cves.join(", ")));
        }
        if record.raw != serde_json::Value::Null {
            lines.push("- **Raw JSON:**".to_string());
            lines.push("```json".to_string());
            lines.push(serde_json::to_string_pretty(&record.raw).unwrap_or_default());
            lines.push("```".to_string());
        }
        lines.push(String::new());
    }

    if !recipes.is_empty() {
        lines.push("## Payload Command Recipes".to_string());
        lines.push(String::new());
        for recipe in recipes {
            lines.push(format!(
                "### {} / {}",
                title_case(&recipe.platform),
                title_case(&recipe.architecture)
            ));
            lines.push(String::new());
            lines.push(format!("- **LHOST:** {}", recipe.lhost));
            lines.push(format!("- **LPORT:** {}", recipe.lport));
            lines.push(format!("- **Format:** {}", recipe.format));
            lines.push(format!("- **Output:** {}", recipe.output_path));
            lines.push(String::new());
            lines.push("```bash".to_string());
            lines.push(recipe.command.clone());
            lines.push("```".to_string());
            lines.push(String::new());
        }
    }

    lines.push("---".to_string());
    lines.push(format!(
        "*Report generated by PloitMalper v{}*",
        env!("CARGO_PKG_VERSION")
    ));
    lines.push(String::new());

    let content = lines.join("\n");
    fs::write(output_path, content)?;
    Ok(PathBuf::from(output_path))
}

// ---------------------------------------------------------------------------
// Backward-compatible wrappers
// ---------------------------------------------------------------------------

pub fn render_findings_table(records: &[ScanRecord]) -> String {
    console_full_findings(&group_findings(records))
}

pub fn render_module_table(suggestions: &[ModuleSuggestion]) -> String {
    let mut categories = categorize_modules(suggestions);
    categories.manual_notes = manual_exploitation_notes(&[]);
    console_module_categories(&categories)
}

fn console_module_categories(categories: &ModuleCategories) -> String {
    let mut out = String::new();
    out.push_str("Metasploit Module Suggestions\n");
    if !categories.enumeration.is_empty() {
        out.push_str("Enumeration\n");
        for suggestion in &categories.enumeration {
            out.push_str(&format!(
                "✓ {} ({})\n",
                suggestion.suggested_module, suggestion.confidence
            ));
        }
    }
    if !categories.validation.is_empty() {
        out.push_str("Validation\n");
        for suggestion in &categories.validation {
            out.push_str(&format!(
                "✓ {} ({})\n",
                suggestion.suggested_module, suggestion.confidence
            ));
        }
    }
    if !categories.exploitation.is_empty() || !categories.manual_notes.is_empty() {
        out.push_str("Potential exploitation\n");
        for suggestion in &categories.exploitation {
            out.push_str(&format!(
                "✓ {} ({})\n",
                suggestion.suggested_module, suggestion.confidence
            ));
        }
        for note in &categories.manual_notes {
            out.push_str(&format!(
                "• {} (No generic Metasploit module available)\n",
                note
            ));
        }
    }
    out
}

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
    fn console_report_contains_all_sections() {
        let records = vec![
            record(
                "LDAP Injection on QUERY_STRING",
                "critical",
                "http://h/search?q=",
            ),
            record(
                "LDAP Injection on QUERY_STRING",
                "critical",
                "http://h/login?user=",
            ),
            record("Trace.axd exposed", "medium", "http://h/trace.axd"),
        ];
        let suggestions = vec![ModuleSuggestion {
            service_banner: "IIS".into(),
            suggested_module: "auxiliary/scanner/http/iis_version".into(),
            confidence: "high".into(),
        }];
        let dedup_stats = DedupStats {
            total: 3,
            unique: 2,
            removed: 1,
        };
        let output = render_console_report(&records, &[], &suggestions, &[], &dedup_stats);
        assert!(output.contains("Executive Summary"));
        assert!(output.contains("Overall Risk"));
        assert!(output.contains("Key Findings"));
        assert!(output.contains("CVE Intelligence"));
        assert!(output.contains("Exploitability Assessment"));
        assert!(output.contains("Metasploit Recommendations"));
        assert!(output.contains("Attack Chain"));
        assert!(output.contains("Full Findings"));
        assert!(output.contains("Raw Evidence"));
        assert!(output.contains("LDAP Injection"));
        assert!(output.contains("Microsoft IIS"));
    }

    #[test]
    fn no_credible_chain_rendered_without_evidence() {
        let records = vec![record("Alive (200)", "info", "http://h/")];
        let output = render_console_report(
            &records,
            &[],
            &[],
            &[],
            &DedupStats {
                total: 1,
                unique: 1,
                removed: 0,
            },
        );
        assert!(output.contains("No credible automated attack chain identified."));
    }

    #[test]
    fn markdown_report_contains_sections_and_endpoints() {
        let records = vec![record(
            "LDAP Injection on QUERY_STRING",
            "critical",
            "http://h/search?q=",
        )];
        let dedup_stats = DedupStats {
            total: 1,
            unique: 1,
            removed: 0,
        };
        let path =
            generate_markdown_report(&records, &[], &[], &[], &dedup_stats, "/tmp/pm_test.md")
                .expect("write report");
        let content = std::fs::read_to_string(&path).expect("read report");
        assert!(content.contains("## 1. Executive Summary"));
        assert!(content.contains("## 2. Risk Overview"));
        assert!(content.contains("## 4. Injectable Endpoints"));
        assert!(content.contains("## 5. CVE Intelligence"));
        assert!(content.contains("## 6. Exploitability Assessment"));
        assert!(content.contains("## 7. Metasploit Recommendations"));
        assert!(content.contains("## 9. Attack Chain"));
        assert!(content.contains("## 11. Raw Evidence"));
        assert!(content.contains("/search?q="));
        assert!(content.contains("# PloitMalper - Vulnerability Analysis Report"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn report_path_is_derived_from_input() {
        assert_eq!(
            derive_report_path(&PathBuf::from("results/scan.json")),
            PathBuf::from("results/scan_ploitmalper.md")
        );
        assert_eq!(
            derive_report_path(&PathBuf::from("/tmp/data/scan.json")),
            PathBuf::from("/tmp/data/scan_ploitmalper.md")
        );
        assert_eq!(
            derive_report_path(&PathBuf::from("scan.json")),
            PathBuf::from("scan_ploitmalper.md")
        );
    }
}
