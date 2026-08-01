use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::analyze::{
    build_attack_path, build_scan_summary, categorize_modules, compute_risk_score, group_findings,
    manual_exploitation_notes, map_mitre,
};
use crate::enrich;
use crate::error::Result;
use crate::models::{
    CVEExtraInfo, DedupStats, FindingGroup, ModuleCategories, ModuleSuggestion, PayloadRecipe,
    ScanRecord, ScanSummary,
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

// ---------------------------------------------------------------------------
// Console rendering
// ---------------------------------------------------------------------------

pub fn render_scan_summary(summary: &ScanSummary) -> String {
    let mut out = String::new();
    out.push_str("Scan Summary\n");
    out.push_str("────────────\n");
    out.push('\n');
    out.push_str(&format!("Host: {}\n", summary.host));
    if let Some(server) = &summary.server {
        out.push_str(&format!("Server: {}\n", server));
    }
    if let Some(framework) = &summary.framework {
        out.push_str(&format!("Framework: {}\n", framework));
    }
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

    if !summary.top_risks.is_empty() {
        out.push('\n');
        out.push_str("Top Risks\n");
        for risk in &summary.top_risks {
            out.push_str(&format!("✓ {}\n", risk));
        }
    }
    out
}

pub fn render_risk_score(records: &[ScanRecord]) -> String {
    let risk = compute_risk_score(records);
    let mut out = String::new();
    out.push_str(&format!("Overall Risk: {}/100\n", risk.score));
    out.push_str(&risk.bar);
    out.push_str("\n\nReason:\n");
    for reason in &risk.reasons {
        out.push_str(&format!("• {}\n", reason));
    }
    out
}

pub fn render_finding_groups(groups: &[FindingGroup]) -> String {
    let mut out = String::new();

    let rows = groups
        .iter()
        .enumerate()
        .map(|(idx, group)| {
            vec![
                (idx + 1).to_string(),
                truncate(&group.title, 34),
                group.severity.to_uppercase(),
                group.count.to_string(),
                if group.affected_endpoints.is_empty() {
                    "—".to_string()
                } else {
                    group.affected_endpoints.len().to_string()
                },
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
            "Deduplicated Vulnerability Findings",
            &["#", "Finding", "Severity", "Count", "Endpoints", "CVE"],
            &rows,
        ));
        out.push('\n');
    }

    let groups_with_endpoints = groups
        .iter()
        .filter(|group| !group.affected_endpoints.is_empty())
        .collect::<Vec<_>>();
    if !groups_with_endpoints.is_empty() {
        out.push_str("Affected endpoints\n");
        for (idx, group) in groups_with_endpoints.iter().enumerate() {
            out.push_str(&format!("  {}. {}\n", idx + 1, group.title));
            for endpoint in &group.affected_endpoints {
                out.push_str(&format!("     • {}\n", endpoint));
            }
        }
    }
    out
}

pub fn render_module_categories(categories: &ModuleCategories) -> String {
    let mut out = String::new();
    out.push_str("Metasploit Module Suggestions\n");

    if !categories.enumeration.is_empty() {
        out.push_str("Enumeration\n");
        out.push_str("------------\n");
        for suggestion in &categories.enumeration {
            out.push_str(&format!(
                "✓ {} ({})\n",
                suggestion.suggested_module, suggestion.confidence
            ));
        }
        out.push('\n');
    }

    if !categories.validation.is_empty() {
        out.push_str("Validation\n");
        out.push_str("----------\n");
        for suggestion in &categories.validation {
            out.push_str(&format!(
                "✓ {} ({})\n",
                suggestion.suggested_module, suggestion.confidence
            ));
        }
        out.push('\n');
    }

    if !categories.exploitation.is_empty() || !categories.manual_notes.is_empty() {
        out.push_str("Potential exploitation\n");
        out.push_str("----------------------\n");
        for suggestion in &categories.exploitation {
            out.push_str(&format!(
                "✓ {} ({})\n",
                suggestion.suggested_module, suggestion.confidence
            ));
        }
        for note in &categories.manual_notes {
            out.push_str(&format!(
                "• {}\n  (No generic Metasploit module available)\n",
                note
            ));
        }
        out.push('\n');
    }

    if out.trim_end().is_empty() {
        out.push_str("(none)\n");
    }
    out
}

pub fn render_attack_path(records: &[ScanRecord]) -> String {
    let steps = build_attack_path(records);
    let mut out = String::new();
    out.push_str("Possible Attack Chain\n");
    for (idx, step) in steps.iter().enumerate() {
        if idx > 0 {
            out.push_str("     │\n     ▼\n");
        }
        out.push_str(&format!("{}\n", step));
    }
    out
}

pub fn render_mitre(records: &[ScanRecord]) -> String {
    let tactics = map_mitre(records);
    let mut out = String::new();
    out.push_str("MITRE ATT&CK Mapping\n");
    if tactics.is_empty() {
        out.push_str("(no applicable tactics)\n");
        return out;
    }
    for tactic in &tactics {
        out.push_str(&tactic.tactic);
        out.push('\n');
        out.push_str(&"─".repeat(tactic.tactic.chars().count()));
        out.push('\n');
        for technique in &tactic.techniques {
            out.push_str(&format!("✓ {}\n", technique));
        }
        if tactic.tactic == "Credential Access"
            && records.iter().any(|record| {
                let text = record.title.to_lowercase();
                text.contains("sql injection") || text.contains("ldap injection")
            })
        {
            out.push_str("Possible SQL/LDAP credential extraction\n");
        }
        out.push('\n');
    }
    out
}

fn render_cve_block(record: &ScanRecord, extra: Option<&CVEExtraInfo>) -> Option<String> {
    let cve = record.cve.as_deref()?;
    let mut lines = Vec::new();
    lines.push(cve.to_string());
    if let Some(cvss) = record.nvd_cvss_v3 {
        lines.push(format!("  CVSS: {:.1}", cvss));
    }
    if let Some(extra) = extra {
        lines.push(format!("  EPSS: {}", enrich::epss_percent(extra.epss)));
        lines.push(format!(
            "  Known Exploited: {}",
            if extra.in_kev { "YES" } else { "NO" }
        ));
        lines.push(format!(
            "  Public exploit: {}",
            if extra.public_exploit { "YES" } else { "NO" }
        ));
        if !extra.metasploit_modules.is_empty() {
            lines.push("  Metasploit:".to_string());
            for module in &extra.metasploit_modules {
                lines.push(format!("    {}", module));
            }
        }
    }
    if let Some(description) = record.nvd_description.as_deref() {
        if !description.is_empty() {
            lines.push(format!("  Description: {}", truncate(description, 100)));
        }
    }
    Some(lines.join("\n"))
}

pub fn render_cve_enrichment(records: &[ScanRecord]) -> String {
    let mut out = String::new();
    out.push_str("CVE Enrichment\n");
    let mut rendered = 0usize;
    for record in records {
        if record.cve.is_none() {
            continue;
        }
        let extra = record.cve.as_deref().and_then(enrich::enrich_cve);
        if let Some(block) = render_cve_block(record, extra.as_ref()) {
            out.push_str(&block);
            out.push('\n');
            rendered += 1;
        }
    }
    if rendered == 0 {
        out.push_str("(no CVEs in findings)\n");
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

pub fn render_console_report(
    records: &[ScanRecord],
    suggestions: &[ModuleSuggestion],
    recipes: &[PayloadRecipe],
) -> String {
    let summary = build_scan_summary(records);
    let groups = group_findings(records);
    let mut categories = categorize_modules(suggestions);
    categories.manual_notes = manual_exploitation_notes(records);

    let mut out = String::new();
    out.push_str(&render_scan_summary(&summary));
    out.push('\n');
    out.push_str(&render_risk_score(records));
    out.push('\n');
    out.push_str(&render_finding_groups(&groups));
    out.push('\n');
    out.push_str(&render_module_categories(&categories));
    out.push('\n');
    out.push_str(&render_attack_path(records));
    out.push('\n');
    out.push_str(&render_mitre(records));
    out.push('\n');
    out.push_str(&render_cve_enrichment(records));
    if !recipes.is_empty() {
        out.push('\n');
        out.push_str(&render_recipes(recipes));
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

pub fn generate_markdown_report(
    records: &[ScanRecord],
    suggestions: &[ModuleSuggestion],
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

    // Executive summary
    let summary = build_scan_summary(records);
    let risk = compute_risk_score(records);

    lines.push("## Executive Summary".to_string());
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
    lines.push(format!("- **Duplicates removed:** {}", dedup_stats.removed));
    if has_nvd {
        lines.push("- **NVD enrichment:** Enabled".to_string());
    }
    lines.push(String::new());

    lines.push(format!("## Overall Risk: {}/100", risk.score));
    lines.push(String::new());
    lines.push(format!("`{}`", risk.bar));
    lines.push(String::new());
    for reason in &risk.reasons {
        lines.push(format!("- {}", reason));
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

    if !summary.top_risks.is_empty() {
        lines.push("### Top Risks".to_string());
        lines.push(String::new());
        for risk in &summary.top_risks {
            lines.push(format!("- **✓** {}", risk));
        }
        lines.push(String::new());
    }

    // Findings with affected endpoints
    let groups = group_findings(records);
    lines.push("## Findings".to_string());
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

    let groups_with_endpoints = groups
        .iter()
        .filter(|group| !group.affected_endpoints.is_empty())
        .collect::<Vec<_>>();
    if !groups_with_endpoints.is_empty() {
        lines.push("### Affected endpoints".to_string());
        lines.push(String::new());
        for (idx, group) in groups_with_endpoints.iter().enumerate() {
            lines.push(format!("**{}. {}**", idx + 1, group.title));
            lines.push(String::new());
            for endpoint in &group.affected_endpoints {
                lines.push(format!("- `{}`", md_escape(endpoint)));
            }
            lines.push(String::new());
        }
    }

    // Attack chain
    let path = build_attack_path(records);
    if !path.is_empty() {
        lines.push("## Possible Attack Chain".to_string());
        lines.push(String::new());
        lines.push("```text".to_string());
        for (idx, step) in path.iter().enumerate() {
            if idx > 0 {
                lines.push("     │".to_string());
                lines.push("     ▼".to_string());
            }
            lines.push(step.clone());
        }
        lines.push("```".to_string());
        lines.push(String::new());
    }

    // MITRE ATT&CK
    let tactics = map_mitre(records);
    if !tactics.is_empty() {
        lines.push("## MITRE ATT&CK Mapping".to_string());
        lines.push(String::new());
        for tactic in &tactics {
            lines.push(format!("### {}", tactic.tactic));
            lines.push(String::new());
            for technique in &tactic.techniques {
                lines.push(format!("- ✓ {}", technique));
            }
            if tactic.tactic == "Credential Access"
                && records.iter().any(|record| {
                    record.title.to_lowercase().contains("sql injection")
                        || record.title.to_lowercase().contains("ldap injection")
                })
            {
                lines.push("- Possible SQL/LDAP credential extraction".to_string());
            }
            lines.push(String::new());
        }
    }

    // Metasploit module suggestions by category
    if !suggestions.is_empty() {
        let mut categories = categorize_modules(suggestions);
        categories.manual_notes = manual_exploitation_notes(records);
        lines.push("## Metasploit Module Suggestions".to_string());
        lines.push(String::new());

        if !categories.enumeration.is_empty() {
            lines.push("### Enumeration".to_string());
            lines.push(String::new());
            for suggestion in &categories.enumeration {
                lines.push(format!(
                    "- `{}` ({})",
                    suggestion.suggested_module, suggestion.confidence
                ));
            }
            lines.push(String::new());
        }

        if !categories.validation.is_empty() {
            lines.push("### Validation".to_string());
            lines.push(String::new());
            for suggestion in &categories.validation {
                lines.push(format!(
                    "- `{}` ({})",
                    suggestion.suggested_module, suggestion.confidence
                ));
            }
            lines.push(String::new());
        }

        if !categories.exploitation.is_empty() || !categories.manual_notes.is_empty() {
            lines.push("### Potential Exploitation".to_string());
            lines.push(String::new());
            for suggestion in &categories.exploitation {
                lines.push(format!(
                    "- `{}` ({})",
                    suggestion.suggested_module, suggestion.confidence
                ));
            }
            for note in &categories.manual_notes {
                lines.push(format!(
                    "- {} (No generic Metasploit module available)",
                    note
                ));
            }
            lines.push(String::new());
        }
    }

    // CVE details
    if has_nvd || records.iter().any(|record| record.cve.is_some()) {
        lines.push("## CVE Details".to_string());
        lines.push(String::new());
        for record in records {
            let cve = match record.cve.as_ref() {
                Some(cve) => cve,
                None => continue,
            };
            let extra = enrich::enrich_cve(cve);

            lines.push(format!("### {}", cve));
            lines.push(String::new());
            if let Some(cvss) = record.nvd_cvss_v3 {
                lines.push(format!("- **CVSS v3 Score:** {:.1}", cvss));
            }
            if let Some(severity) = record.nvd_cvss_v3_severity.as_ref() {
                lines.push(format!("- **NVD Severity:** {}", severity.to_uppercase()));
            }
            if let Some(extra) = &extra {
                lines.push(format!("- **EPSS:** {}", enrich::epss_percent(extra.epss)));
                lines.push(format!(
                    "- **Known Exploited (CISA KEV):** {}",
                    if extra.in_kev { "YES" } else { "NO" }
                ));
                lines.push(format!(
                    "- **Public exploit:** {}",
                    if extra.public_exploit { "YES" } else { "NO" }
                ));
                if !extra.metasploit_modules.is_empty() {
                    lines.push("- **Metasploit:**".to_string());
                    for module in &extra.metasploit_modules {
                        lines.push(format!("  - `{}`", module));
                    }
                }
            }
            if let Some(published) = record.nvd_published.as_ref() {
                lines.push(format!("- **Published:** {}", published));
            }
            if let Some(description) = record.nvd_description.as_ref() {
                if !description.is_empty() {
                    lines.push(format!("- **Description:** {}", description));
                }
            }
            if !record.nvd_references.is_empty() {
                lines.push("- **References:**".to_string());
                for reference in &record.nvd_references {
                    lines.push(format!("  - {}", reference));
                }
            }
            lines.push(String::new());
        }
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
    render_finding_groups(&group_findings(records))
}

pub fn render_module_table(suggestions: &[ModuleSuggestion]) -> String {
    render_module_categories(&categorize_modules(suggestions))
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
        let output = render_console_report(&records, &suggestions, &[]);
        assert!(output.contains("Scan Summary"));
        assert!(output.contains("Overall Risk"));
        assert!(output.contains("LDAP Injection"));
        assert!(output.contains("/search?q="));
        assert!(output.contains("Microsoft IIS"));
        assert!(output.contains("Possible Attack Chain"));
        assert!(output.contains("MITRE ATT&CK Mapping"));
        assert!(output.contains("CVE Enrichment"));
    }

    #[test]
    fn markdown_report_contains_risk_and_endpoints() {
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
        let path = generate_markdown_report(&records, &[], &[], &dedup_stats, "/tmp/pm_test.md")
            .expect("write report");
        let content = std::fs::read_to_string(&path).expect("read report");
        assert!(content.contains("Overall Risk"));
        assert!(content.contains("Affected endpoints"));
        assert!(content.contains("/search?q="));
        let _ = std::fs::remove_file(path);
    }
}
