use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::Result;
use crate::models::{DedupStats, ModuleSuggestion, PayloadRecipe, ScanRecord};

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

fn cvss_label(score: Option<f32>) -> String {
    match score {
        None => "—".to_string(),
        Some(score) => format!("{score:.1}"),
    }
}

pub fn render_findings_table(records: &[ScanRecord]) -> String {
    let has_nvd = records.iter().any(|record| record.nvd_cvss_v3.is_some());
    let mut rows = Vec::new();

    for (idx, record) in records.iter().enumerate() {
        let mut row = vec![
            (idx + 1).to_string(),
            truncate(&record.target, 18),
            truncate(&record.tool, 10),
            truncate(&record.title, 35),
            record.severity.to_uppercase(),
            record
                .port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "—".to_string()),
            record.cve.clone().unwrap_or_else(|| "—".to_string()),
        ];

        if has_nvd {
            row.push(cvss_label(record.nvd_cvss_v3));
        }

        rows.push(row);
    }

    let mut headers = vec!["#", "Target", "Tool", "Title", "Severity", "Port", "CVE"];
    if has_nvd {
        headers.push("CVSS v3");
    }

    ascii_table("Deduplicated Vulnerability Findings", &headers, &rows)
}

pub fn render_module_table(suggestions: &[ModuleSuggestion]) -> String {
    let rows = suggestions
        .iter()
        .map(|sug| {
            vec![
                truncate(&sug.service_banner, 24),
                truncate(&sug.suggested_module, 54),
                sug.confidence.to_uppercase(),
            ]
        })
        .collect::<Vec<_>>();

    ascii_table(
        "Metasploit Module Suggestions",
        &["Service Banner", "Suggested Module", "Confidence"],
        &rows,
    )
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
    lines.push("**Tool Version:** 0.1.0".to_string());
    lines.push(String::new());

    lines.push("## Executive Summary".to_string());
    lines.push(String::new());
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

    let mut severity_counts = BTreeMap::<String, usize>::new();
    for record in records {
        let severity = record.severity.to_lowercase();
        *severity_counts.entry(severity).or_insert(0) += 1;
    }

    lines.push("### Severity Distribution".to_string());
    lines.push(String::new());
    for severity in ["critical", "high", "medium", "low", "info", "unknown"] {
        if let Some(count) = severity_counts.get(severity) {
            if *count > 0 {
                lines.push(format!("- **{}:** {}", severity.to_uppercase(), count));
            }
        }
    }
    lines.push(String::new());

    lines.push("## Findings".to_string());
    lines.push(String::new());

    if has_nvd {
        lines.push(
            "| # | Target | Tool | Title | Severity | Port | CVE | CVSS v3 | NVD Severity |"
                .to_string(),
        );
        lines.push(
            "|---|--------|------|-------|----------|------|-----|---------|--------------|"
                .to_string(),
        );
        for (idx, record) in records.iter().enumerate() {
            let cvss = record
                .nvd_cvss_v3
                .map(|value| format!("{value:.1}"))
                .unwrap_or_else(|| "—".to_string());
            let nvd_sev = record
                .nvd_cvss_v3_severity
                .clone()
                .unwrap_or_else(|| "—".to_string())
                .to_uppercase();
            lines.push(format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                idx + 1,
                md_escape(&record.target),
                md_escape(&record.tool),
                md_escape(&record.title),
                record.severity.to_uppercase(),
                record
                    .port
                    .map(|port| port.to_string())
                    .unwrap_or_else(|| "—".to_string()),
                md_escape(record.cve.as_deref().unwrap_or("—")),
                cvss,
                nvd_sev
            ));
        }
    } else {
        lines.push("| # | Target | Tool | Title | Severity | Port | CVE |".to_string());
        lines.push("|---|--------|------|-------|----------|------|-----|".to_string());
        for (idx, record) in records.iter().enumerate() {
            lines.push(format!(
                "| {} | {} | {} | {} | {} | {} | {} |",
                idx + 1,
                md_escape(&record.target),
                md_escape(&record.tool),
                md_escape(&record.title),
                record.severity.to_uppercase(),
                record
                    .port
                    .map(|port| port.to_string())
                    .unwrap_or_else(|| "—".to_string()),
                md_escape(record.cve.as_deref().unwrap_or("—"))
            ));
        }
    }
    lines.push(String::new());

    if has_nvd {
        lines.push("## CVE Details (NVD)".to_string());
        lines.push(String::new());
        for record in records {
            let cve = match record.cve.as_ref() {
                Some(cve) => cve,
                None => continue,
            };

            lines.push(format!("### {}", cve));
            lines.push(String::new());
            if let Some(cvss) = record.nvd_cvss_v3 {
                lines.push(format!("- **CVSS v3 Score:** {:.1}", cvss));
            }
            if let Some(severity) = record.nvd_cvss_v3_severity.as_ref() {
                lines.push(format!("- **NVD Severity:** {}", severity.to_uppercase()));
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

    if !suggestions.is_empty() {
        lines.push("## Metasploit Module Suggestions".to_string());
        lines.push(String::new());
        lines.push("| Service Banner | Suggested Module | Confidence |".to_string());
        lines.push("|---------------|------------------|------------|".to_string());
        for suggestion in suggestions {
            lines.push(format!(
                "| {} | `{}` | {} |",
                md_escape(&suggestion.service_banner),
                suggestion.suggested_module,
                suggestion.confidence.to_uppercase()
            ));
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
    lines.push("*Report generated by PloitMalper v0.1.0*".to_string());
    lines.push(String::new());

    let content = lines.join("\n");
    fs::write(output_path, content)?;
    Ok(PathBuf::from(output_path))
}

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
