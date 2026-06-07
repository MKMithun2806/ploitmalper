use std::collections::HashSet;

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::models::{DedupResult, ScanRecord};

fn normalize_title(title: &str) -> String {
    let cleaned = title
        .trim()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");

    let re = Regex::new(r"\s*[/\\]\s*$").expect("valid regex");
    re.replace_all(&cleaned, "").to_string()
}

fn composite_key(record: &ScanRecord) -> String {
    let normalized = normalize_title(&record.title);
    let raw = format!("{}|{}|{}", record.target, record.tool, normalized);
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn deduplicate_records(records: Vec<ScanRecord>) -> DedupResult {
    let total_count = records.len();
    let mut seen: HashSet<String> = HashSet::new();
    let mut unique_records = Vec::new();

    for record in records {
        let key = composite_key(&record);
        if seen.insert(key) {
            unique_records.push(record);
        }
    }

    let unique_count = unique_records.len();
    let removed_count = total_count.saturating_sub(unique_count);

    DedupResult {
        unique_count,
        removed_count,
        records: unique_records,
    }
}

pub fn normalize_title_text(title: &str) -> String {
    normalize_title(title)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ScanRecord;
    use serde_json::json;

    #[test]
    fn deduplicates_on_normalized_title() {
        let records = vec![
            ScanRecord {
                target: "10.0.0.1".into(),
                tool: "nmap".into(),
                title: "Apache Version /".into(),
                severity: "high".into(),
                port: Some(80),
                cve: None,
                service: Some("apache".into()),
                raw: json!({}),
                ..Default::default()
            },
            ScanRecord {
                target: "10.0.0.1".into(),
                tool: "nmap".into(),
                title: "apache version".into(),
                severity: "high".into(),
                port: Some(80),
                cve: None,
                service: Some("apache".into()),
                raw: json!({}),
                ..Default::default()
            },
        ];

        let result = deduplicate_records(records);
        assert_eq!(result.unique_count, 1);
        assert_eq!(result.removed_count, 1);
    }
}
