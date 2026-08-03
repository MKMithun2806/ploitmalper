use std::collections::BTreeSet;

use regex::Regex;
use serde_json::Value;

use crate::models::ScanRecord;

/// Matches CVE ids in their canonical form. The trailing sequence can be 4
/// digits (legacy) or up to 7 digits (2014+ scheme); the boundary guards
/// against matching inside a longer alphanumeric token.
fn cve_regex() -> Regex {
    Regex::new(r"(?i)\bCVE-\d{4}-\d{4,7}\b").expect("valid CVE regex")
}

/// Extract every CVE id present in a piece of free-form text, including ids
/// embedded inside URLs (e.g. `...cvename.cgi?name=CVE-2003-1418`).
pub fn extract_cves(text: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    for capture in cve_regex().captures_iter(text) {
        if let Some(found) = capture.get(0) {
            seen.insert(found.as_str().to_uppercase());
        }
    }
    seen.into_iter().collect()
}

/// Search a parsed JSON value (recursively) for CVE ids in string fields.
pub fn extract_cves_from_json(value: &Value) -> Vec<String> {
    let mut all = Vec::new();
    collect_strings(value, &mut all);
    let joined = all.join("\n");
    extract_cves(&joined)
}

fn collect_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => out.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                collect_strings(item, out);
            }
        }
        Value::Object(map) => {
            for field in map.values() {
                collect_strings(field, out);
            }
        }
        _ => {}
    }
}

/// Populate `record.cves` from every available field (title, detail,
/// reference, raw). The legacy single `cve` field is kept as the first id.
pub fn extract_into_record(record: &mut ScanRecord) {
    let mut discovered = Vec::new();
    discovered.extend(extract_cves(&record.title));
    discovered.extend(extract_cves(&record.detail));
    discovered.extend(extract_cves(&record.reference));
    if let Some(cve) = record.cve.as_deref() {
        discovered.extend(extract_cves(cve));
    }
    discovered.extend(extract_cves_from_json(&record.raw));

    let mut seen = BTreeSet::new();
    record.cves = discovered
        .into_iter()
        .filter(|id| seen.insert(id.clone()))
        .collect();

    if record.cve.is_none() {
        record.cve = record.cves.first().cloned();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_from_free_text() {
        let cves = extract_cves(
            "See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418 and CVE-2021-44228",
        );
        assert_eq!(
            cves,
            vec!["CVE-2003-1418".to_string(), "CVE-2021-44228".to_string()]
        );
    }

    #[test]
    fn handles_newer_and_legacy_id_lengths() {
        assert_eq!(extract_cves("CVE-2014-1234"), vec!["CVE-2014-1234"]);
        assert_eq!(extract_cves("CVE-2024-1234567"), vec!["CVE-2024-1234567"]);
    }

    #[test]
    fn rejects_bad_ids_and_case_insensitive() {
        assert!(extract_cves("CVE-99-12").is_empty());
        assert!(extract_cves("CVE-2021-44").is_empty());
        assert_eq!(extract_cves("cve-2003-1418"), vec!["CVE-2003-1418"]);
    }

    #[test]
    fn scans_json_recursively() {
        let value = json!({
            "nested": {"data": "ref CVE-2022-22965"},
            "list": ["CVE-2021-41773"]
        });
        let mut cves = extract_cves_from_json(&value);
        cves.sort();
        assert_eq!(
            cves,
            vec!["CVE-2021-41773".to_string(), "CVE-2022-22965".to_string()]
        );
    }

    #[test]
    fn populates_record_cves() {
        let mut record = ScanRecord {
            title: "Apache CVE-2021-41773 RCE".into(),
            detail: "reference CVE-2021-44228".into(),
            ..Default::default()
        };
        extract_into_record(&mut record);
        assert_eq!(
            record.cves,
            vec!["CVE-2021-41773".to_string(), "CVE-2021-44228".to_string()]
        );
        assert_eq!(record.cve.as_deref(), Some("CVE-2021-41773"));
    }
}
