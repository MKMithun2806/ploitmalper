use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub target: String,
    pub tool: String,
    pub title: String,
    pub severity: String,
    pub port: Option<u16>,
    pub cve: Option<String>,
    pub raw: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupResult {
    pub unique_count: usize,
    pub removed_count: usize,
    pub records: Vec<ScanRecord>,
}

fn normalize_title(title: &str) -> String {
    let cleaned = title
        .trim()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");

    let re = regex::Regex::new(r"\s*[/\\]\s*$").unwrap();
    re.replace_all(&cleaned, "").to_string()
}

fn composite_key(record: &ScanRecord) -> String {
    let normalized = normalize_title(&record.title);
    let raw = format!("{}|{}|{}", record.target, record.tool, normalized);
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[pyfunction]
fn deduplicate_records(json_input: &str) -> PyResult<String> {
    let records: Vec<ScanRecord> = serde_json::from_str(json_input)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let total_count = records.len();
    let mut seen: HashMap<String, ScanRecord> = HashMap::new();

    for record in records {
        let key = composite_key(&record);
        seen.entry(key).or_insert(record);
    }

    let unique_count = seen.len();
    let removed_count = total_count.saturating_sub(unique_count);
    let records: Vec<ScanRecord> = seen.into_values().collect();

    let result = DedupResult {
        unique_count,
        removed_count,
        records,
    };

    serde_json::to_string(&result)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn normalize_title_py(title: &str) -> String {
    normalize_title(title)
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(deduplicate_records, m)?)?;
    m.add_function(wrap_pyfunction!(normalize_title_py, m)?)?;
    Ok(())
}
