use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedFinding {
    pub target: String,
    pub tool: String,
    pub title: String,
    pub severity: String,
    pub port: Option<u16>,
    pub cve: Option<String>,
    pub service: Option<String>,
    pub raw: serde_json::Value,
}

#[pyfunction]
fn parse_vulnmalper_json(json_input: &str) -> PyResult<String> {
    let value: serde_json::Value = serde_json::from_str(json_input)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let findings = match value {
        serde_json::Value::Array(arr) => parse_array(&arr),
        serde_json::Value::Object(obj) => {
            if let Some(results) = obj.get("results") {
                if let Some(arr) = results.as_array() {
                    parse_array(arr)
                } else {
                    vec![]
                }
            } else if let Some(findings) = obj.get("findings") {
                if let Some(arr) = findings.as_array() {
                    parse_array(arr)
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        }
        _ => vec![],
    };

    serde_json::to_string(&findings)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

fn parse_array(arr: &[serde_json::Value]) -> Vec<ParsedFinding> {
    arr.iter()
        .filter_map(|v| {
            let target = v.get("target")?.as_str()?.to_string();
            let tool = v.get("tool")?.as_str()?.to_string();
            let title = v.get("title")?.as_str()?.to_string();
            let severity = v
                .get("severity")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string();
            let port = v.get("port").and_then(|p| p.as_u64()).map(|p| p as u16);
            let cve = v.get("cve").and_then(|c| c.as_str()).map(String::from);
            let service = v
                .get("service")
                .and_then(|s| s.as_str())
                .map(String::from);
            let raw = v.clone();

            Some(ParsedFinding {
                target,
                tool,
                title,
                severity,
                port,
                cve,
                service,
                raw,
            })
        })
        .collect()
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_vulnmalper_json, m)?)?;
    Ok(())
}
