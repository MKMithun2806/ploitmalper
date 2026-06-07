use crate::error::Result;
use crate::models::ScanRecord;
use serde_json::Value;

pub fn parse_vulnmalper_json(json_input: &str) -> Result<Vec<ScanRecord>> {
    let value: Value = serde_json::from_str(json_input)?;
    let findings = match value {
        Value::Array(arr) => parse_array(&arr),
        Value::Object(obj) => {
            if let Some(arr) = obj.get("results").and_then(Value::as_array) {
                parse_array(arr)
            } else if let Some(arr) = obj.get("findings").and_then(Value::as_array) {
                parse_array(arr)
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    };

    Ok(findings)
}

fn parse_array(arr: &[Value]) -> Vec<ScanRecord> {
    arr.iter()
        .filter_map(|v| {
            let target = v.get("target")?.as_str()?.to_string();
            let tool = v.get("tool")?.as_str()?.to_string();
            let title = v.get("title")?.as_str()?.to_string();
            let severity = v
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let port = v
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok());
            let cve = v.get("cve").and_then(Value::as_str).map(ToOwned::to_owned);
            let service = v
                .get("service")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);

            Some(ScanRecord {
                target,
                tool,
                title,
                severity,
                port,
                cve,
                service,
                raw: v.clone(),
                ..Default::default()
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_results_array() {
        let input = r#"{"results":[{"target":"10.0.0.1","tool":"nmap","title":"OpenSSH","severity":"high"}]}"#;
        let records = parse_vulnmalper_json(input).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].target, "10.0.0.1");
    }
}
