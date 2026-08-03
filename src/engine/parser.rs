use crate::error::Result;
use crate::models::{InjectableEndpoint, ParsedScan, ScanRecord};
use serde_json::Value;

pub fn parse_vulnmalper_json(json_input: &str) -> Result<Vec<ScanRecord>> {
    Ok(parse_vulnmalper_scan(json_input)?.records)
}

/// Parse a VulnMalper scan report into normalized records plus the injectable
/// endpoints the scanner flagged on each host.
pub fn parse_vulnmalper_scan(json_input: &str) -> Result<ParsedScan> {
    let value: Value = serde_json::from_str(json_input)?;

    let mut records = match &value {
        Value::Array(arr) => parse_array(arr),
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

    // Ensure every record carries its extracted CVE ids before deduplication.
    for record in &mut records {
        crate::cve::extract_into_record(record);
    }

    let injectable_endpoints = extract_injectable_endpoints(&value);

    Ok(ParsedScan {
        records,
        injectable_endpoints,
    })
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
            let detail = v
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let reference = v
                .get("reference")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            let mut record = ScanRecord {
                target,
                tool,
                title,
                severity,
                port,
                cve,
                service,
                raw: v.clone(),
                detail,
                reference,
                ..Default::default()
            };
            if record.affected_endpoints.is_empty() {
                record.affected_endpoints = crate::analyze::extract_endpoint(&record)
                    .into_iter()
                    .collect();
            }
            Some(record)
        })
        .collect()
}

/// Collect `hosts[].injectable` endpoint lists, associating each endpoint with
/// the host that reported it.
fn extract_injectable_endpoints(value: &Value) -> Vec<InjectableEndpoint> {
    let mut endpoints = Vec::new();
    let hosts = match value.as_object().and_then(|obj| obj.get("hosts")) {
        Some(Value::Array(hosts)) => hosts,
        _ => return endpoints,
    };

    for host in hosts {
        let target = host
            .get("url")
            .and_then(Value::as_str)
            .or_else(|| host.get("host").and_then(Value::as_str))
            .unwrap_or("unknown")
            .to_string();
        let injectable = match host.get("injectable") {
            Some(Value::Array(list)) => list,
            _ => continue,
        };
        for entry in injectable {
            if let Some(endpoint) = entry.as_str() {
                let endpoint = endpoint.trim().to_string();
                if endpoint.is_empty() {
                    continue;
                }
                endpoints.push(InjectableEndpoint {
                    target: target.clone(),
                    endpoint,
                });
            }
        }
    }
    endpoints
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

    #[test]
    fn captures_detail_reference_and_extracts_cves() {
        let input = r#"{
            "findings": [{
                "target": "http://10.0.0.1/",
                "tool": "nikto",
                "title": "GET /: Server leaks inodes. See: CVE-2003-1418:",
                "severity": "info",
                "detail": "GET /: Server leaks inodes. See: CVE-2003-1418",
                "reference": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418"
            }]
        }"#;
        let scan = parse_vulnmalper_scan(input).unwrap();
        let record = &scan.records[0];
        assert_eq!(
            record.detail,
            "GET /: Server leaks inodes. See: CVE-2003-1418"
        );
        assert!(record.reference.contains("cve.mitre.org"));
        assert!(record.cves.contains(&"CVE-2003-1418".to_string()));
    }

    #[test]
    fn extracts_host_injectable_endpoints() {
        let input = r#"{
            "hosts": [{
                "url": "http://192.168.1.2/",
                "host": "192.168.1.2",
                "injectable": ["http://192.168.1.2?name=1", "http://192.168.1.2?id=2"]
            }]
        }"#;
        let scan = parse_vulnmalper_scan(input).unwrap();
        assert_eq!(scan.injectable_endpoints.len(), 2);
        assert_eq!(scan.injectable_endpoints[0].target, "http://192.168.1.2/");
        assert_eq!(
            scan.injectable_endpoints[1].endpoint,
            "http://192.168.1.2?id=2"
        );
    }
}
