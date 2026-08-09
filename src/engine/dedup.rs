use std::collections::HashMap;

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::analyze::extract_endpoint;
use crate::models::{DedupResult, ScanRecord};

/// Structured endpoint parts parsed from a raw URL/path so fingerprinting is
/// immune to scheme, casing, and host-framing noise.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EndpointParts {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
    pub query: String,
}

/// Normalize a target for comparison so `http://h/` and `http://h` merge,
/// while a distinct path keeps records separated.
pub fn normalize_target(target: &str) -> String {
    let lower = target.trim().to_lowercase();
    let stripped = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);
    let mut host = stripped.trim_end_matches('/').to_string();

    // Keep the path portion so `/`, `/index.html` and `/admin` stay distinct.
    let host_part;
    if let Some(idx) = host.find('/') {
        host_part = host[..idx].to_string();
    } else {
        host_part = host.clone();
        host = host_part.clone();
    }
    if host_part.is_empty() {
        return host.clone();
    }

    // Strip a `:port` suffix unless this is an IPv6 literal.
    if host_part.parse::<std::net::Ipv6Addr>().is_err() {
        if let Some(colon) = host_part.rfind(':') {
            let after = &host_part[colon + 1..];
            if !after.is_empty() && after.chars().all(|c| c.is_ascii_digit()) {
                let rest = &host[host_part.len()..];
                return format!("{}{}", &host_part[..colon], rest);
            }
        }
    }
    host
}

/// Parse an endpoint (URL or path) into structured components. Safe on
/// arbitrary scanner output: any malformed input degrades to empty parts.
pub fn parse_endpoint_parts(value: &str) -> EndpointParts {
    let value = value.trim();
    if value.is_empty() {
        return EndpointParts::default();
    }

    let (scheme, rest) = match value.split_once("://") {
        Some((scheme, rest)) => (scheme.to_lowercase(), rest),
        None => (String::new(), value),
    };

    let (authority, path_and_query) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };

    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (path_and_query.to_string(), String::new()),
    };
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path
    };

    let (host, port) = parse_authority(authority);
    EndpointParts {
        scheme,
        host,
        port,
        path,
        query,
    }
}

fn parse_authority(authority: &str) -> (String, Option<u16>) {
    // IPv6 literal like `[::1]:8080`.
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            let host = rest[..close].to_string();
            let after = &rest[close + 1..];
            let port = after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return (host, port);
        }
    }
    if let Some(colon) = authority.rfind(':') {
        if let Ok(port) = authority[colon + 1..].parse::<u16>() {
            return (authority[..colon].to_string(), Some(port));
        }
    }
    (authority.to_string(), None)
}

/// First parameter name in a query string, used to fingerprint injectable
/// endpoints neutrally (param name, not value).
fn first_parameter(query: &str) -> Option<String> {
    let first = query.split('&').next()?;
    let key = first.split('=').next()?.trim();
    if key.is_empty() {
        None
    } else {
        Some(key.to_string())
    }
}

fn normalize_key(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Normalize a finding title for deduplication:
///
/// * strip leading HTTP method prefixes (`GET`, `POST`, ...)
/// * normalize endpoint prefixes so `"/:"`, `"GET /:"` and `"/"` collapse
/// * remove trailing and duplicated punctuation (e.g. stray `:` / `.`)
/// * strip trailing reference URLs (they are truncated at arbitrary lengths)
/// * collapse whitespace
/// * lowercase (case-insensitive comparison)
///
/// The raw title is preserved on the record (`raw_findings`) for reporting.
pub fn normalize_title(title: &str) -> String {
    let mut text = title.trim().to_lowercase();

    // Strip leading HTTP verbs (GET/POST/HEAD/...).
    text = Regex::new(r"^\s*(get|post|put|head|delete|patch|options|trace|connect)\s+")
        .expect("valid method regex")
        .replace(&text, "")
        .to_string();

    // Normalize leading endpoint markers ("/:", "/", "GET /:" → no prefix).
    text = text.trim_start_matches('/').trim_start().to_string();
    text = text.trim_start_matches(':').trim_start().to_string();

    // Drop trailing reference material: "See: <url>" (which scanners truncate
    // at arbitrary lengths) or "See: <CVE>" noise. A bare trailing CVE id is
    // preserved because it is the finding itself.
    text =
        Regex::new(r"\s*(?:(?:see\s*:?\s*)?https?://\S+|\bsee\s*:?\s*cve-\d{4}-\d{3,7})\s*:?\s*$")
            .expect("valid reference regex")
            .replace(&text, "")
            .to_string();

    // Collapse whitespace.
    text = text.split_whitespace().collect::<Vec<_>>().join(" ");

    // Collapse `|`-framed scanner output: treat `|` as a pure segment
    // separator and drop empty segments, so `"GET / |"` and `"GET / "`
    // frame the same finding. Meaningful non-empty segments are preserved.
    text = text
        .split('|')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("|");

    // Strip trailing punctuation and path separators, then re-trim.
    text = text
        .trim_matches(|c: char| ".,:;\\/|".contains(c))
        .trim()
        .to_string();

    text
}

/// Stable structured fingerprint for a record, built from normalized fields
/// (asset, service/port, type, endpoint path and parameter) rather than from
/// raw, framing-prone scanner strings. Empty optional fields are dropped so a
/// record that simply lacks a port/service never accidentally forks identity.
fn fingerprint_segments(record: &ScanRecord) -> Vec<String> {
    let mut segments = vec![normalize_target(&record.target)];

    if let Some(port) = record.port {
        segments.push(format!("port:{}", port));
    }
    if let Some(service) = record.service.as_deref() {
        let service = normalize_key(service);
        if !service.is_empty() {
            segments.push(format!("service:{}", service));
        }
    }

    let normalized = normalize_title(&record.title);
    if !normalized.is_empty() {
        segments.push(format!("type:{}", normalized));
    }

    if let Some(endpoint) = extract_endpoint(record) {
        let parts = parse_endpoint_parts(&endpoint);
        // Trim framing delimiters off the path so `...CSP` and `...CSP:` and
        // `/admin/` merge, while genuinely different paths stay distinct.
        let path = normalize_path(&parts.path);
        if !path.is_empty() {
            segments.push(format!("path:{}", path));
        }
        if let Some(param) = first_parameter(&parts.query) {
            segments.push(format!("param:{}", param));
        }
    }

    segments
}

fn normalize_path(path: &str) -> String {
    path.trim()
        .trim_end_matches(|c: char| ".,:;\\/|".contains(c))
        .trim()
        .to_lowercase()
}

fn composite_key(record: &ScanRecord) -> String {
    let raw = fingerprint_segments(record).join("|");
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn deduplicate_records(records: Vec<ScanRecord>) -> DedupResult {
    let total_count = records.len();
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut unique_records = Vec::new();

    for mut record in records {
        let key = composite_key(&record);
        record.normalized_title = normalize_title(&record.title);
        record.merged_count = 1;
        record.raw_findings = vec![record.title.clone()];

        if let Some(&existing_idx) = seen.get(&key) {
            merge_record(&mut unique_records[existing_idx], &record);
        } else {
            if record.affected_endpoints.is_empty() {
                record.affected_endpoints = extract_endpoint(&record).into_iter().collect();
            }
            seen.insert(key, unique_records.len());
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

/// Merge a duplicate into the kept record, preserving every piece of
/// scanner evidence and aggregating endpoints, CVEs, tools and count.
fn merge_record(kept: &mut ScanRecord, duplicate: &ScanRecord) {
    kept.merged_count += 1;

    if let Some(endpoint) = extract_endpoint(duplicate) {
        if !kept.affected_endpoints.contains(&endpoint) {
            kept.affected_endpoints.push(endpoint);
        }
    }
    for cve in &duplicate.cves {
        if !kept.cves.contains(cve) {
            kept.cves.push(cve.clone());
        }
    }
    if kept.cve.is_none() {
        kept.cve = duplicate.cve.clone();
    }
    if kept.service.is_none() {
        kept.service = duplicate.service.clone();
    }
    if kept.port.is_none() {
        kept.port = duplicate.port;
    }
    if kept.detail.is_empty() {
        kept.detail = duplicate.detail.clone();
    }
    if kept.reference.is_empty() {
        kept.reference = duplicate.reference.clone();
    }
    for raw in &duplicate.raw_findings {
        if !kept.raw_findings.contains(raw) {
            kept.raw_findings.push(raw.clone());
        }
    }

    // Keep the most severe classification across merged records.
    if crate::analyze::severity_rank(&duplicate.severity)
        < crate::analyze::severity_rank(&kept.severity)
    {
        kept.severity = duplicate.severity.clone();
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

    fn record(title: &str, target: &str) -> ScanRecord {
        ScanRecord {
            target: target.into(),
            tool: "nikto".into(),
            title: title.into(),
            severity: "low".into(),
            raw: json!({}),
            ..Default::default()
        }
    }

    #[test]
    fn strips_http_method_and_endpoint_prefix() {
        assert_eq!(
            normalize_title("/: Suggested security header missing: content-security-policy"),
            normalize_title("GET /: Suggested security header missing: content-security-policy")
        );
    }

    #[test]
    fn removes_trailing_punctuation_and_truncated_urls() {
        let with_url = normalize_title(
            "GET /: Suggested security header missing: content-security-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP:",
        );
        let truncated_url = normalize_title(
            "/: Suggested security header missing: content-security-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        );
        assert_eq!(with_url, truncated_url);
        assert!(!with_url.contains("See:"));
        assert!(!with_url.ends_with(':'));
    }

    #[test]
    fn merges_etag_findings_with_truncated_see_references() {
        let with_url = normalize_title(
            "/: Server may leak inodes via ETags, header found with file /, inode: 917, size: 524, mtime: Wed Nov 11 20:09:58 2020. See: http://cve.mitre",
        );
        let with_cve = normalize_title(
            "GET /: Server may leak inodes via ETags, header found with file /, inode: 917, size: 524, mtime: Wed Nov 11 20:09:58 2020. See: CVE-2003-141",
        );
        assert_eq!(with_url, with_cve);
        assert!(!with_url.contains("See:"));
        assert!(!with_cve.contains("CVE-2003"));
    }

    #[test]
    fn preserves_bare_trailing_cve_id() {
        assert_eq!(
            normalize_title("Exposed service CVE-2017-0144"),
            "exposed service cve-2017-0144"
        );
    }

    #[test]
    fn case_insensitive_and_whitespace_collapsed() {
        assert_eq!(
            normalize_title("  APACHE   version  "),
            normalize_title("apache version")
        );
    }

    #[test]
    fn deduplicates_duplicated_nikto_csp_findings() {
        let records = vec![
            record(
                "/: Suggested security header missing: content-security-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                "http://192.168.1.2/",
            ),
            record(
                "GET /: Suggested security header missing: content-security-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP:",
                "http://192.168.1.2/",
            ),
        ];
        let result = deduplicate_records(records);
        assert_eq!(result.unique_count, 1);
        assert_eq!(result.removed_count, 1);
        assert_eq!(result.records[0].merged_count, 2);
        assert_eq!(result.records[0].raw_findings.len(), 2);
    }

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

    #[test]
    fn distinct_targets_stay_separate() {
        let records = vec![
            record("Alive (200)", "http://192.168.1.2/"),
            record("Alive (200)", "http://192.168.1.2/index.html"),
        ];
        let result = deduplicate_records(records);
        assert_eq!(result.unique_count, 2);
    }

    #[test]
    fn keeps_raw_titles_for_traceability() {
        let records = vec![
            record("Apache version", "10.0.0.1"),
            record("APACHE VERSION", "10.0.0.1"),
        ];
        let result = deduplicate_records(records);
        assert_eq!(
            result.records[0].raw_findings,
            vec!["Apache version", "APACHE VERSION"]
        );
        assert_eq!(result.records[0].merged_count, 2);
    }

    #[test]
    fn collapses_pipe_framed_titles_into_same_identity() {
        let records = vec![record("GET / |", "10.0.0.1"), record("GET / ", "10.0.0.1")];
        let result = deduplicate_records(records);
        assert_eq!(result.unique_count, 1);
        assert_eq!(result.records[0].merged_count, 2);
    }

    #[test]
    fn structured_fingerprint_parts() {
        let parts = parse_endpoint_parts("https://example.com:8443/admin?a=1&b=2");
        assert_eq!(parts.scheme, "https");
        assert_eq!(parts.host, "example.com");
        assert_eq!(parts.port, Some(8443));
        assert_eq!(parts.path, "/admin");
        assert_eq!(parts.query, "a=1&b=2");

        let ipv6 = parse_endpoint_parts("[::1]:8080/x");
        assert_eq!(ipv6.host, "::1");
        assert_eq!(ipv6.port, Some(8080));
        assert_eq!(ipv6.path, "/x");
    }

    #[test]
    fn same_title_different_ports_stay_separate() {
        let mut a = record("/: Apache", "10.0.0.1");
        a.port = Some(80);
        a.service = Some("http".into());
        let mut b = record("/: Apache", "10.0.0.1");
        b.port = Some(8080);
        b.service = Some("http".into());
        let result = deduplicate_records(vec![a, b]);
        assert_eq!(result.unique_count, 2);
    }

    #[test]
    fn normalization_is_case_and_scheme_insensitive() {
        let a = record("Apache version", "http://10.0.0.1/");
        let b = record("APACHE VERSION", "10.0.0.1:80");
        let result = deduplicate_records(vec![a, b]);
        assert_eq!(result.unique_count, 1);
        assert_eq!(result.removed_count, 1);
    }
}
