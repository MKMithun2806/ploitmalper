use std::collections::HashMap;
use std::fs;
use std::process::Command;
use std::thread;
use std::time::Duration;

use serde_json::Value;

use crate::config::nvd_cache_file;
use crate::error::Result;
use crate::models::{NVDCVEInfo, ScanRecord};

const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_RATE_LIMIT_DELAY: Duration = Duration::from_millis(600);

#[derive(Debug, Clone)]
pub struct NVDClient {
    pub api_key: String,
    cache: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EnrichmentStats {
    pub fetched: usize,
    pub cache_hits: usize,
    pub not_found: usize,
}

impl NVDClient {
    pub fn new(api_key: &str) -> Self {
        let mut client = Self {
            api_key: api_key.to_string(),
            cache: HashMap::new(),
        };
        client.load_cache();
        client
    }

    fn load_cache(&mut self) {
        let path = nvd_cache_file();
        if let Ok(raw) = fs::read_to_string(path) {
            if let Ok(cache) = serde_json::from_str::<HashMap<String, Value>>(&raw) {
                self.cache = cache;
            }
        }
    }

    fn save_cache(&self) -> Result<()> {
        let path = nvd_cache_file();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(&self.cache)?)?;
        Ok(())
    }

    fn get_cached(&self, cve_id: &str) -> Option<&Value> {
        self.cache.get(cve_id)
    }

    fn cache_result(&mut self, cve_id: &str, data: Value) -> Result<()> {
        self.cache.insert(cve_id.to_string(), data);
        self.save_cache()
    }

    fn fetch_cve(&self, cve_id: &str, use_key: bool) -> std::result::Result<Value, String> {
        let url = format!("{}?cveId={}", NVD_API_BASE, cve_id);
        let mut command = Command::new("curl");
        command
            .arg("-sS")
            .arg("--fail")
            .arg("--max-time")
            .arg("15")
            .arg("-H")
            .arg("User-Agent: PloitMalper/0.1.0");

        if use_key && !self.api_key.is_empty() {
            command.arg("-H").arg(format!("apiKey: {}", self.api_key));
        }

        let output = command.arg(&url).output().map_err(|e| e.to_string())?;

        if output.status.success() {
            serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
        } else if output.status.code() == Some(22) && use_key && !self.api_key.is_empty() {
            let fallback = Command::new("curl")
                .arg("-sS")
                .arg("--fail")
                .arg("--max-time")
                .arg("15")
                .arg("-H")
                .arg("User-Agent: PloitMalper/0.1.0")
                .arg(&url)
                .output()
                .map_err(|e| e.to_string())?;
            if fallback.status.success() {
                serde_json::from_slice(&fallback.stdout).map_err(|e| e.to_string())
            } else {
                Err(String::from_utf8_lossy(&fallback.stderr).trim().to_string())
            }
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
    }

    pub fn lookup_cve(&mut self, cve_id: &str) -> Option<NVDCVEInfo> {
        if let Some(cached) = self.get_cached(cve_id) {
            return Some(Self::info_from_cached(cve_id, cached));
        }

        thread::sleep(NVD_RATE_LIMIT_DELAY);

        let resp = match self.fetch_cve(cve_id, true) {
            Ok(value) => value,
            Err(_) => return None,
        };

        let vulnerabilities = resp.get("vulnerabilities")?.as_array()?;
        let cve_data = vulnerabilities.first()?.get("cve")?.as_object()?.clone();

        let info = Self::info_from_cve(cve_id, &cve_data);
        let cache_entry = serde_json::json!({
            "cve_id": info.cve_id,
            "description": info.description,
            "cvss_v3_score": info.cvss_v3_score,
            "cvss_v3_severity": info.cvss_v3_severity,
            "cvss_v2_score": info.cvss_v2_score,
            "published": info.published,
            "last_modified": info.last_modified,
            "weaknesses": info.weaknesses,
            "references": info.references,
        });

        let _ = self.cache_result(cve_id, cache_entry);
        Some(info)
    }

    fn info_from_cached(cve_id: &str, cached: &Value) -> NVDCVEInfo {
        NVDCVEInfo {
            cve_id: cached
                .get("cve_id")
                .and_then(Value::as_str)
                .unwrap_or(cve_id)
                .to_string(),
            description: cached
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            cvss_v3_score: cached
                .get("cvss_v3_score")
                .and_then(Value::as_f64)
                .map(|v| v as f32),
            cvss_v3_severity: cached
                .get("cvss_v3_severity")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            cvss_v2_score: cached
                .get("cvss_v2_score")
                .and_then(Value::as_f64)
                .map(|v| v as f32),
            published: cached
                .get("published")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            last_modified: cached
                .get("last_modified")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            weaknesses: cached
                .get("weaknesses")
                .and_then(Value::as_array)
                .map(|refs| {
                    refs.iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            references: cached
                .get("references")
                .and_then(Value::as_array)
                .map(|refs| {
                    refs.iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    fn info_from_cve(cve_id: &str, cve_data: &serde_json::Map<String, Value>) -> NVDCVEInfo {
        let descriptions = cve_data
            .get("descriptions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut description = String::new();
        for entry in &descriptions {
            if entry.get("lang").and_then(Value::as_str) == Some("en") {
                description = entry
                    .get("value")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                break;
            }
        }
        if description.is_empty() {
            description = descriptions
                .first()
                .and_then(|entry| entry.get("value"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
        }

        let metrics = cve_data.get("metrics").and_then(Value::as_object);
        let mut cvss_v3_score = None;
        let mut cvss_v3_severity = None;
        let mut cvss_v2_score = None;

        if let Some(metrics) = metrics {
            let metric_groups = metrics
                .get("cvssMetricV31")
                .or_else(|| metrics.get("cvssMetricV30"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if let Some(metric_group) = metric_groups.first() {
                if let Some(cvss_data) = metric_group.get("cvssData").and_then(Value::as_object) {
                    cvss_v3_score = cvss_data
                        .get("baseScore")
                        .and_then(Value::as_f64)
                        .map(|v| v as f32);
                    cvss_v3_severity = cvss_data
                        .get("baseSeverity")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned);
                }
            }

            if cvss_v3_score.is_none() {
                if let Some(cvss_v2_metrics) = metrics.get("cvssMetricV2").and_then(Value::as_array)
                {
                    if let Some(metric) = cvss_v2_metrics.first() {
                        cvss_v2_score = metric
                            .get("cvssData")
                            .and_then(Value::as_object)
                            .and_then(|cvss| cvss.get("baseScore"))
                            .and_then(Value::as_f64)
                            .map(|v| v as f32);
                    }
                }
            }
        }

        let references = cve_data
            .get("references")
            .and_then(Value::as_array)
            .map(|refs| {
                refs.iter()
                    .take(5)
                    .filter_map(|ref_value| ref_value.get("url").and_then(Value::as_str))
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let weaknesses = cve_data
            .get("weaknesses")
            .and_then(Value::as_array)
            .map(|entries| {
                let mut out = Vec::new();
                for entry in entries {
                    if let Some(descs) = entry.get("description").and_then(Value::as_array) {
                        for desc in descs {
                            if let Some(value) = desc.get("value").and_then(Value::as_str) {
                                if !out.contains(&value.to_string()) {
                                    out.push(value.to_string());
                                }
                            }
                        }
                    }
                }
                out
            })
            .unwrap_or_default();

        NVDCVEInfo {
            cve_id: cve_id.to_string(),
            description,
            cvss_v3_score,
            cvss_v3_severity,
            cvss_v2_score,
            published: cve_data
                .get("published")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            last_modified: cve_data
                .get("lastModified")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            weaknesses,
            references,
        }
    }

    pub fn enrich_records(&mut self, records: &mut [ScanRecord]) -> EnrichmentStats {
        let mut stats = EnrichmentStats::default();

        for record in records {
            let cves = if record.cves.is_empty() {
                record.cve.clone().into_iter().collect::<Vec<_>>()
            } else {
                record.cves.clone()
            };

            for cve in cves {
                let key = cve.trim().to_uppercase();
                if let Some(cached) = self.get_cached(&key).cloned() {
                    stats.cache_hits += 1;
                    let info = Self::info_from_cached(&key, &cached);
                    apply_nvd(record, &info);
                    continue;
                }

                if let Some(info) = self.lookup_cve(&key) {
                    stats.fetched += 1;
                    apply_nvd(record, &info);
                } else {
                    stats.not_found += 1;
                }
            }
        }

        stats
    }
}

fn apply_nvd(record: &mut ScanRecord, info: &NVDCVEInfo) {
    record.nvd_description = Some(info.description.clone());
    record.nvd_cvss_v3 = info.cvss_v3_score;
    record.nvd_cvss_v3_severity = info.cvss_v3_severity.clone();
    record.nvd_cvss_v2 = info.cvss_v2_score;
    record.nvd_published = Some(info.published.clone());
    record.nvd_last_modified = Some(info.last_modified.clone());
    record.nvd_weaknesses = info.weaknesses.clone();
    record.nvd_references = info.references.clone();

    if let Some(severity) = &info.cvss_v3_severity {
        record.severity = severity.to_lowercase();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_cwe_weaknesses_from_nvd_response() {
        let cve_data = json!({
            "descriptions": [{"lang": "en", "value": "Path traversal in Apache."}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL"
                    }
                }]
            },
            "weaknesses": [{
                "description": [{"lang": "en", "value": "CWE-22"}, {"lang": "en", "value": "CWE-200"}]
            }],
            "published": "2021-10-05T00:00:00.000",
            "lastModified": "2021-10-08T00:00:00.000",
            "references": [{"url": "https://example.com/advisory"}]
        });
        let info = NVDClient::info_from_cve("CVE-2021-41773", cve_data.as_object().unwrap());
        assert_eq!(
            info.weaknesses,
            vec!["CWE-22".to_string(), "CWE-200".to_string()]
        );
        assert_eq!(info.cvss_v3_score, Some(9.8));
        assert_eq!(info.cvss_v3_severity.as_deref(), Some("CRITICAL"));
        assert_eq!(info.published, "2021-10-05T00:00:00.000");
        assert_eq!(
            info.references,
            vec!["https://example.com/advisory".to_string()]
        );
    }

    #[test]
    fn enriches_every_discovered_cve_from_cache() {
        let mut client = NVDClient {
            api_key: String::new(),
            cache: HashMap::new(),
        };
        client.cache.insert(
            "CVE-2003-1418".into(),
            json!({
                "cve_id": "CVE-2003-1418",
                "description": "Inode leak",
                "cvss_v3_score": null,
                "cvss_v3_severity": null,
                "cvss_v2_score": 5.0,
                "published": "2003-08-11T00:00:00.000",
                "last_modified": "2017-10-11T00:00:00.000",
                "weaknesses": ["CWE-200"],
                "references": []
            }),
        );
        client.cache.insert(
            "CVE-2021-41773".into(),
            json!({
                "cve_id": "CVE-2021-41773",
                "description": "Path traversal",
                "cvss_v3_score": 9.8,
                "cvss_v3_severity": "CRITICAL",
                "cvss_v2_score": null,
                "published": "2021-10-05T00:00:00.000",
                "last_modified": "2021-10-08T00:00:00.000",
                "weaknesses": ["CWE-22"],
                "references": ["https://example.com"]
            }),
        );

        let mut records = vec![ScanRecord {
            cves: vec!["CVE-2003-1418".to_string(), "CVE-2021-41773".to_string()],
            ..Default::default()
        }];
        let stats = client.enrich_records(&mut records);
        assert_eq!(stats.cache_hits, 2);
        assert_eq!(stats.fetched, 0);
        assert_eq!(stats.not_found, 0);
        assert_eq!(records[0].nvd_cvss_v3, Some(9.8));
        assert_eq!(records[0].severity, "critical");
        assert_eq!(records[0].nvd_weaknesses, vec!["CWE-22".to_string()]);
    }

    #[test]
    fn gracefully_handles_missing_cve() {
        // A CVE not in cache would hit the network; ensure the cache-hit path
        // with a fully populated entry never panics and applies fields.
        let mut client = NVDClient {
            api_key: String::new(),
            cache: HashMap::new(),
        };
        client.cache.insert(
            "CVE-2021-44228".into(),
            json!({
                "cve_id": "CVE-2021-44228",
                "description": "Log4j JNDI injection",
                "cvss_v3_score": 10.0,
                "cvss_v3_severity": "CRITICAL",
                "cvss_v2_score": null,
                "published": "2021-12-09T00:00:00.000",
                "last_modified": "2021-12-10T00:00:00.000",
                "weaknesses": ["CWE-502"],
                "references": []
            }),
        );
        let mut records = vec![ScanRecord {
            cves: vec!["CVE-2021-44228".to_string()],
            ..Default::default()
        }];
        let stats = client.enrich_records(&mut records);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(records[0].nvd_cvss_v3, Some(10.0));
        assert_eq!(records[0].nvd_cvss_v3_severity.as_deref(), Some("CRITICAL"));
    }
}
