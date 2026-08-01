use crate::models::CVEExtraInfo;

/// Curated enrichment for well-known CVEs: EPSS probability, CISA KEV status,
/// public exploit availability, and any applicable Metasploit modules.
///
/// This is a deterministic offline catalog. For CVEs not present here the
/// report simply falls back to raw NVD data.
const CVE_CATALOG: &[(&str, f32, bool, bool, &[&str])] = &[
    (
        "CVE-2021-41773",
        0.94,
        true,
        true,
        &["exploit/multi/http/apache_path_traversal"],
    ),
    (
        "CVE-2021-44228",
        0.97,
        true,
        true,
        &["exploit/multi/http/log4shell_header_injection"],
    ),
    (
        "CVE-2017-0144",
        0.97,
        true,
        true,
        &["exploit/windows/smb/ms17_010_eternalblue"],
    ),
    (
        "CVE-2019-0708",
        0.95,
        true,
        true,
        &["exploit/windows/rdp/cve_2019_0708_bluekeep"],
    ),
    (
        "CVE-2017-5638",
        0.97,
        true,
        true,
        &["exploit/multi/http/struts2_content_type_ognl"],
    ),
    (
        "CVE-2020-1472",
        0.97,
        true,
        true,
        &["exploit/windows/netlogon/zerologon"],
    ),
    (
        "CVE-2021-34527",
        0.94,
        true,
        true,
        &["exploit/windows/driver/cve_2021_34527_printnightmare"],
    ),
    (
        "CVE-2021-26855",
        0.97,
        true,
        true,
        &["exploit/windows/http/exchange_proxylogon_rce"],
    ),
    (
        "CVE-2020-3452",
        0.94,
        true,
        true,
        &["auxiliary/scanner/http/cisco_directory_traversal"],
    ),
    (
        "CVE-2018-7600",
        0.97,
        true,
        true,
        &["exploit/unix/webapp/drupal_drupalgeddon2"],
    ),
    (
        "CVE-2021-26084",
        0.96,
        true,
        true,
        &["exploit/multi/http/confluence_webwork_ognl_injection"],
    ),
    (
        "CVE-2021-21972",
        0.94,
        true,
        true,
        &["exploit/multi/http/vmware_vcenter_uploadova_rce"],
    ),
];

/// Look up extra intelligence for a CVE ID.
pub fn enrich_cve(cve_id: &str) -> Option<CVEExtraInfo> {
    let normalized = cve_id.trim().to_uppercase();
    CVE_CATALOG
        .iter()
        .find(|(id, _, _, _, _)| id.eq_ignore_ascii_case(&normalized))
        .map(|(_, epss, in_kev, public_exploit, modules)| CVEExtraInfo {
            epss: Some(*epss),
            in_kev: *in_kev,
            public_exploit: *public_exploit,
            metasploit_modules: modules.iter().map(|module| (*module).to_string()).collect(),
        })
}

pub fn is_known_cve(cve_id: &str) -> bool {
    enrich_cve(cve_id).is_some()
}

pub fn epss_percent(epss: Option<f32>) -> String {
    epss.map(|value| format!("{:.0}%", value * 100.0))
        .unwrap_or_else(|| "N/A".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enriches_known_cve() {
        let info = enrich_cve("CVE-2021-41773").expect("known CVE");
        assert!((info.epss.unwrap() - 0.94).abs() < 0.001);
        assert!(info.in_kev);
        assert!(info.public_exploit);
        assert!(info
            .metasploit_modules
            .contains(&"exploit/multi/http/apache_path_traversal".to_string()));
    }

    #[test]
    fn unknown_cve_returns_none() {
        assert!(enrich_cve("CVE-2099-99999").is_none());
    }

    #[test]
    fn case_insensitive_lookup() {
        assert!(is_known_cve("cve-2021-41773"));
    }
}
