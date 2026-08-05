use std::collections::BTreeSet;

use crate::models::{MSFModule, MSFNoModuleReason};

use std::sync::OnceLock;

/// Offline Metasploit module catalog. Every entry carries exploit
/// intelligence: rank, disclosure date, supported platforms and required
/// options, so recommendations are actionable without a live MSF-RPC server.
fn catalog() -> &'static Vec<MSFModule> {
    static MODULES: OnceLock<Vec<MSFModule>> = OnceLock::new();
    MODULES.get_or_init(|| {
        vec![
            MSFModule {
                name: "exploit/multi/http/apache_path_traversal".into(),
                cve: Some("CVE-2021-41773".into()),
                rank: "excellent".into(),
                disclosure_date: "2021-10-05".into(),
                platforms: vec!["Unix".into(), "Windows".into()],
                required_options: vec!["RHOSTS".into(), "TARGETURI".into(), "LHOST".into()],
            },
            MSFModule {
                name: "exploit/multi/http/log4shell_header_injection".into(),
                cve: Some("CVE-2021-44228".into()),
                rank: "excellent".into(),
                disclosure_date: "2021-12-09".into(),
                platforms: vec!["Unix".into(), "Windows".into(), "Java".into()],
                required_options: vec![
                    "RHOSTS".into(),
                    "TARGETURI".into(),
                    "HTTP_HEADER".into(),
                    "LHOST".into(),
                ],
            },
            MSFModule {
                name: "exploit/windows/smb/ms17_010_eternalblue".into(),
                cve: Some("CVE-2017-0144".into()),
                rank: "excellent".into(),
                disclosure_date: "2017-03-14".into(),
                platforms: vec!["Windows".into()],
                required_options: vec!["RHOSTS".into()],
            },
            MSFModule {
                name: "exploit/windows/rdp/cve_2019_0708_bluekeep".into(),
                cve: Some("CVE-2019-0708".into()),
                rank: "excellent".into(),
                disclosure_date: "2019-05-14".into(),
                platforms: vec!["Windows".into()],
                required_options: vec!["RHOSTS".into(), "RPORT".into()],
            },
            MSFModule {
                name: "exploit/multi/http/struts2_content_type_ognl".into(),
                cve: Some("CVE-2017-5638".into()),
                rank: "excellent".into(),
                disclosure_date: "2017-03-07".into(),
                platforms: vec!["Unix".into(), "Windows".into(), "Java".into()],
                required_options: vec!["RHOSTS".into(), "TARGETURI".into()],
            },
            MSFModule {
                name: "exploit/windows/netlogon/zerologon".into(),
                cve: Some("CVE-2020-1472".into()),
                rank: "excellent".into(),
                disclosure_date: "2020-08-11".into(),
                platforms: vec!["Windows".into()],
                required_options: vec!["RHOSTS".into(), "RPORT".into()],
            },
            MSFModule {
                name: "exploit/windows/driver/cve_2021_34527_printnightmare".into(),
                cve: Some("CVE-2021-34527".into()),
                rank: "excellent".into(),
                disclosure_date: "2021-07-01".into(),
                platforms: vec!["Windows".into()],
                required_options: vec!["RHOSTS".into(), "TARGET".into(), "LHOST".into()],
            },
            MSFModule {
                name: "exploit/windows/http/exchange_proxylogon_rce".into(),
                cve: Some("CVE-2021-26855".into()),
                rank: "excellent".into(),
                disclosure_date: "2021-02-27".into(),
                platforms: vec!["Windows".into()],
                required_options: vec![
                    "RHOSTS".into(),
                    "EMAIL".into(),
                    "PASSWORD".into(),
                    "LHOST".into(),
                ],
            },
            MSFModule {
                name: "auxiliary/scanner/http/cisco_directory_traversal".into(),
                cve: Some("CVE-2020-3452".into()),
                rank: "good".into(),
                disclosure_date: "2020-07-14".into(),
                platforms: vec!["Cisco ASA".into()],
                required_options: vec!["RHOSTS".into(), "TARGETURI".into()],
            },
            MSFModule {
                name: "exploit/unix/webapp/drupal_drupalgeddon2".into(),
                cve: Some("CVE-2018-7600".into()),
                rank: "excellent".into(),
                disclosure_date: "2018-03-28".into(),
                platforms: vec!["Unix".into(), "PHP".into()],
                required_options: vec!["RHOSTS".into(), "TARGETURI".into(), "LHOST".into()],
            },
            MSFModule {
                name: "exploit/multi/http/confluence_webwork_ognl_injection".into(),
                cve: Some("CVE-2021-26084".into()),
                rank: "excellent".into(),
                disclosure_date: "2021-08-25".into(),
                platforms: vec!["Unix".into(), "Windows".into(), "Java".into()],
                required_options: vec!["RHOSTS".into(), "TARGETURI".into(), "LHOST".into()],
            },
            MSFModule {
                name: "exploit/multi/http/vmware_vcenter_uploadova_rce".into(),
                cve: Some("CVE-2021-21972".into()),
                rank: "excellent".into(),
                disclosure_date: "2021-02-23".into(),
                platforms: vec!["Unix".into(), "Windows".into()],
                required_options: vec!["RHOSTS".into(), "TARGETURI".into(), "LHOST".into()],
            },
            MSFModule {
                name: "auxiliary/scanner/http/apache_version".into(),
                cve: None,
                rank: "normal".into(),
                disclosure_date: "unknown".into(),
                platforms: vec!["Apache".into()],
                required_options: vec!["RHOSTS".into()],
            },
            MSFModule {
                name: "auxiliary/scanner/http/iis_version".into(),
                cve: None,
                rank: "normal".into(),
                disclosure_date: "unknown".into(),
                platforms: vec!["Windows / IIS".into()],
                required_options: vec!["RHOSTS".into()],
            },
            MSFModule {
                name: "auxiliary/scanner/ssh/ssh_version".into(),
                cve: None,
                rank: "normal".into(),
                disclosure_date: "unknown".into(),
                platforms: vec!["OpenSSH".into()],
                required_options: vec!["RHOSTS".into(), "RPORT".into()],
            },
            MSFModule {
                name: "auxiliary/scanner/mysql/mysql_version".into(),
                cve: None,
                rank: "normal".into(),
                disclosure_date: "unknown".into(),
                platforms: vec!["MySQL".into()],
                required_options: vec!["RHOSTS".into(), "RPORT".into()],
            },
            MSFModule {
                name: "exploit/linux/mysql/mysql_yassl_getname".into(),
                cve: None,
                rank: "good".into(),
                disclosure_date: "2012-05-10".into(),
                platforms: vec!["Linux / MySQL".into()],
                required_options: vec!["RHOSTS".into(), "RPORT".into()],
            },
            MSFModule {
                name: "auxiliary/scanner/postgres/postgres_version".into(),
                cve: None,
                rank: "normal".into(),
                disclosure_date: "unknown".into(),
                platforms: vec!["PostgreSQL".into()],
                required_options: vec!["RHOSTS".into(), "RPORT".into()],
            },
            MSFModule {
                name: "auxiliary/scanner/smb/smb_version".into(),
                cve: None,
                rank: "normal".into(),
                disclosure_date: "unknown".into(),
                platforms: vec!["SMB".into()],
                required_options: vec!["RHOSTS".into()],
            },
            MSFModule {
                name: "auxiliary/scanner/ftp/ftp_version".into(),
                cve: None,
                rank: "normal".into(),
                disclosure_date: "unknown".into(),
                platforms: vec!["FTP".into()],
                required_options: vec!["RHOSTS".into(), "RPORT".into()],
            },
            MSFModule {
                name: "auxiliary/scanner/rdp/rdp_scanner".into(),
                cve: None,
                rank: "normal".into(),
                disclosure_date: "unknown".into(),
                platforms: vec!["RDP".into()],
                required_options: vec!["RHOSTS".into(), "RPORT".into()],
            },
            MSFModule {
                name: "exploit/multi/http/tomcat_jsp_upload_bypass".into(),
                cve: None,
                rank: "excellent".into(),
                disclosure_date: "2017-06-19".into(),
                platforms: vec!["Tomcat".into()],
                required_options: vec![
                    "RHOSTS".into(),
                    "TARGETURI".into(),
                    "TARGET".into(),
                    "LHOST".into(),
                ],
            },
            MSFModule {
                name: "exploit/multi/http/jenkins_script_console".into(),
                cve: None,
                rank: "excellent".into(),
                disclosure_date: "2019-01-01".into(),
                platforms: vec!["Jenkins".into()],
                required_options: vec!["RHOSTS".into(), "TARGETURI".into(), "LHOST".into()],
            },
            MSFModule {
                name: "auxiliary/scanner/http/wordpress_scanner".into(),
                cve: None,
                rank: "normal".into(),
                disclosure_date: "unknown".into(),
                platforms: vec!["WordPress".into()],
                required_options: vec!["RHOSTS".into(), "TARGETURI".into()],
            },
            MSFModule {
                name: "auxiliary/scanner/http/robots_txt".into(),
                cve: None,
                rank: "normal".into(),
                disclosure_date: "unknown".into(),
                platforms: vec!["HTTP".into()],
                required_options: vec!["RHOSTS".into(), "TARGETURI".into()],
            },
            MSFModule {
                name: "auxiliary/scanner/http/golang_pprof".into(),
                cve: None,
                rank: "normal".into(),
                disclosure_date: "unknown".into(),
                platforms: vec!["Go".into()],
                required_options: vec!["RHOSTS".into(), "TARGETURI".into()],
            },
        ]
    })
}

/// Metasploit modules directly tied to a specific CVE.
pub fn modules_for_cve(cve: &str) -> Vec<MSFModule> {
    let needle = cve.trim().to_uppercase();
    catalog()
        .iter()
        .filter(|module| {
            module
                .cve
                .as_deref()
                .map(|known| known.eq_ignore_ascii_case(&needle))
                .unwrap_or(false)
        })
        .cloned()
        .collect()
}

/// Metasploit modules relevant to a set of technologies / service banners.
/// Matching is case-insensitive substring over module metadata.
pub fn modules_for_technology(needles: &[String]) -> Vec<MSFModule> {
    if needles.is_empty() {
        return Vec::new();
    }
    let lowered: Vec<String> = needles.iter().map(|n| n.to_lowercase()).collect();
    let mut found = BTreeSet::new();
    let mut result = Vec::new();
    for module in catalog() {
        if module.cve.is_some() {
            continue; // CVE-driven modules are surfaced through CVE lookup.
        }
        let haystack = format!(
            "{}{}{}{}",
            module.name,
            module.platforms.join(" "),
            module.disclosure_date,
            module
                .required_options
                .iter()
                .map(|o| o.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        )
        .to_lowercase();
        if lowered.iter().any(|needle| haystack.contains(needle))
            && found.insert(module.name.clone())
        {
            result.push(module.clone());
        }
    }
    result
}

/// Explicit reason when no Metasploit module is known for a CVE, so the
/// report never silently omits the search.
pub fn no_module_reason(cve: &str) -> MSFNoModuleReason {
    let cve = cve.trim().to_uppercase();
    if modules_for_cve(&cve).is_empty() {
        MSFNoModuleReason {
            cve,
            reason: "No Metasploit module is known for this CVE in the offline catalog. Verify with `msfconsole -q -x \"search cve:<id>\"` against an updated Metasploit install; if none exists, check Exploit-DB and packet storm for public PoCs.".to_string(),
        }
    } else {
        MSFNoModuleReason {
            cve,
            reason: "Module available; see Metasploit Recommendations.".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cve_lookup_returns_exact_module() {
        let modules = modules_for_cve("cve-2021-44228");
        assert_eq!(modules.len(), 1);
        assert_eq!(
            modules[0].name,
            "exploit/multi/http/log4shell_header_injection"
        );
        assert_eq!(modules[0].rank, "excellent");
        assert!(!modules[0].required_options.is_empty());
    }

    #[test]
    fn unknown_cve_has_explicit_reason() {
        let reason = no_module_reason("CVE-2099-99999");
        assert!(reason.reason.contains("No Metasploit module"));
    }

    #[test]
    fn technology_lookup_filters_cve_modules() {
        let modules = modules_for_technology(&["apache".to_string()]);
        assert!(modules
            .iter()
            .any(|m| m.name == "auxiliary/scanner/http/apache_version"));
        assert!(modules.iter().all(|m| m.cve.is_none()));
    }
}
