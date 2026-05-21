use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleSuggestion {
    pub service_banner: String,
    pub suggested_module: String,
    pub confidence: String,
}

fn build_banner_map() -> HashMap<String, Vec<String>> {
    let mut m = HashMap::new();
    m.insert("apache".to_string(), vec!["exploit/multi/http/apache_mod_cgi_bash_env_exec".to_string(), "auxiliary/scanner/http/apache_version".to_string()]);
    m.insert("nginx".to_string(), vec!["auxiliary/scanner/http/nginx_version".to_string()]);
    m.insert("iis".to_string(), vec!["auxiliary/scanner/http/iis_version".to_string()]);
    m.insert("openssh".to_string(), vec!["auxiliary/scanner/ssh/ssh_version".to_string()]);
    m.insert("mysql".to_string(), vec!["auxiliary/scanner/mysql/mysql_version".to_string(), "exploit/linux/mysql/mysql_yassl_getname".to_string()]);
    m.insert("postgresql".to_string(), vec!["auxiliary/scanner/postgres/postgres_version".to_string()]);
    m.insert("smb".to_string(), vec!["auxiliary/scanner/smb/smb_version".to_string(), "exploit/windows/smb/ms17_010_eternalblue".to_string()]);
    m.insert("ftp".to_string(), vec!["auxiliary/scanner/ftp/ftp_version".to_string()]);
    m.insert("rdp".to_string(), vec!["auxiliary/scanner/rdp/rdp_scanner".to_string(), "exploit/windows/rdp/cve_2019_0708_bluekeep".to_string()]);
    m.insert("tomcat".to_string(), vec!["exploit/multi/http/tomcat_jsp_upload_bypass".to_string()]);
    m.insert("jenkins".to_string(), vec!["exploit/multi/http/jenkins_script_console".to_string()]);
    m.insert("wordpress".to_string(), vec!["auxiliary/scanner/http/wordpress_scanner".to_string()]);
    m.insert("drupal".to_string(), vec!["exploit/unix/webapp/drupal_drupalgeddon2".to_string()]);
    m
}

fn banner_matches(banner_lower: &str, keyword: &str) -> bool {
    let pattern = format!(r"(^|\s){}(\s|$|/|\.)", regex::escape(keyword));
    let re = regex::Regex::new(&pattern).unwrap();
    re.is_match(banner_lower)
}

#[pyfunction]
fn suggest_modules(service_banner: &str) -> PyResult<String> {
    let banner_lower = service_banner.to_lowercase();
    let banner_map = build_banner_map();
    let mut suggestions: Vec<ModuleSuggestion> = Vec::new();

    for (keyword, modules) in &banner_map {
        if banner_matches(&banner_lower, keyword) {
            for module in modules {
                suggestions.push(ModuleSuggestion {
                    service_banner: service_banner.to_string(),
                    suggested_module: module.clone(),
                    confidence: "high".to_string(),
                });
            }
        }
    }

    serde_json::to_string(&suggestions)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn get_all_known_banners() -> PyResult<String> {
    let banner_map = build_banner_map();
    let banners: Vec<&String> = banner_map.keys().collect();
    serde_json::to_string(&banners)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(suggest_modules, m)?)?;
    m.add_function(wrap_pyfunction!(get_all_known_banners, m)?)?;
    Ok(())
}
