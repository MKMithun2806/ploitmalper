use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleSuggestion {
    pub service_banner: String,
    pub suggested_module: String,
    pub confidence: String,
}

lazy_static::lazy_static! {
    static ref BANNER_MAP: HashMap<&'static str, Vec<&'static str>> = {
        let mut m = HashMap::new();
        m.insert("apache", vec!["exploit/multi/http/apache_mod_cgi_bash_env_exec", "auxiliary/scanner/http/apache_version"]);
        m.insert("nginx", vec!["auxiliary/scanner/http/nginx_version"]);
        m.insert("iis", vec!["auxiliary/scanner/http/iis_version"]);
        m.insert("openssh", vec!["auxiliary/scanner/ssh/ssh_version"]);
        m.insert("mysql", vec!["auxiliary/scanner/mysql/mysql_version", "exploit/linux/mysql/mysql_yassl_getname"]);
        m.insert("postgresql", vec!["auxiliary/scanner/postgres/postgres_version"]);
        m.insert("smb", vec!["auxiliary/scanner/smb/smb_version", "exploit/windows/smb/ms17_010_eternalblue"]);
        m.insert("ftp", vec!["auxiliary/scanner/ftp/ftp_version"]);
        m.insert("rdp", vec!["auxiliary/scanner/rdp/rdp_scanner", "exploit/windows/rdp/cve_2019_0708_bluekeep"]);
        m.insert("tomcat", vec!["exploit/multi/http/tomcat_jsp_upload_bypass"]);
        m.insert("jenkins", vec!["exploit/multi/http/jenkins_script_console"]);
        m.insert("wordpress", vec!["auxiliary/scanner/http/wordpress_scanner"]);
        m.insert("drupal", vec!["exploit/unix/webapp/drupal_drupalgeddon2"]);
        m
    };
}

#[pyfunction]
fn suggest_modules(service_banner: &str) -> PyResult<String> {
    let banner_lower = service_banner.to_lowercase();
    let mut suggestions: Vec<ModuleSuggestion> = Vec::new();

    for (keyword, modules) in BANNER_MAP.iter() {
        if banner_lower.contains(keyword) {
            for module in modules {
                suggestions.push(ModuleSuggestion {
                    service_banner: service_banner.to_string(),
                    suggested_module: module.to_string(),
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
    let banners: Vec<&str> = BANNER_MAP.keys().copied().collect();
    serde_json::to_string(&banners)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(suggest_modules, m)?)?;
    m.add_function(wrap_pyfunction!(get_all_known_banners, m)?)?;
    Ok(())
}
