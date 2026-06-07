use crate::models::ModuleSuggestion;

const BANNER_CATALOG: &[(&str, &[&str])] = &[
    (
        "apache",
        &[
            "exploit/multi/http/apache_mod_cgi_bash_env_exec",
            "auxiliary/scanner/http/apache_version",
        ],
    ),
    ("nginx", &["auxiliary/scanner/http/nginx_version"]),
    ("iis", &["auxiliary/scanner/http/iis_version"]),
    ("openssh", &["auxiliary/scanner/ssh/ssh_version"]),
    (
        "mysql",
        &[
            "auxiliary/scanner/mysql/mysql_version",
            "exploit/linux/mysql/mysql_yassl_getname",
        ],
    ),
    (
        "postgresql",
        &["auxiliary/scanner/postgres/postgres_version"],
    ),
    (
        "smb",
        &[
            "auxiliary/scanner/smb/smb_version",
            "exploit/windows/smb/ms17_010_eternalblue",
        ],
    ),
    ("ftp", &["auxiliary/scanner/ftp/ftp_version"]),
    (
        "rdp",
        &[
            "auxiliary/scanner/rdp/rdp_scanner",
            "exploit/windows/rdp/cve_2019_0708_bluekeep",
        ],
    ),
    ("tomcat", &["exploit/multi/http/tomcat_jsp_upload_bypass"]),
    ("jenkins", &["exploit/multi/http/jenkins_script_console"]),
    ("wordpress", &["auxiliary/scanner/http/wordpress_scanner"]),
    ("drupal", &["exploit/unix/webapp/drupal_drupalgeddon2"]),
    (
        "wp-admin",
        &[
            "auxiliary/scanner/http/wordpress_scanner",
            "auxiliary/scanner/http/wordpress_login_enum",
        ],
    ),
    ("robots.txt", &["auxiliary/scanner/http/robots_txt"]),
    ("pprof", &["auxiliary/scanner/http/golang_pprof"]),
    (
        "debug",
        &[
            "auxiliary/scanner/http/debug_page",
            "auxiliary/scanner/http/http_version",
        ],
    ),
];

fn banner_matches(banner_lower: &str, keyword: &str) -> bool {
    if keyword.len() <= 3 {
        let pattern = format!(
            r"(?i)(^|[\s/_.\-:;]){}([\s/_.\-:;]|$)",
            regex::escape(keyword)
        );
        regex::Regex::new(&pattern)
            .expect("valid regex")
            .is_match(banner_lower)
    } else {
        banner_lower.contains(keyword)
    }
}

pub fn suggest_modules(service_banner: &str) -> Vec<ModuleSuggestion> {
    let banner_lower = service_banner.to_lowercase();
    let mut suggestions = Vec::new();

    for (keyword, modules) in BANNER_CATALOG {
        if banner_matches(&banner_lower, keyword) {
            for module in *modules {
                suggestions.push(ModuleSuggestion {
                    service_banner: service_banner.to_string(),
                    suggested_module: (*module).to_string(),
                    confidence: "high".to_string(),
                });
            }
        }
    }

    suggestions
}

pub fn suggest_from_title(title: &str, details: &str) -> Vec<ModuleSuggestion> {
    let combined = format!("{} {}", title.to_lowercase(), details.to_lowercase());
    let mut suggestions = Vec::new();

    for (keyword, modules) in BANNER_CATALOG {
        if banner_matches(&combined, keyword) {
            for module in *modules {
                suggestions.push(ModuleSuggestion {
                    service_banner: format!("title/details match: {}", keyword),
                    suggested_module: (*module).to_string(),
                    confidence: "medium".to_string(),
                });
            }
        }
    }

    suggestions
}

pub fn get_all_known_banners() -> Vec<String> {
    let mut banners = BANNER_CATALOG
        .iter()
        .map(|(keyword, _)| (*keyword).to_string())
        .collect::<Vec<_>>();
    banners.sort();
    banners
}
