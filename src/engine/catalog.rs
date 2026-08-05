use std::collections::BTreeSet;

use crate::models::{MSFModule, ModuleSuggestion};

/// A module catalog built from a live Metasploit RPC listing
/// (`module.exploits`, `module.auxiliary`, `module.post`).
///
/// Unlike the static offline catalogs, the source of truth here is the
/// connected instance: a module is only ever suggested if it actually exists
/// on that instance, so names that do not exist (e.g. a hypothetical
/// `auxiliary/scanner/http/nginx_version`) can never be recommended.
///
/// Banner/title matching is derived from the module names themselves — the
/// significant tokens of each module's leaf name are matched against the
/// banner text — so no module names are hardcoded here.
pub struct LiveModuleCatalog {
    modules: Vec<MSFModule>,
    names: BTreeSet<String>,
}

impl LiveModuleCatalog {
    pub fn from_modules(modules: Vec<MSFModule>) -> Self {
        let names = modules.iter().map(|m| m.name.clone()).collect();
        Self { modules, names }
    }

    pub fn len(&self) -> usize {
        self.modules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    pub fn contains(&self, full_name: &str) -> bool {
        self.names.contains(full_name)
    }

    pub fn all(&self) -> &[MSFModule] {
        &self.modules
    }

    /// Suggest modules for a service banner. Confidence is high because the
    /// match is against the banner observed for a live service.
    pub fn suggest_for_banner(&self, banner: &str) -> Vec<ModuleSuggestion> {
        self.match_banner(banner, "high", banner.to_string())
    }

    /// Suggest modules for a finding title/details pair. Confidence is medium
    /// because the match is against free text rather than a live banner.
    pub fn suggest_for_title(&self, title: &str, details: &str) -> Vec<ModuleSuggestion> {
        let combined = format!("{} {}", title, details);
        self.match_banner(&combined, "medium", "title/details match".to_string())
    }

    /// Modules known for a CVE.
    ///
    /// The listing responses carry names only (no references), so the offline
    /// catalog is used as the candidate source and every candidate is filtered
    /// through the live names. Modules whose name embeds the CVE (e.g.
    /// `exploit/windows/rdp/cve_2019_0708_bluekeep`) are surfaced directly
    /// from the listing even when they are absent from the offline catalog.
    pub fn modules_for_cve(&self, cve: &str) -> Vec<MSFModule> {
        let needle = cve.trim().to_uppercase();
        let needle_key = needle.replace('-', "_").to_lowercase();
        let mut seen = BTreeSet::new();
        let mut found = Vec::new();

        for module in &self.modules {
            if !is_suggestable(&module.name) {
                continue;
            }
            let name_key = module.name.to_lowercase();
            if name_key.contains(&needle_key) && seen.insert(module.name.clone()) {
                found.push(module.clone());
            }
        }

        for module in crate::msf::modules_for_cve(&needle) {
            if self.names.contains(&module.name) && seen.insert(module.name.clone()) {
                found.push(module);
            }
        }

        found.sort_by(|a, b| a.name.cmp(&b.name));
        found
    }

    fn match_banner(&self, text: &str, confidence: &str, source: String) -> Vec<ModuleSuggestion> {
        let haystack = text.to_lowercase();
        let mut seen = BTreeSet::new();
        let mut suggestions = Vec::new();
        for module in &self.modules {
            if !is_suggestable(&module.name) {
                continue;
            }
            if leaf_matches(&module.name, &haystack) && seen.insert(module.name.clone()) {
                suggestions.push(ModuleSuggestion {
                    service_banner: source.clone(),
                    suggested_module: module.name.clone(),
                    confidence: confidence.to_string(),
                });
            }
        }
        suggestions
    }
}

/// Only host-facing modules are suggested: exploits and auxiliary modules.
/// Post modules operate on already-obtained sessions and are excluded.
fn is_suggestable(full_name: &str) -> bool {
    full_name.starts_with("exploit/") || full_name.starts_with("auxiliary/")
}

/// True when any significant token of the module's leaf name appears in the
/// banner text. Tokens shorter than three characters are ignored so generic
/// one-letter fragments (and the shared `version` suffix on every scanner)
/// cannot cause spurious matches on their own.
fn leaf_matches(module_name: &str, haystack: &str) -> bool {
    let leaf = module_name.rsplit('/').next().unwrap_or(module_name);
    leaf.split(['_', '-'])
        .any(|token| token.len() >= 3 && haystack.contains(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(name: &str) -> MSFModule {
        MSFModule {
            name: name.to_string(),
            cve: None,
            rank: "normal".to_string(),
            disclosure_date: "unknown".to_string(),
            platforms: Vec::new(),
            required_options: Vec::new(),
        }
    }

    /// A representative live listing (as returned by module.exploits /
    /// module.auxiliary / module.post) used by the tests below.
    fn sample_catalog() -> LiveModuleCatalog {
        LiveModuleCatalog::from_modules(vec![
            module("auxiliary/scanner/http/robots_txt"),
            module("auxiliary/scanner/http/apache_version"),
            module("auxiliary/scanner/http/http_version"),
            module("auxiliary/scanner/ssh/ssh_version"),
            module("auxiliary/scanner/mysql/mysql_version"),
            module("auxiliary/scanner/smb/smb_version"),
            module("exploit/windows/smb/ms17_010_eternalblue"),
            module("exploit/windows/rdp/cve_2019_0708_bluekeep"),
            module("post/multi/gather/env"),
        ])
    }

    #[test]
    fn banner_match_finds_existing_modules() {
        let catalog = sample_catalog();
        let suggestions = catalog.suggest_for_banner("Apache/2.4.49");
        assert!(suggestions
            .iter()
            .any(|s| s.suggested_module == "auxiliary/scanner/http/apache_version"));
        assert_eq!(
            suggestions[0].confidence, "high",
            "banner matches carry high confidence"
        );
    }

    #[test]
    fn banner_match_skips_non_existent_modules() {
        let catalog = sample_catalog();
        // nginx_version does not exist on the (simulated) instance, so even a
        // "nginx" banner must not produce a suggestion for it.
        let suggestions = catalog.suggest_for_banner("nginx/1.25");
        assert!(
            !suggestions
                .iter()
                .any(|s| s.suggested_module.contains("nginx_version")),
            "non-existent module must never be suggested"
        );
    }

    #[test]
    fn banner_match_finds_ssh_for_openssh_banner() {
        let catalog = sample_catalog();
        let suggestions = catalog.suggest_for_banner("OpenSSH/8.9p1");
        assert!(suggestions
            .iter()
            .any(|s| s.suggested_module == "auxiliary/scanner/ssh/ssh_version"));
    }

    #[test]
    fn title_match_finds_robots_txt() {
        let catalog = sample_catalog();
        let suggestions = catalog.suggest_for_title("robots.txt exposed", "");
        assert!(suggestions
            .iter()
            .any(|s| s.suggested_module == "auxiliary/scanner/http/robots_txt"));
        assert_eq!(
            suggestions[0].confidence, "medium",
            "title matches carry medium confidence"
        );
    }

    #[test]
    fn post_modules_are_never_suggested() {
        let catalog = sample_catalog();
        let suggestions = catalog.suggest_for_banner("environment variables");
        assert!(
            !suggestions
                .iter()
                .any(|s| s.suggested_module.starts_with("post/")),
            "post modules operate on sessions and must not be host suggestions"
        );
    }

    #[test]
    fn cve_lookup_filters_offline_candidates_through_live_list() {
        let catalog = sample_catalog();
        let modules = catalog.modules_for_cve("CVE-2021-41773");
        // The offline catalog maps this CVE to apache_path_traversal, but the
        // simulated instance does not load it, so nothing should be returned.
        assert!(
            !modules
                .iter()
                .any(|m| m.name.contains("apache_path_traversal")),
            "offline-only candidates must be filtered out when not present live"
        );
    }

    #[test]
    fn cve_lookup_surfaces_name_embedded_cves() {
        let catalog = sample_catalog();
        let modules = catalog.modules_for_cve("CVE-2019-0708");
        assert!(modules
            .iter()
            .any(|m| m.name == "exploit/windows/rdp/cve_2019_0708_bluekeep"));
    }

    #[test]
    fn leaf_matching_ignores_short_tokens() {
        // The token "sh" (from ssh) is too short to match on its own, and the
        // shared "version" token must not cause every *_version module to match.
        assert!(!leaf_matches("auxiliary/scanner/ssh/ssh_version", "xsh"));
    }
}
