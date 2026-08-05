use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use crate::config::ConfigManager;
use crate::engine::{catalog::LiveModuleCatalog, dedup, matcher, msfrpc, parser};
use crate::error::{AppError, Result};
use crate::models::{DedupStats, InjectableEndpoint, ModuleSuggestion, ScanRecord};
use crate::nvd::{EnrichmentStats, NVDClient};
use crate::report;

/// Options controlling the shared `process` pipeline.
#[derive(Debug, Clone)]
pub struct ProcessOptions {
    pub verbose: bool,
    /// Render the full console report to stdout.
    pub print_console: bool,
}

impl Default for ProcessOptions {
    fn default() -> Self {
        Self {
            verbose: false,
            print_console: true,
        }
    }
}

/// The outcome of running the shared process pipeline over one scan JSON.
#[derive(Debug)]
pub struct ProcessResult {
    pub records: Vec<ScanRecord>,
    pub injectable: Vec<InjectableEndpoint>,
    pub suggestions: Vec<ModuleSuggestion>,
    pub dedup_stats: DedupStats,
}

/// Shared pipeline: parse -> normalize -> dedup -> NVD enrich -> suggest.
/// Used by both the standalone `process` command and `ingest --process` so
/// the two never drift apart.
pub fn process_scan_file(
    input_path: &Path,
    config_mgr: &mut ConfigManager,
    opts: &ProcessOptions,
) -> Result<ProcessResult> {
    if opts.verbose {
        println!("[dbg] processing {}", input_path.display());
    }
    println!("[+] Loading scan results from: {}", input_path.display());
    let raw_json = std::fs::read_to_string(input_path)?;

    println!("[+] Parsing with Rust engine...");
    let mut parsed = parser::parse_vulnmalper_scan(&raw_json)?;
    let injectable = parsed.injectable_endpoints.clone();
    let raw_count = parsed.records.len();

    println!(
        "[+] Found {} raw findings ({} injectable endpoint{} flagged). Normalizing...",
        raw_count,
        injectable.len(),
        if injectable.len() == 1 { "" } else { "s" }
    );

    // Extract CVEs from every field before deduplication.
    for record in &mut parsed.records {
        crate::cve::extract_into_record(record);
    }
    let discovered_cves: std::collections::BTreeSet<String> = parsed
        .records
        .iter()
        .flat_map(|record| record.cves.iter().cloned())
        .collect();
    println!(
        "[+] Discovered {} CVE id{}.",
        discovered_cves.len(),
        if discovered_cves.len() == 1 { "" } else { "s" }
    );

    let dedup_result = dedup::deduplicate_records(parsed.records);
    let mut records = dedup_result.records;
    let dedup_stats = DedupStats {
        total: raw_count,
        unique: dedup_result.unique_count,
        removed: dedup_result.removed_count,
    };

    println!(
        "[+] Normalization + deduplication complete: {} unique, {} merged",
        dedup_stats.unique, dedup_stats.removed
    );
    println!();

    if config_mgr.is_nvd_configured() {
        let nvd_cfg = config_mgr.get_nvd_config().clone();
        let mut nvd_client = NVDClient::new(&nvd_cfg.api_key);
        println!("[+] Enriching discovered CVEs via NVD API...");
        let stats: EnrichmentStats = nvd_client.enrich_records(&mut records);
        println!(
            "[+] NVD enrichment complete: {} fetched, {} from cache, {} not found",
            stats.fetched, stats.cache_hits, stats.not_found
        );
        println!();
    }

    let live_catalog = connect_live_catalog(config_mgr, opts.verbose)?;

    let mut all_suggestions = Vec::<ModuleSuggestion>::new();
    let mut seen_suggestions = HashSet::<(String, String)>::new();
    let mut dropped_offline = BTreeSet::<String>::new();

    println!("[+] Analyzing service banners, technologies and CVEs for module suggestions...");
    for record in &records {
        if let Some(service) = record.service.as_deref() {
            if opts.verbose {
                println!("[dbg] searching modules for service '{}'", service);
            }
            let offline = matcher::suggest_modules(service);
            let live = match &live_catalog {
                Some(catalog) => catalog.suggest_for_banner(service),
                None => Vec::new(),
            };
            note_dropped_offline(&live_catalog, &offline, &live, &mut dropped_offline);
            for suggestion in live_or_offline(&live_catalog, offline, live) {
                push_unique_suggestion(&mut all_suggestions, &mut seen_suggestions, suggestion);
            }
        }
        if !record.title.is_empty() {
            if opts.verbose {
                println!("[dbg] matching modules for title '{}'", record.title);
            }
            let offline = matcher::suggest_from_title(&record.title, &record.detail);
            let live = match &live_catalog {
                Some(catalog) => catalog.suggest_for_title(&record.title, &record.detail),
                None => Vec::new(),
            };
            note_dropped_offline(&live_catalog, &offline, &live, &mut dropped_offline);
            for suggestion in live_or_offline(&live_catalog, offline, live) {
                push_unique_suggestion(&mut all_suggestions, &mut seen_suggestions, suggestion);
            }
        }
        for cve in &record.cves {
            if opts.verbose {
                println!("[dbg] searching modules for {}", cve);
            }
            let offline: Vec<ModuleSuggestion> = crate::msf::modules_for_cve(cve)
                .into_iter()
                .map(|module| suggestion_for_module(cve, &module))
                .collect();
            let live: Vec<ModuleSuggestion> = match &live_catalog {
                Some(catalog) => catalog
                    .modules_for_cve(cve)
                    .into_iter()
                    .map(|module| suggestion_for_module(cve, &module))
                    .collect(),
                None => Vec::new(),
            };
            note_dropped_offline(&live_catalog, &offline, &live, &mut dropped_offline);
            for suggestion in live_or_offline(&live_catalog, offline, live) {
                push_unique_suggestion(&mut all_suggestions, &mut seen_suggestions, suggestion);
            }
        }
    }

    if !dropped_offline.is_empty() {
        let dropped: Vec<&str> = dropped_offline.iter().map(String::as_str).collect();
        println!(
            "[!] Skipping {} module(s) not present on the connected MSF instance: {}",
            dropped.len(),
            dropped.join(", ")
        );
        println!();
    }

    if all_suggestions.is_empty() {
        println!("[?] No module suggestions for detected services or CVEs.");
    } else {
        println!("[+] {} module suggestion(s) found:", all_suggestions.len());
        for suggestion in &all_suggestions {
            println!(
                "    {} (confidence: {})",
                suggestion.suggested_module, suggestion.confidence
            );
        }
    }

    println!();

    if opts.print_console {
        println!(
            "{}",
            report::render_console_report(
                &records,
                &injectable,
                &all_suggestions,
                &[],
                &dedup_stats
            )
        );
        println!();
    }

    Ok(ProcessResult {
        records,
        injectable,
        suggestions: all_suggestions,
        dedup_stats,
    })
}

/// Write the PloitMalper markdown report for a processed result.
pub fn write_markdown_report(result: &ProcessResult, path: &Path) -> Result<PathBuf> {
    report::generate_markdown_report(
        &result.records,
        &result.injectable,
        &result.suggestions,
        &[],
        &result.dedup_stats,
        path.to_str().unwrap_or("report.md"),
    )
}

/// Locate every recognised VulnMalper JSON under `folder` and process it,
/// writing the PloitMalper markdown report next to each JSON. Returns the
/// number of reports written.
pub fn process_folder(
    folder: &Path,
    config_mgr: &mut ConfigManager,
    verbose: bool,
) -> Result<usize> {
    let scan = crate::ingest::scanner::scan_folder(folder, verbose)?;
    let jsons: Vec<_> = scan
        .artifacts
        .iter()
        .filter(|a| a.kind == crate::ingest::scanner::ArtifactKind::VulnMalperJson)
        .collect();

    if jsons.is_empty() {
        return Err(AppError::Message(format!(
            "no VulnMalper JSON files found in '{}' to process",
            folder.display()
        )));
    }

    let opts = ProcessOptions {
        verbose,
        print_console: false,
    };
    let mut written = 0usize;
    for artifact in &jsons {
        let input_path = PathBuf::from(&artifact.path);
        let report_path = report::derive_report_path(&input_path);
        println!();
        println!(
            "[+] Processing {} -> {}",
            input_path.display(),
            report_path.display()
        );
        let result = process_scan_file(&input_path, config_mgr, &opts)?;
        write_markdown_report(&result, &report_path)?;
        println!("[+] Report written to: {}", report_path.display());
        written += 1;
    }
    Ok(written)
}

fn push_unique_suggestion(
    suggestions: &mut Vec<ModuleSuggestion>,
    seen: &mut HashSet<(String, String)>,
    suggestion: ModuleSuggestion,
) {
    let key = (
        suggestion.service_banner.clone(),
        suggestion.suggested_module.clone(),
    );
    if seen.insert(key) {
        suggestions.push(suggestion);
    }
}

/// Connect to the configured MSF-RPC instance and load the live module
/// catalog. Returns `None` (and falls back to the offline catalogs) whenever
/// the instance is unreachable or its module listing cannot be fetched, so the
/// shared pipeline keeps working without a live Metasploit.
fn connect_live_catalog(
    config_mgr: &ConfigManager,
    verbose: bool,
) -> Result<Option<LiveModuleCatalog>> {
    if !config_mgr.is_configured() {
        if verbose {
            println!("[dbg] MSF-RPC not configured; using offline module catalogs.");
        }
        return Ok(None);
    }
    let cfg = config_mgr.get_msfrpc_config().clone();
    println!("[+] Connecting to MSF-RPC for live module lookup...");
    let mut client =
        msfrpc::MsfRpcClient::new(&cfg.host, cfg.port, &cfg.username, &cfg.password, cfg.ssl);
    let login = client.login()?;
    if !login.success {
        println!(
            "[!] MSF-RPC unreachable at {}:{}; using offline module catalogs. ({})",
            cfg.host, cfg.port, login.error
        );
        return Ok(None);
    }
    let modules = match client.list_modules() {
        Ok(modules) => modules,
        Err(error) => {
            println!(
                "[!] Could not list modules from MSF-RPC; using offline module catalogs. ({error})"
            );
            client.logout();
            return Ok(None);
        }
    };
    let catalog = LiveModuleCatalog::from_modules(modules);
    println!(
        "[+] Loaded {} module(s) from the connected instance; suggestions verified live.",
        catalog.len()
    );
    client.logout();
    Ok(Some(catalog))
}

/// When a live catalog is active, suggestions must come from the live module
/// list (which may be empty — that is the point: no offline guesses). When it
/// is not active, the offline suggestions are used as before.
fn live_or_offline(
    live_catalog: &Option<LiveModuleCatalog>,
    offline: Vec<ModuleSuggestion>,
    live: Vec<ModuleSuggestion>,
) -> Vec<ModuleSuggestion> {
    if live_catalog.is_some() {
        live
    } else {
        offline
    }
}

/// Record which offline-catalog modules were dropped because they do not exist
/// on the connected instance, so the operator can see the live verification in
/// action instead of silently losing suggestions.
fn note_dropped_offline(
    live_catalog: &Option<LiveModuleCatalog>,
    offline: &[ModuleSuggestion],
    live: &[ModuleSuggestion],
    dropped: &mut BTreeSet<String>,
) {
    if live_catalog.is_none() {
        return;
    }
    let live_names: HashSet<&str> = live.iter().map(|s| s.suggested_module.as_str()).collect();
    for suggestion in offline {
        if !live_names.contains(suggestion.suggested_module.as_str()) {
            dropped.insert(suggestion.suggested_module.clone());
        }
    }
}

fn suggestion_for_module(cve: &str, module: &crate::models::MSFModule) -> ModuleSuggestion {
    ModuleSuggestion {
        service_banner: format!("cve:{}", cve),
        suggested_module: module.name.clone(),
        confidence: if module.rank == "excellent" || module.rank == "great" {
            "high".to_string()
        } else {
            "medium".to_string()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suggestion(module: &str) -> ModuleSuggestion {
        ModuleSuggestion {
            service_banner: "banner".to_string(),
            suggested_module: module.to_string(),
            confidence: "high".to_string(),
        }
    }

    #[test]
    fn live_catalog_suppresses_offline_guesses() {
        // nginx_version exists only in the offline catalog; with a live catalog
        // present the offline suggestion must be dropped.
        let offline = vec![suggestion("auxiliary/scanner/http/nginx_version")];
        let live: Vec<ModuleSuggestion> = Vec::new();
        let mut dropped = BTreeSet::new();
        note_dropped_offline(
            &Some(LiveModuleCatalog::from_modules(Vec::new())),
            &offline,
            &live,
            &mut dropped,
        );
        assert!(dropped.contains("auxiliary/scanner/http/nginx_version"));
    }

    #[test]
    fn offline_fallback_keeps_offline_suggestions() {
        // Without a live catalog the offline suggestions flow through.
        let offline = vec![suggestion("auxiliary/scanner/http/robots_txt")];
        let live: Vec<ModuleSuggestion> = Vec::new();
        let chosen = live_or_offline(&None, offline.clone(), live);
        assert_eq!(chosen.len(), 1);
        assert_eq!(
            chosen[0].suggested_module,
            "auxiliary/scanner/http/robots_txt"
        );
    }

    #[test]
    fn live_catalog_replaces_offline_suggestions() {
        let offline = vec![suggestion("auxiliary/scanner/http/nginx_version")];
        let live = vec![suggestion("auxiliary/scanner/http/robots_txt")];
        let chosen = live_or_offline(
            &Some(LiveModuleCatalog::from_modules(Vec::new())),
            offline,
            live,
        );
        assert_eq!(chosen.len(), 1);
        assert_eq!(
            chosen[0].suggested_module,
            "auxiliary/scanner/http/robots_txt"
        );
    }
}
