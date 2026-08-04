use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::config::ConfigManager;
use crate::engine::{dedup, matcher, parser};
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

    let mut all_suggestions = Vec::<ModuleSuggestion>::new();
    let mut seen_suggestions = HashSet::<(String, String)>::new();

    println!("[+] Analyzing service banners, technologies and CVEs for module suggestions...");
    for record in &records {
        if let Some(service) = record.service.as_deref() {
            if opts.verbose {
                println!("[dbg] searching modules for service '{}'", service);
            }
            for suggestion in matcher::suggest_modules(service) {
                push_unique_suggestion(&mut all_suggestions, &mut seen_suggestions, suggestion);
            }
        }
        if !record.title.is_empty() {
            if opts.verbose {
                println!("[dbg] matching modules for title '{}'", record.title);
            }
            for suggestion in matcher::suggest_from_title(&record.title, &record.detail) {
                push_unique_suggestion(&mut all_suggestions, &mut seen_suggestions, suggestion);
            }
        }
        for cve in &record.cves {
            if opts.verbose {
                println!("[dbg] searching modules for {}", cve);
            }
            for module in crate::msf::modules_for_cve(cve) {
                let suggestion = ModuleSuggestion {
                    service_banner: format!("cve:{}", cve),
                    suggested_module: module.name.clone(),
                    confidence: if module.rank == "excellent" || module.rank == "great" {
                        "high".to_string()
                    } else {
                        "medium".to_string()
                    },
                };
                push_unique_suggestion(&mut all_suggestions, &mut seen_suggestions, suggestion);
            }
        }
    }

    if all_suggestions.is_empty() {
        println!("[?] No module suggestions for detected services or CVEs.");
    } else {
        println!(
            "[+] {} module suggestion(s) found:",
            all_suggestions.len()
        );
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
