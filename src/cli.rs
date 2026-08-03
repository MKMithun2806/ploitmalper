use std::collections::HashSet;
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use crate::config::ConfigManager;
use crate::engine::{dedup, matcher, msfrpc, parser};
use crate::error::{AppError, Result};
use crate::models::{DedupStats, ModuleSuggestion, PayloadRecipe};
use crate::nvd::{EnrichmentStats, NVDClient};
use crate::recipe;
use crate::report;
use crate::share;

pub fn main() {
    if let Err(err) = run() {
        eprintln!("[!] {}", err);
        std::process::exit(1);
    }
}

pub fn run() -> Result<()> {
    let mut config_mgr = ConfigManager::new();
    let config_loaded = config_mgr.load();

    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_banner();
        return Ok(());
    }

    match args[0].as_str() {
        "process" => {
            cmd_process(&args[1..], &mut config_mgr, config_loaded)?;
        }
        "share" => {
            cmd_share(&args[1..])?;
        }
        "reset-config" => {
            cmd_reset_config(&mut config_mgr)?;
        }
        "setup" => {
            cmd_setup(&mut config_mgr)?;
        }
        "db_setup" => {
            cmd_db_setup(&mut config_mgr)?;
        }
        "ingest" => {
            cmd_ingest(&args[1..], &mut config_mgr)?;
        }
        "-h" | "--help" => {
            print_banner();
        }
        other => {
            eprintln!("[!] Unknown command: {}", other);
            print_banner();
        }
    }

    Ok(())
}

fn cmd_setup(config_mgr: &mut ConfigManager) -> Result<()> {
    println!("PloitMalper Configuration Setup");
    println!();
    println!("--- MSF-RPC Configuration ---");
    println!("Enter your Metasploit RPC server details.");
    let current = config_mgr.get_msfrpc_config().clone();

    let host = prompt_text("MSF-RPC Host", &current.host)?;
    let port = prompt_u16("MSF-RPC Port", current.port)?;
    let username = prompt_text("MSF-RPC Username", &current.username)?;
    let password = prompt_text("MSF-RPC Password", &current.password)?;
    let ssl = prompt_bool("Use SSL?", current.ssl)?;
    let workspace = prompt_text("Workspace", &current.workspace)?;

    config_mgr.config.msfrpc.host = host;
    config_mgr.config.msfrpc.port = port;
    config_mgr.config.msfrpc.username = username;
    config_mgr.config.msfrpc.password = password;
    config_mgr.config.msfrpc.ssl = ssl;
    config_mgr.config.msfrpc.workspace = workspace;

    println!();
    println!("--- NVD API Configuration ---");
    println!("Enter your NVD API key for CVE enrichment (optional but recommended).");
    println!("Get one at: https://nvd.nist.gov/developers/request-an-api-key");
    let current_nvd = config_mgr.get_nvd_config().clone();
    let nvd_key = prompt_text("NVD API Key", &current_nvd.api_key)?;
    config_mgr.config.nvd.api_key = nvd_key;

    config_mgr.save()?;
    println!();
    println!(
        "[+] Configuration saved to {}",
        crate::config::config_file().display()
    );
    Ok(())
}

fn cmd_process(args: &[String], config_mgr: &mut ConfigManager, config_loaded: bool) -> Result<()> {
    let input_file = match args.first() {
        Some(path) => path,
        None => {
            eprintln!("[!] No input file specified. Use: ploit-malper process <scan.json>");
            return Ok(());
        }
    };

    let input_path = PathBuf::from(input_file);
    if !input_path.exists() {
        eprintln!("[!] File not found: {}", input_path.display());
        return Ok(());
    }

    println!("[+] Loading scan results from: {}", input_path.display());
    let raw_json = std::fs::read_to_string(&input_path)?;

    println!("[+] Parsing with Rust engine...");
    let parsed = parser::parse_vulnmalper_json(&raw_json)?;
    println!("[+] Found {} raw findings. Deduplicating...", parsed.len());

    let dedup_result = dedup::deduplicate_records(parsed);
    let mut records = dedup_result.records;
    let dedup_stats = DedupStats {
        total: records.len() + dedup_result.removed_count,
        unique: dedup_result.unique_count,
        removed: dedup_result.removed_count,
    };

    println!(
        "[+] Deduplication complete: {} unique, {} removed",
        dedup_stats.unique, dedup_stats.removed
    );
    println!();

    if config_mgr.is_nvd_configured() {
        let nvd_cfg = config_mgr.get_nvd_config().clone();
        let mut nvd_client = NVDClient::new(&nvd_cfg.api_key);
        println!("[+] Enriching CVEs via NVD API...");
        let stats: EnrichmentStats = nvd_client.enrich_records(&mut records);
        println!(
            "[+] NVD enrichment complete: {} fetched, {} from cache, {} not found",
            stats.fetched, stats.cache_hits, stats.not_found
        );
        println!();
    }

    let mut all_suggestions = Vec::<ModuleSuggestion>::new();
    let mut seen_suggestions = HashSet::<(String, String)>::new();

    println!("[+] Analyzing service banners and titles for module suggestions...");
    for record in &records {
        if let Some(service) = record.service.as_deref() {
            for suggestion in matcher::suggest_modules(service) {
                push_unique_suggestion(&mut all_suggestions, &mut seen_suggestions, suggestion);
            }
        }
        if !record.title.is_empty() {
            for suggestion in matcher::suggest_from_title(&record.title, "") {
                push_unique_suggestion(&mut all_suggestions, &mut seen_suggestions, suggestion);
            }
        }
    }

    if all_suggestions.is_empty() {
        println!("[?] No module suggestions for detected services.");
    }

    println!();
    println!(
        "{}",
        report::render_console_report(&records, &all_suggestions, &[])
    );
    println!();

    let mut msf_connected = false;
    let mut msf_client = None;
    if !config_loaded || !config_mgr.is_configured() {
        println!("[?] No MSF-RPC configuration found.");
        if prompt_bool_with_default("Configure MSF-RPC and NVD API now?", true)? {
            cmd_setup(config_mgr)?;
        } else {
            println!("[?] Continuing without MSF-RPC integration.");
            println!();
        }
    }

    if config_mgr.is_configured() {
        let msf_cfg = config_mgr.get_msfrpc_config().clone();
        println!();
        println!("[+] Connecting to MSF-RPC for workspace verification...");
        let mut client = msfrpc::MsfRpcClient::new(
            &msf_cfg.host,
            msf_cfg.port,
            &msf_cfg.username,
            &msf_cfg.password,
            msf_cfg.ssl,
        );

        let login_result = client.login()?;
        if login_result.success {
            msf_connected = true;
            println!(
                "[+] Authenticated to MSF-RPC at {}:{}",
                msf_cfg.host, msf_cfg.port
            );

            let ws_result = client.get_workspaces()?;
            if !ws_result.workspaces.is_empty() {
                println!();
                println!("MSF Workspaces");
                println!("{:<24} {:<16} {:>8}", "Name", "Scope", "Hosts");
                println!("{}", "-".repeat(52));
                for workspace in &ws_result.workspaces {
                    println!(
                        "{:<24} {:<16} {:>8}",
                        truncate(&workspace.name, 24),
                        truncate(&workspace.scope, 16),
                        workspace.host_count
                    );
                }
            }

            for record in records.iter().take(5) {
                if let Some(target) = record.target.as_str().split_whitespace().next() {
                    let check_result =
                        client.check_host_exists(target, Some(&msf_cfg.workspace))?;
                    if check_result.exists {
                        println!(
                            "[?] Host {} already exists in workspace '{}'",
                            target, msf_cfg.workspace
                        );
                    }
                }
            }
        } else {
            println!(
                "[!] Remote MSF-RPC unreachable. Switched entirely to offline matching matrix."
            );
            println!("    Error: {}", login_result.error);
        }

        msf_client = Some(client);
    }

    let mut recipes: Vec<PayloadRecipe> = Vec::new();
    if prompt_bool_with_default("\nGenerate msfvenom payload recipes?", false)? {
        println!();
        println!("Payload Recipe Builder");
        let platforms = recipe::get_available_platforms();
        println!("Available platforms: {}", platforms.join(", "));
        let platform = prompt_choice("Platform", &platforms, "windows")?;
        let arches = recipe::get_available_arches(&platform);
        println!("Available architectures: {}", arches.join(", "));
        let arch = prompt_choice("Architecture", &arches, "x64")?;
        let lhost = prompt_text("LHOST", "10.0.0.1")?;
        let lport = prompt_u16("LPORT", 4444)?;
        let output = prompt_text("Output path", "/tmp/payload")?;

        let recipe = recipe::build_recipe(&platform, &arch, &lhost, lport, &output, None, None);
        println!();
        println!("Generated recipe:");
        println!("{}", recipe.command);
        recipes.push(recipe);
    }

    if prompt_bool_with_default("\nWrite findings to Markdown report (report.md)?", true)? {
        let output_path = report::generate_markdown_report(
            &records,
            &all_suggestions,
            &recipes,
            &dedup_stats,
            "report.md",
        )?;
        println!();
        println!("[+] Report written to: {}", output_path.display());
    }

    if msf_connected {
        if let Some(mut client) = msf_client {
            client.logout();
        }
    }

    config_mgr.config.last_scan_file = Some(input_path.to_string_lossy().to_string());
    config_mgr.save()?;
    Ok(())
}

fn cmd_share(args: &[String]) -> Result<()> {
    let mut directory = PathBuf::from(".");
    let mut port = 8888u16;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--directory" | "-d" => {
                if let Some(value) = args.get(index + 1) {
                    directory = PathBuf::from(value);
                    index += 2;
                    continue;
                }
            }
            "--port" | "-p" => {
                if let Some(value) = args.get(index + 1) {
                    port = value
                        .parse::<u16>()
                        .map_err(|_| AppError::Message(format!("Invalid port value: {}", value)))?;
                    index += 2;
                    continue;
                }
            }
            _ => {}
        }
        index += 1;
    }

    println!("[+] Starting file server in: {}", directory.display());
    println!("[+] Port: {}", port);
    println!();

    let (server, actual_port) = share::start_file_server(directory, port)?;
    println!(
        "File server running at http://0.0.0.0:{} (press Ctrl+C to stop)",
        actual_port
    );

    let _server = server;
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

fn cmd_reset_config(config_mgr: &mut ConfigManager) -> Result<()> {
    println!("[?] Resetting all stored configuration...");
    config_mgr.reset()?;
    println!("[+] Configuration reset. Run ploit-malper to set up credentials.");
    Ok(())
}

fn cmd_db_setup(config_mgr: &mut ConfigManager) -> Result<()> {
    let verbose = std::env::args().any(|a| a == "--verbose" || a == "-v");

    println!("PloitMalper Database Setup");
    println!();
    println!("The intelligence database stores scan artifacts (NetMalper, VulnMalper,");
    println!("PloitMalper) with history tracking. PocketBase is the primary backend with");
    println!("SQLite as the local fallback.");
    println!();

    let current = config_mgr.get_database_config().clone();
    let backend_choices = vec!["pocketbase".to_string(), "sqlite".to_string()];
    let backend = prompt_choice("Backend", &backend_choices, &current.backend)?;

    let mut db = current.clone();
    db.backend = backend;

    if db.backend == "pocketbase" {
        println!();
        println!("--- PocketBase Configuration ---");
        db.pocketbase_url = prompt_text("PocketBase URL", &db.pocketbase_url)?;
        db.pocketbase_admin_email = prompt_text("Admin email", &db.pocketbase_admin_email)?;
        db.pocketbase_admin_password =
            prompt_text("Admin password", &db.pocketbase_admin_password)?;

        println!();
        println!("[+] Preparing schema file...");
        crate::db::schema::write_schema_file()?;
        println!(
            "[+] Schema written to {}",
            crate::config::db_schema_file().display()
        );

        if !crate::db::schema::pbctl_available() {
            println!("[!] pbctl not found on PATH; falling back to direct PocketBase API.");
        } else {
            println!();
            println!("--- Schema plan (pbctl plan) ---");
            let plan = crate::db::schema::pbctl_plan(&db, verbose)?;
            print!("{}", plan.combined());
            if !plan.success() {
                return Err(AppError::Message(format!(
                    "pbctl plan failed (exit {})",
                    plan.exit_code
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "?".to_string())
                )));
            }
        }

        if prompt_bool_with_default("Apply schema to PocketBase?", true)? {
            if crate::db::schema::pbctl_available() {
                println!("[+] Applying schema via pbctl...");
                let out = crate::db::schema::pbctl_apply(&db, verbose)?;
                print!("{}", out.combined());
                if !out.success() {
                    return Err(AppError::Message(format!(
                        "pbctl apply failed (exit {})",
                        out.exit_code
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "?".to_string())
                    )));
                }
            } else {
                println!("[+] Creating collections via PocketBase API...");
                let mut storage = crate::db::open_storage(&db)?;
                if !storage.ping()? {
                    return Err(AppError::Message(
                        "PocketBase is not reachable at the configured URL".to_string(),
                    ));
                }
                storage.ensure_schema()?;
            }
        } else {
            println!("[!] Schema not applied. Configuration saved for later use.");
        }
    } else {
        println!();
        println!("--- SQLite Configuration ---");
        db.sqlite_path = prompt_text("SQLite database path", &db.sqlite_path)?;
        println!("[+] Initializing SQLite database...");
        let mut storage = crate::db::open_storage(&db)?;
        storage.ensure_schema()?;
        if !storage.ping()? {
            return Err(AppError::Message(
                "SQLite database could not be opened".to_string(),
            ));
        }
        println!("[+] SQLite database ready.");
    }

    db.configured = true;
    config_mgr.config.database = db;
    config_mgr.save()?;
    println!();
    println!(
        "[+] Database configuration saved to {}",
        crate::config::config_file().display()
    );
    Ok(())
}

fn cmd_ingest(args: &[String], config_mgr: &mut ConfigManager) -> Result<()> {
    let mut folder: Option<PathBuf> = None;
    let mut opts = crate::ingest::importer::IngestOptions::default();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--verbose" | "-v" => opts.verbose = true,
            "--dry-run" => opts.dry_run = true,
            "--force" | "-f" => opts.force = true,
            "--backend" | "-b" => {
                if let Some(value) = args.get(index + 1) {
                    if !["pocketbase", "sqlite", "auto"].contains(&value.as_str()) {
                        return Err(AppError::Message(format!(
                            "invalid backend '{}' (use pocketbase, sqlite or auto)",
                            value
                        )));
                    }
                    opts.backend = value.clone();
                    index += 1;
                }
            }
            "--pocketbase-url" => {
                if let Some(value) = args.get(index + 1) {
                    opts.pocketbase_url = Some(value.clone());
                    index += 1;
                }
            }
            "--sqlite-path" => {
                if let Some(value) = args.get(index + 1) {
                    opts.sqlite_path = Some(value.clone());
                    index += 1;
                }
            }
            "-h" | "--help" => {
                println!(
                    "Usage: ploit-malper ingest <folder> [--verbose] [--dry-run] [--force] \
                     [--backend pocketbase|sqlite|auto] [--pocketbase-url URL] [--sqlite-path PATH]"
                );
                return Ok(());
            }
            other if folder.is_none() && !other.starts_with('-') => {
                folder = Some(PathBuf::from(other));
            }
            other => {
                return Err(AppError::Message(format!(
                    "unknown ingest option: {}",
                    other
                )));
            }
        }
        index += 1;
    }

    let folder = folder.ok_or_else(|| {
        AppError::Message(
            "ingest requires a folder path (e.g. ploit-malper ingest ./results)".to_string(),
        )
    })?;

    if !config_mgr.database_configured() {
        return Err(AppError::Message(
            "no database configured; run 'ploit-malper db_setup' first".to_string(),
        ));
    }

    let summary =
        crate::ingest::importer::ingest_folder(&folder, config_mgr.get_database_config(), &opts)?;

    if opts.dry_run || summary.skipped_already_imported {
        return Ok(());
    }

    println!();
    println!("[+] Import summary:");
    println!("    run_id:        {}", summary.run_id);
    println!("    target:        {}", summary.target);
    println!(
        "    artifacts:     {} accepted, {} rejected",
        summary.artifacts_accepted, summary.artifacts_rejected
    );
    println!("    assets:        {}", summary.assets);
    println!("    services:      {}", summary.services);
    println!("    findings:      {}", summary.findings);
    println!("    relationships: {}", summary.relationships);
    println!("    reports:       {}", summary.reports);
    println!("    observations:  {}", summary.observations);
    Ok(())
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

fn prompt_text(prompt: &str, default: &str) -> Result<String> {
    print!("  {} [{}]: ", prompt, default);
    io::stdout().flush()?;
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;
    let value = buffer.trim();
    Ok(if value.is_empty() {
        default.to_string()
    } else {
        value.to_string()
    })
}

fn prompt_u16(prompt: &str, default: u16) -> Result<u16> {
    loop {
        let value = prompt_text(prompt, &default.to_string())?;
        if value.is_empty() {
            return Ok(default);
        }
        match value.parse::<u16>() {
            Ok(parsed) => return Ok(parsed),
            Err(_) => println!("  Please enter a valid number."),
        }
    }
}

fn prompt_bool(prompt: &str, default: bool) -> Result<bool> {
    prompt_bool_with_default(prompt, default)
}

fn prompt_bool_with_default(prompt: &str, default: bool) -> Result<bool> {
    let suffix = if default { "[Y/n]" } else { "[y/N]" };
    loop {
        print!("  {} {}: ", prompt, suffix);
        io::stdout().flush()?;
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer)?;
        let value = buffer.trim().to_lowercase();
        if value.is_empty() {
            return Ok(default);
        }
        match value.as_str() {
            "y" | "yes" | "true" => return Ok(true),
            "n" | "no" | "false" => return Ok(false),
            _ => println!("  Please answer yes or no."),
        }
    }
}

fn prompt_choice(prompt: &str, choices: &[String], default: &str) -> Result<String> {
    let resolved_default = if choices.iter().any(|c| c == default) {
        default.to_string()
    } else {
        choices.first().cloned().unwrap_or_default()
    };
    loop {
        print!("  {} [{}]: ", prompt, resolved_default);
        io::stdout().flush()?;
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer)?;
        let value = buffer.trim();
        if value.is_empty() {
            return Ok(resolved_default);
        }
        if choices.iter().any(|choice| choice == value) {
            return Ok(value.to_string());
        }
        println!("  Please choose one of: {}", choices.join(", "));
    }
}

fn truncate(value: &str, width: usize) -> String {
    let count = value.chars().count();
    if count <= width {
        return value.to_string();
    }
    if width <= 1 {
        return "…".to_string();
    }
    let mut truncated = value.chars().take(width - 1).collect::<String>();
    truncated.push('…');
    truncated
}

fn print_banner() {
    println!("PloitMalper v{}", env!("CARGO_PKG_VERSION"));
    println!("Vulnerability Post-Processing and Analysis Toolkit");
    println!();
    println!("Commands:");
    println!("  process <file>   Process and deduplicate scan results");
    println!("  db_setup         Configure the intelligence database (PocketBase/SQLite)");
    println!("  ingest <folder>  Import Malper scan artifacts into the database");
    println!("  share            Start temporary file server");
    println!("  setup            Configure MSF-RPC and NVD API credentials");
    println!("  reset-config     Reset stored configuration");
}
