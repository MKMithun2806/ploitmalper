use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::DatabaseConfig;
use crate::db::content;
use crate::db::models::{
    now_utc, sha256_hex, Asset, Finding, Observation, ScanRun, Service, ASSET_REMOVED,
};
use crate::db::Storage;
use crate::error::{AppError, Result};
use crate::ingest::scanner::{scan_folder, Artifact, ArtifactKind};

/// Options controlling a single `ingest` invocation.
#[derive(Debug, Clone)]
pub struct IngestOptions {
    pub verbose: bool,
    pub dry_run: bool,
    pub force: bool,
    /// Run the `process` pipeline over every VulnMalper JSON in the folder
    /// and write a fresh PloitMalper report next to it before ingesting.
    pub process: bool,
    /// Backend override: "auto" uses the persisted config.
    pub backend: String,
    pub pocketbase_url: Option<String>,
    pub sqlite_path: Option<String>,
}

impl Default for IngestOptions {
    fn default() -> Self {
        Self {
            verbose: false,
            dry_run: false,
            force: false,
            process: false,
            backend: "auto".to_string(),
            pocketbase_url: None,
            sqlite_path: None,
        }
    }
}

/// Summary returned to the CLI after an import attempt.
#[derive(Debug, Default, Clone)]
pub struct IngestSummary {
    pub run_id: String,
    pub target: String,
    pub artifacts_accepted: usize,
    pub artifacts_rejected: usize,
    pub assets: usize,
    pub services: usize,
    pub findings: usize,
    pub observations: usize,
    pub skipped_already_imported: bool,
    pub dry_run: bool,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn ingest_folder(
    folder: &Path,
    config: &DatabaseConfig,
    opts: &IngestOptions,
) -> Result<IngestSummary> {
    if opts.verbose {
        println!("[+] Scanning folder: {}", folder.display());
    }
    let scan = scan_folder(folder, opts.verbose)?;

    // Malper analyse reports are recognised but intentionally ignored.
    for artifact in scan
        .artifacts
        .iter()
        .filter(|a| a.kind == ArtifactKind::MalperAnalyse)
    {
        println!(
            "[.] Ignoring Malper analyse report (by design): {}",
            artifact.path.display()
        );
    }

    let accepted: Vec<&Artifact> = scan
        .artifacts
        .iter()
        .filter(|a| a.kind != ArtifactKind::MalperAnalyse)
        .collect();

    if accepted.is_empty() {
        return Err(AppError::Message(format!(
            "no Malper artifacts found in '{}' ({} file(s) rejected)",
            folder.display(),
            scan.rejected.len()
        )));
    }

    // ------------------------------------------------------------------
    // Run identity
    // ------------------------------------------------------------------
    let mut infos = Vec::new();
    for artifact in &accepted {
        infos.push((artifact, extract_info(artifact)?));
    }

    let explicit_ids: Vec<String> = infos
        .iter()
        .filter_map(|(_, info)| info.run_id.clone())
        .collect();
    if explicit_ids.len() > 1 {
        let mut unique: Vec<String> = Vec::new();
        for id in &explicit_ids {
            if !unique.contains(id) {
                unique.push(id.clone());
            }
        }
        if unique.len() > 1 {
            return Err(AppError::Message(format!(
                "mixed run: multiple explicit run ids found ({})",
                unique.join(", ")
            )));
        }
    }

    // Primary target: prefer the NetMalper graph, then VulnMalper JSON.
    let primary = infos
        .iter()
        .find(|(a, _)| a.kind == ArtifactKind::NetMalperGraph)
        .or_else(|| {
            infos
                .iter()
                .find(|(a, _)| a.kind == ArtifactKind::VulnMalperJson)
        })
        .or_else(|| infos.first())
        .map(|(_, info)| info.target.clone())
        .unwrap_or_default();

    let folder_hint = folder
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    for (artifact, info) in &infos {
        if !target_compatible(&primary, &info.target, &folder_hint) {
            return Err(AppError::Message(format!(
                "mixed/incompatible run: {} targets '{}' but run target is '{}'",
                artifact.path.display(),
                info.target,
                primary
            )));
        }
    }

    let run_id = if explicit_ids.is_empty() {
        let combined = content_hash(&accepted);
        format!("run_{}", sha256_hex(&format!("{}:{}", primary, combined)))
    } else {
        explicit_ids[0].clone()
    };
    let content_hash = content_hash(&accepted);

    let started_at = infos
        .iter()
        .filter_map(|(_, info)| info.timestamp.as_deref())
        .filter_map(rfc3339)
        .min()
        .map(|dt| dt.to_string());

    let mut summary = IngestSummary {
        run_id: run_id.clone(),
        target: primary.clone(),
        artifacts_accepted: accepted.len(),
        artifacts_rejected: scan.rejected.len(),
        dry_run: opts.dry_run,
        ..Default::default()
    };

    if opts.dry_run {
        println!("[dry-run] would import {} artifact(s):", accepted.len());
        for artifact in &accepted {
            println!(
                "  - {} ({})",
                artifact.path.display(),
                artifact.kind.label()
            );
        }
        println!(
            "[dry-run] run_id={} target={} content_hash={}",
            run_id, primary, content_hash
        );
        return Ok(summary);
    }

    // ------------------------------------------------------------------
    // Storage
    // ------------------------------------------------------------------
    let backend = if opts.backend == "auto" {
        config.backend.as_str()
    } else {
        opts.backend.as_str()
    };
    let mut storage = crate::db::open_storage_with(
        config,
        backend,
        opts.pocketbase_url.as_deref(),
        opts.sqlite_path.as_deref(),
    )?;

    if !storage.ping()? {
        return Err(AppError::Message(format!(
            "{} backend is not reachable",
            storage.kind()
        )));
    }
    storage.ensure_schema()?;

    if let Some(run) = storage.get_scan_run(&run_id)? {
        if !opts.force {
            if run.content_hash == content_hash {
                println!(
                    "[+] Run {} already imported (target={}); skipping (use --force to re-import)",
                    run_id, primary
                );
                summary.skipped_already_imported = true;
                return Ok(summary);
            }
            return Err(AppError::Message(format!(
                "run {} already exists with different content (target={}); use --force to re-import",
                run_id, primary
            )));
        }
        println!("[+] Re-importing run {} (--force)", run_id);
    }

    // Snapshot existing state for observation diffing.
    let prev_assets: HashMap<String, Asset> = storage
        .list_assets()?
        .into_iter()
        .map(|a| (a.stable_id.clone(), a))
        .collect();
    let prev_services: HashMap<String, Service> = storage
        .list_all_services()?
        .into_iter()
        .map(|s| (s.stable_id.clone(), s))
        .collect();
    let prev_findings: HashMap<String, Finding> = storage
        .list_all_findings()?
        .into_iter()
        .map(|f| (f.stable_id.clone(), f))
        .collect();

    // ------------------------------------------------------------------
    // Build the new world state in dependency order.
    // ------------------------------------------------------------------
    let mut ctx = BuildContext {
        assets: HashMap::new(),
        services: HashMap::new(),
        findings: HashMap::new(),
        report_content_paths: HashMap::new(),
        has_vulnmalper_json: false,
    };

    for artifact in &accepted {
        match artifact.kind {
            ArtifactKind::NetMalperGraph => import_netmalper(artifact, &mut ctx)?,
            ArtifactKind::VulnMalperJson => {
                ctx.has_vulnmalper_json = true;
                import_vulnmalper_json(artifact, &mut ctx)?;
            }
            ArtifactKind::VulnMalperMarkdown => import_vulnmalper_markdown(artifact, &mut ctx)?,
            ArtifactKind::PloitMalperReport => import_ploitmalper_report(artifact, &mut ctx)?,
            ArtifactKind::MalperAnalyse => {}
        }
    }

    // ------------------------------------------------------------------
    // Commit with history-aware diffs.
    // ------------------------------------------------------------------
    let mut observations = Vec::new();

    let mut asset_observations =
        commit_assets(&mut storage, &run_id, &mut ctx.assets, &prev_assets)?;
    observations.append(&mut asset_observations);
    summary.assets = ctx.assets.len();

    let mut service_observations =
        commit_services(&mut storage, &run_id, &mut ctx.services, &prev_services)?;
    observations.append(&mut service_observations);
    summary.services = ctx.services.len();

    let mut finding_observations =
        commit_findings(&mut storage, &run_id, &mut ctx.findings, &prev_findings)?;
    observations.append(&mut finding_observations);
    summary.findings = ctx.findings.len();

    for observation in &observations {
        storage.add_observation(observation)?;
    }
    summary.observations = observations.len();

    // ------------------------------------------------------------------
    // Scan run record
    // ------------------------------------------------------------------
    let tools = accepted
        .iter()
        .map(|a| tool_for_kind(a.kind))
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect::<HashSet<_>>();
    let mut tools: Vec<String> = tools.into_iter().collect();
    tools.sort();
    tools.dedup();

    let artifact_refs: Vec<Value> = accepted
        .iter()
        .map(|a| {
            let mut entry = json!({
                "path": a.path.display().to_string(),
                "kind": a.kind.label(),
                "size": a.size,
                "hash": a.hash,
            });
            if let Some(rel) = ctx.report_content_paths.get(&a.hash) {
                entry["content_path"] = json!(rel);
                entry["tool"] = json!(tool_for_kind(a.kind));
            }
            entry
        })
        .collect();

    let mut run = ScanRun::new(
        &run_id,
        &primary,
        &folder.display().to_string(),
        &content_hash,
        started_at,
    );
    run.tools = tools;
    run.artifacts = artifact_refs;
    run.finished_at = Some(now_utc());
    run.stats = json!({
        "assets": summary.assets,
        "services": summary.services,
        "findings": summary.findings,
        "observations": summary.observations,
    });
    storage.upsert_scan_run(&run)?;

    if opts.verbose {
        println!("[+] Imported run {} (target={})", run_id, primary);
        println!(
            "    assets={} services={} findings={} observations={}",
            summary.assets, summary.services, summary.findings, summary.observations
        );
    }

    Ok(summary)
}

// ---------------------------------------------------------------------------
// Run identity helpers
// ---------------------------------------------------------------------------

struct ArtifactInfo {
    target: String,
    timestamp: Option<String>,
    run_id: Option<String>,
}

fn extract_info(artifact: &Artifact) -> Result<ArtifactInfo> {
    match artifact.kind {
        ArtifactKind::NetMalperGraph | ArtifactKind::VulnMalperJson => {
            let value: Value = serde_json::from_str(&artifact.content)?;
            let object = value
                .as_object()
                .ok_or_else(|| AppError::Message("artifact JSON is not an object".to_string()))?;

            if artifact.kind == ArtifactKind::NetMalperGraph {
                let meta = object
                    .get("meta")
                    .and_then(Value::as_object)
                    .ok_or_else(|| AppError::Message("netmalper graph missing meta".to_string()))?;
                Ok(ArtifactInfo {
                    target: meta
                        .get("target")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    timestamp: meta
                        .get("timestamp")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    run_id: explicit_run_id(object),
                })
            } else {
                let vuln = object
                    .get("vulnmalper")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        AppError::Message("vulnmalper json missing metadata".to_string())
                    })?;
                Ok(ArtifactInfo {
                    target: vuln
                        .get("source_target")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    timestamp: vuln
                        .get("generated_utc")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    run_id: explicit_run_id(object),
                })
            }
        }
        ArtifactKind::VulnMalperMarkdown => Ok(ArtifactInfo {
            target: md_kv(&artifact.content, "**Target:**").unwrap_or_default(),
            timestamp: md_kv(&artifact.content, "**Generated:**"),
            run_id: None,
        }),
        ArtifactKind::PloitMalperReport => {
            let target = artifact
                .content
                .lines()
                .find(|l| l.contains("**Host:**"))
                .and_then(|l| l.split("**Host:**").nth(1))
                .and_then(extract_backtick_or_trim)
                .unwrap_or_default();
            let timestamp = artifact
                .content
                .lines()
                .find(|l| l.contains("**Generated:**"))
                .and_then(|l| l.split("**Generated:**").nth(1))
                .map(|rest| rest.trim().trim_matches('`').trim().to_string());
            Ok(ArtifactInfo {
                target,
                timestamp,
                run_id: None,
            })
        }
        ArtifactKind::MalperAnalyse => Ok(ArtifactInfo {
            target: String::new(),
            timestamp: None,
            run_id: None,
        }),
    }
}

fn explicit_run_id(object: &serde_json::Map<String, Value>) -> Option<String> {
    object
        .get("run_id")
        .or_else(|| object.get("runId"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Extract the backtick-quoted value following a markdown marker like
/// `**Target:**`.
fn md_kv(content: &str, marker: &str) -> Option<String> {
    let line = content.lines().find(|l| l.contains(marker))?;
    let rest = line.split(marker).nth(1)?;
    extract_backtick_or_trim(rest)
}

fn extract_backtick_or_trim(rest: &str) -> Option<String> {
    let rest = rest.trim();
    if let Some(start) = rest.find('`') {
        let after = &rest[start + 1..];
        if let Some(end) = after.find('`') {
            return Some(after[..end].trim().to_string());
        }
        return Some(after.trim().to_string());
    }
    if rest.is_empty() {
        return None;
    }
    let value = rest.split('|').next().unwrap_or(rest).trim();
    Some(value.to_string())
}

/// Normalise an RFC3339 timestamp, a `YYYY-MM-DD HH:MM:SS UTC` string, or a
/// unix epoch into an RFC3339 string.
fn rfc3339(value: &str) -> Option<OffsetDateTime> {
    let trimmed = value.trim();
    if let Ok(dt) = OffsetDateTime::parse(trimmed, &Rfc3339) {
        return Some(dt);
    }
    let normalised = trimmed.replace(" UTC", "Z").replace(' ', "T");
    if let Ok(dt) = OffsetDateTime::parse(&normalised, &Rfc3339) {
        return Some(dt);
    }
    if let Ok(epoch) = trimmed.parse::<i64>() {
        if let Ok(dt) = OffsetDateTime::from_unix_timestamp(epoch) {
            return Some(dt);
        }
    }
    None
}

fn content_hash(artifacts: &[&Artifact]) -> String {
    let mut hashes: Vec<&str> = artifacts.iter().map(|a| a.hash.as_str()).collect();
    hashes.sort_unstable();
    sha256_hex(&hashes.join("|"))
}

fn target_compatible(primary: &str, other: &str, folder_hint: &str) -> bool {
    let primary = normalize_target(primary);
    let other = normalize_target(other);
    if primary.is_empty() || other.is_empty() {
        return true;
    }
    if primary == other {
        return true;
    }

    // IP addresses must match exactly — substring matching would wrongly treat
    // e.g. 192.168.1.14 and 192.168.1.1 as related.
    if is_ip(&primary) || is_ip(&other) {
        return false;
    }

    // Hostname compatibility: same domain or subdomain-of relationship.
    let primary_labels: Vec<&str> = primary.split('.').collect();
    let other_labels: Vec<&str> = other.split('.').collect();
    let subdomain = |a: &[&str], b: &[&str]| a.len() >= 2 && b.len() >= 2 && a.ends_with(b);
    if subdomain(&primary_labels, &other_labels) || subdomain(&other_labels, &primary_labels) {
        return true;
    }

    // Folder name anchors the run (e.g. `ploit-malper ingest ./results/example.com`).
    if !folder_hint.is_empty()
        && (primary == folder_hint
            || other == folder_hint
            || primary.ends_with(&format!(".{}", folder_hint))
            || other.ends_with(&format!(".{}", folder_hint)))
    {
        return true;
    }

    false
}

fn normalize_target(value: &str) -> String {
    let lower = value.trim().to_lowercase();
    let stripped = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);
    let host = stripped.trim_end_matches('/');

    // Strip a `:port` suffix unless this is an IPv6 literal.
    if host.parse::<std::net::Ipv6Addr>().is_err() {
        if let Some(colon) = host.rfind(':') {
            let after = &host[colon + 1..];
            if !after.is_empty() && after.chars().all(|c| c.is_ascii_digit()) {
                return host[..colon].to_string();
            }
        }
    }
    host.to_string()
}

fn is_ip(value: &str) -> bool {
    value.parse::<std::net::Ipv4Addr>().is_ok() || value.parse::<std::net::Ipv6Addr>().is_ok()
}

fn classify_target(value: &str) -> &'static str {
    let host = normalize_target(value);
    if host.parse::<std::net::Ipv4Addr>().is_ok() || host.parse::<std::net::Ipv6Addr>().is_ok() {
        "ip"
    } else if host.split('.').count() > 1 {
        "domain"
    } else {
        "hostname"
    }
}

/// The tool that produced an artifact, used for ScanRun.tools and report refs.
fn tool_for_kind(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::NetMalperGraph => "netmalper",
        ArtifactKind::VulnMalperJson | ArtifactKind::VulnMalperMarkdown => "vulnmalper",
        ArtifactKind::PloitMalperReport => "ploitmalper",
        ArtifactKind::MalperAnalyse => "",
    }
}

/// Store a report artifact's full content in the content store and remember
/// where it went so the ScanRun record can reference it.
fn store_report(ctx: &mut BuildContext, artifact: &Artifact) -> Result<()> {
    let (_, rel) = content::store_content(&artifact.content)?;
    ctx.report_content_paths.insert(artifact.hash.clone(), rel);
    Ok(())
}

fn service_id(asset_id: &str, port: u16, protocol: &str) -> String {
    sha256_hex(&format!("service:{}:{}:{}", asset_id, port, protocol))
}

fn new_service(asset_id: &str, port: u16, protocol: &str, name: &str) -> Service {
    let mut service = Service::new(asset_id, port, protocol, name);
    service.stable_id = service_id(asset_id, port, protocol);
    service
}

fn push_endpoint(metadata: &mut Value, url: &str) {
    if !metadata.is_object() {
        *metadata = json!({});
    }
    if let Some(arr) = metadata["endpoints"].as_array_mut() {
        if !arr.iter().any(|v| v.as_str() == Some(url)) {
            arr.push(json!(url));
        }
    } else {
        metadata["endpoints"] = json!([url]);
    }
}

// ---------------------------------------------------------------------------
// World-state building
// ---------------------------------------------------------------------------

struct BuildContext {
    assets: HashMap<String, Asset>,
    services: HashMap<String, Service>,
    findings: HashMap<String, Finding>,
    /// artifact hash -> content-store relative path of the stored report.
    report_content_paths: HashMap<String, String>,
    has_vulnmalper_json: bool,
}

impl BuildContext {
    fn ensure_asset(&mut self, name: &str) {
        if !self
            .assets
            .contains_key(&sha256_hex(&format!("asset:{}", name)))
        {
            let asset = Asset::new(name, classify_target(name));
            self.assets.insert(asset.stable_id.clone(), asset);
        }
    }

    fn ensure_service(&mut self, asset_id: &str, port: u16, protocol: &str, name: &str) {
        let key = service_id(asset_id, port, protocol);
        self.services
            .entry(key)
            .or_insert_with(|| new_service(asset_id, port, protocol, name));
    }
}

fn import_netmalper(artifact: &Artifact, ctx: &mut BuildContext) -> Result<()> {
    let value: Value = serde_json::from_str(&artifact.content)?;
    let object = value
        .as_object()
        .ok_or_else(|| AppError::Message("netmalper graph: not an object".to_string()))?;
    let meta = object
        .get("meta")
        .and_then(Value::as_object)
        .ok_or_else(|| AppError::Message("netmalper graph: missing meta".to_string()))?;
    let target = meta
        .get("target")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Message("netmalper graph: missing target".to_string()))?
        .to_string();

    let nodes = object
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::Message("netmalper graph: missing nodes".to_string()))?;

    // Primary asset from the root node / target.
    let mut root = Asset::new(&target, classify_target(&target));
    if let Some(fqdn) = meta.get("fqdn").and_then(Value::as_str) {
        root.fqdn = Some(fqdn.to_string());
    }
    let root_id = root.stable_id.clone();
    ctx.assets.insert(root.stable_id.clone(), root);

    // Pass 1: ip + port nodes.
    for node in nodes {
        let data = node.get("data").cloned().unwrap_or_else(|| json!({}));
        match node.get("type").and_then(Value::as_str).unwrap_or_default() {
            "ip" => {
                if let Some(ip) = data.get("ip").and_then(Value::as_str) {
                    if ip != target {
                        ctx.ensure_asset(ip);
                        let asset_id = sha256_hex(&format!("asset:{}", ip));
                        if let Some(asset) = ctx.assets.get_mut(&asset_id) {
                            if let Some(reverse_dns) =
                                data.get("reverse_dns").and_then(Value::as_str)
                            {
                                if reverse_dns != ip {
                                    asset.reverse_dns = Some(reverse_dns.to_string());
                                }
                            }
                        }
                    } else if let Some(asset) = ctx.assets.get_mut(&root_id) {
                        asset.ip = Some(ip.to_string());
                        if let Some(reverse_dns) = data.get("reverse_dns").and_then(Value::as_str) {
                            if reverse_dns != ip {
                                asset.reverse_dns = Some(reverse_dns.to_string());
                            }
                        }
                    }
                }
            }
            "port" => {
                let port = data.get("port").and_then(Value::as_u64).unwrap_or(0) as u16;
                let host = data
                    .get("host")
                    .and_then(Value::as_str)
                    .unwrap_or(&target)
                    .to_string();
                ctx.ensure_asset(&host);
                let asset_id = sha256_hex(&format!("asset:{}", host));
                let protocol = data
                    .get("protocol")
                    .and_then(Value::as_str)
                    .unwrap_or("tcp")
                    .to_string();
                let service_name = data
                    .get("service")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                ctx.ensure_service(&asset_id, port, &protocol, &service_name);
                let key = service_id(&asset_id, port, &protocol);
                if let Some(service) = ctx.services.get_mut(&key) {
                    if let Some(product) = data.get("product").and_then(Value::as_str) {
                        if !product.is_empty() {
                            service.product = Some(product.to_string());
                        }
                    }
                    if let Some(version) = data.get("version").and_then(Value::as_str) {
                        if !version.is_empty() {
                            service.version = Some(version.to_string());
                        }
                    }
                    if let Some(version_str) = data.get("version_str").and_then(Value::as_str) {
                        if !version_str.is_empty() {
                            service.version_str = Some(version_str.to_string());
                        }
                    }
                    if let Some(cpes) = data.get("cpe").and_then(Value::as_array) {
                        for cpe in cpes.iter().filter_map(Value::as_str) {
                            if !service.cpes.iter().any(|c| c == cpe) {
                                service.cpes.push(cpe.to_string());
                            }
                        }
                    }
                }
            }
            "endpoint" => {
                if let Some(url) = data.get("url").and_then(Value::as_str) {
                    let host = normalize_target(url);
                    ctx.ensure_asset(&host);
                    let asset_id = sha256_hex(&format!("asset:{}", host));
                    if let Some(asset) = ctx.assets.get_mut(&asset_id) {
                        push_endpoint(&mut asset.metadata, url);
                    }
                    // Associate with the service on the same port, if any.
                    if let Some(port) = port_from_host_url(url, data.get("port")) {
                        let protocol = "tcp";
                        ctx.ensure_service(&asset_id, port, protocol, "http");
                        let key = service_id(&asset_id, port, protocol);
                        if let Some(service) = ctx.services.get_mut(&key) {
                            push_endpoint(&mut service.metadata, url);
                            if let Some(status) = data.get("status").and_then(Value::as_u64) {
                                service.metadata["http_status"] = json!(status);
                            }
                        }
                    }
                }
            }
            "nse_finding" => {
                let script_id = data
                    .get("script_id")
                    .and_then(Value::as_str)
                    .unwrap_or("nse");
                let host = data
                    .get("host")
                    .and_then(Value::as_str)
                    .unwrap_or(&target)
                    .to_string();
                ctx.ensure_asset(&host);
                let asset_id = sha256_hex(&format!("asset:{}", host));
                let port = data.get("port").and_then(Value::as_u64).unwrap_or(0) as u16;
                let output = data
                    .get("output")
                    .and_then(Value::as_str)
                    .unwrap_or_default();

                let mut finding =
                    Finding::new(&asset_id, &format!("nmap/{}", script_id), script_id);
                finding.severity = "info".to_string();
                if !output.is_empty() {
                    let (detail, detail_path) = content::store_or_excerpt(output)?;
                    finding.detail = Some(detail);
                    finding.detail_path = detail_path;
                }
                let protocol = "tcp";
                ctx.ensure_service(&asset_id, port, protocol, "unknown");
                let service_key = service_id(&asset_id, port, protocol);
                finding.service_id = Some(service_key.clone());
                if let Some(service) = ctx.services.get_mut(&service_key) {
                    if service.banner.is_none() && !output.is_empty() {
                        service.banner = Some(truncate(output, 2048));
                    }
                }
                ctx.findings.insert(finding.stable_id.clone(), finding);
            }
            _ => {}
        }
    }

    Ok(())
}

fn import_vulnmalper_json(artifact: &Artifact, ctx: &mut BuildContext) -> Result<()> {
    let value: Value = serde_json::from_str(&artifact.content)?;
    let object = value
        .as_object()
        .ok_or_else(|| AppError::Message("vulnmalper json: not an object".to_string()))?;
    let hosts = object
        .get("hosts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    for host in hosts {
        let host_obj = match host.as_object() {
            Some(h) => h,
            None => continue,
        };
        let hostname = host_obj
            .get("host")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                host_obj
                    .get("url")
                    .and_then(Value::as_str)
                    .map(normalize_target)
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_default();
        if hostname.is_empty() {
            continue;
        }

        ctx.ensure_asset(&hostname);
        let asset_id = sha256_hex(&format!("asset:{}", hostname));

        let port = host_obj.get("port").and_then(Value::as_u64).unwrap_or(0) as u16;
        let scheme = host_obj
            .get("scheme")
            .and_then(Value::as_str)
            .unwrap_or("http");
        let service_name = host_obj
            .get("service")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(scheme)
            .to_string();
        let url = host_obj
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        // Enrich the matching service.
        ctx.ensure_service(&asset_id, port, "tcp", &service_name);
        let service_key = service_id(&asset_id, port, "tcp");
        if let Some(service) = ctx.services.get_mut(&service_key) {
            if service.service_name == "unknown" || service.service_name.is_empty() {
                service.service_name = service_name.clone();
            }
            if let Some(product) = host_obj.get("product").and_then(Value::as_str) {
                if !product.is_empty() {
                    service.product = Some(product.to_string());
                }
            }
            if let Some(tech) = host_obj.get("tech").and_then(Value::as_array) {
                for t in tech.iter().filter_map(Value::as_str) {
                    if !service.technologies.iter().any(|x| x == t) {
                        service.technologies.push(t.to_string());
                    }
                }
            }
            if let Some(alive) = host_obj.get("alive").and_then(Value::as_bool) {
                service.metadata["alive"] = json!(alive);
            }
            if let Some(status) = host_obj.get("status").and_then(Value::as_u64) {
                service.metadata["http_status"] = json!(status);
            }
            if host_obj.get("waf").is_some() {
                service.metadata["waf"] = host_obj["waf"].clone();
            }
            if let Some(injectable) = host_obj.get("injectable").and_then(Value::as_array) {
                service.metadata["injectable"] = json!(injectable);
            }
            if let Some(ep) = host_obj.get("crawl_new_endpoints").and_then(Value::as_u64) {
                service.metadata["crawl_new_endpoints"] = json!(ep);
            }
            if !url.is_empty() {
                push_endpoint(&mut service.metadata, &url);
            }
        }

        // Findings.
        let findings = host_obj
            .get("findings")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for finding_value in findings {
            let fobj = match finding_value.as_object() {
                Some(f) => f,
                None => continue,
            };
            let tool = fobj
                .get("tool")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let title = fobj
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or("unnamed finding");
            let mut finding = Finding::new(&asset_id, tool, title);
            finding.severity = fobj
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or("info")
                .to_lowercase();
            finding.exploitability =
                Some(exploitability_from_severity(&finding.severity).to_string());
            finding.target_url = fobj
                .get("target")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    if url.is_empty() {
                        None
                    } else {
                        Some(url.clone())
                    }
                });
            finding.detail = fobj
                .get("detail")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(content::store_or_excerpt)
                .transpose()?
                .map(|(detail, detail_path)| {
                    finding.detail_path = detail_path;
                    detail
                });
            finding.reference = fobj
                .get("reference")
                .and_then(Value::as_str)
                .map(str::to_string)
                .filter(|s| !s.is_empty());
            finding.service_id = Some(service_key.clone());
            if !url.is_empty() {
                finding.endpoints.push(url.clone());
            }
            ctx.findings.insert(finding.stable_id.clone(), finding);
        }
    }

    Ok(())
}

fn import_vulnmalper_markdown(artifact: &Artifact, ctx: &mut BuildContext) -> Result<()> {
    // Always store the report content as a file.
    store_report(ctx, artifact)?;

    // If a VulnMalper JSON export is present, use it as the structured source.
    if ctx.has_vulnmalper_json {
        return Ok(());
    }

    let target = md_kv(&artifact.content, "**Target:**").unwrap_or_default();
    if target.is_empty() {
        return Ok(());
    }
    ctx.ensure_asset(&target);
    let asset_id = sha256_hex(&format!("asset:{}", target));

    let mut current_url = String::new();
    let mut in_summary = false;
    for line in artifact.content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("### 🌐 `") {
            current_url = rest.trim_end_matches('`').trim().to_string();
            in_summary = false;
            continue;
        }
        if line.starts_with("#### Summary") {
            in_summary = true;
            continue;
        }
        if line.starts_with("#### ") || line.starts_with("<details") {
            in_summary = false;
            continue;
        }
        if !in_summary || !line.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = line.split('|').collect();
        // Skip header / separator rows.
        if cells.len() < 5 {
            continue;
        }
        if cells.iter().any(|c| {
            c.contains("Severity")
                || c.contains("Tool")
                || c.contains("Title")
                || c.contains("---")
                || c.trim() == "#"
        }) {
            continue;
        }
        let number = cells.get(1).map(|c| c.trim()).unwrap_or("");
        let severity_cell = cells.get(2).map(|c| c.trim()).unwrap_or("");
        let tool_cell = cells.get(3).map(|c| c.trim()).unwrap_or("");
        if number.is_empty() || severity_cell.is_empty() {
            continue;
        }
        let severity = severity_cell
            .split("**")
            .nth(1)
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "info".to_string());
        let tool = tool_cell.split('`').nth(1).unwrap_or("unknown").to_string();
        let title = cells[4..].join("|").trim().to_string();
        if title.is_empty() {
            continue;
        }

        let mut finding = Finding::new(&asset_id, &tool, &title);
        finding.severity = severity.clone();
        finding.exploitability = Some(exploitability_from_severity(&severity).to_string());
        if !current_url.is_empty() {
            finding.target_url = Some(current_url.clone());
            finding.endpoints.push(current_url.clone());
        }
        ctx.findings.insert(finding.stable_id.clone(), finding);
    }

    Ok(())
}

fn import_ploitmalper_report(artifact: &Artifact, ctx: &mut BuildContext) -> Result<()> {
    // Store the full report content as a file.
    store_report(ctx, artifact)?;

    let target = artifact
        .content
        .lines()
        .find(|l| l.contains("**Host:**"))
        .and_then(|l| l.split("**Host:**").nth(1))
        .and_then(extract_backtick_or_trim)
        .unwrap_or_default();
    if target.is_empty() {
        return Ok(());
    }

    ctx.ensure_asset(&target);
    let asset_id = sha256_hex(&format!("asset:{}", target));
    if let Some(asset) = ctx.assets.get_mut(&asset_id) {
        let risk_score = artifact
            .content
            .lines()
            .find(|l| l.starts_with("## Overall Risk"))
            .and_then(|l| l.split_terminator(':').nth(1))
            .and_then(|r| r.trim().split('/').next())
            .and_then(|v| v.trim().parse::<u64>().ok());
        let enrichment = match asset.metadata.get_mut("ploitmalper") {
            Some(Value::Object(map)) => map,
            _ => {
                asset.metadata["ploitmalper"] = json!({});
                asset.metadata["ploitmalper"].as_object_mut().unwrap()
            }
        };
        if let Some(score) = risk_score {
            enrichment.insert("risk_score".to_string(), json!(score));
            enrichment.insert(
                "risk_label".to_string(),
                json!(risk_label_from_score(score)),
            );
        }
    }

    // Surface every injectable endpoint the report flags (e.g. SQLi) as a
    // finding so it lands in the intelligence database.
    for finding in injectable_findings(&artifact.content, &asset_id) {
        ctx.findings.insert(finding.stable_id.clone(), finding);
    }

    Ok(())
}

/// Extract the injectable endpoints table from a PloitMalper report and turn
/// each flagged URL into a high-severity finding.
fn injectable_findings(content: &str, asset_id: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut in_section = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("## 4. Injectable Endpoints") {
            in_section = true;
            continue;
        }
        if in_section && trimmed.starts_with("## ") {
            break;
        }
        if !in_section || !trimmed.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = trimmed.split('|').collect();
        let endpoint_cell = match cells.get(2) {
            Some(cell) => cell.trim(),
            None => continue,
        };
        let endpoint = endpoint_cell.trim_matches('`').trim();
        if endpoint.is_empty()
            || endpoint == "Endpoint"
            || endpoint.starts_with('-')
            || !endpoint.starts_with("http")
        {
            continue;
        }
        let endpoint = endpoint.to_string();
        let mut finding = Finding::new(
            asset_id,
            "ploitmalper",
            &format!("Injectable endpoint: {}", endpoint),
        );
        finding.severity = "high".to_string();
        finding.exploitability = Some("likely".to_string());
        finding.target_url = Some(endpoint.clone());
        finding.endpoints.push(endpoint);
        findings.push(finding);
    }
    findings
}

// ---------------------------------------------------------------------------
// Committing with history-aware diffs
// ---------------------------------------------------------------------------

struct ObsSpec {
    kind: &'static str,
    before: Value,
    after: Value,
    detail: String,
}

fn commit_assets(
    storage: &mut Box<dyn Storage>,
    run_id: &str,
    new: &mut HashMap<String, Asset>,
    prev: &HashMap<String, Asset>,
) -> Result<Vec<Observation>> {
    let mut observations = Vec::new();
    for (id, asset) in new.iter_mut() {
        match prev.get(id) {
            Some(old) => {
                asset.first_seen = old.first_seen.clone();
                asset.last_seen = now_utc();
                for spec in diff_asset(old, asset) {
                    observations.push(Observation::new(
                        run_id,
                        "asset",
                        id,
                        spec.kind,
                        spec.before,
                        spec.after,
                        &spec.detail,
                    ));
                }
                storage.upsert_asset(asset)?;
            }
            None => {
                observations.push(Observation::new(
                    run_id,
                    "asset",
                    id,
                    "asset_discovered",
                    Value::Null,
                    json!(asset),
                    "asset discovered in this run",
                ));
                storage.upsert_asset(asset)?;
            }
        }
    }
    for (id, old) in prev {
        if !new.contains_key(id) {
            let mut removed = old.clone();
            removed.status = ASSET_REMOVED.to_string();
            storage.upsert_asset(&removed)?;
            observations.push(Observation::new(
                run_id,
                "asset",
                id,
                "asset_removed",
                json!(old),
                Value::Null,
                "asset no longer present in this run",
            ));
        }
    }
    Ok(observations)
}

fn commit_services(
    storage: &mut Box<dyn Storage>,
    run_id: &str,
    new: &mut HashMap<String, Service>,
    prev: &HashMap<String, Service>,
) -> Result<Vec<Observation>> {
    let mut observations = Vec::new();
    for (id, service) in new.iter_mut() {
        match prev.get(id) {
            Some(old) => {
                service.first_seen = old.first_seen.clone();
                service.last_seen = now_utc();
                for spec in diff_service(old, service) {
                    observations.push(Observation::new(
                        run_id,
                        "service",
                        id,
                        spec.kind,
                        spec.before,
                        spec.after,
                        &spec.detail,
                    ));
                }
                storage.upsert_service(service)?;
            }
            None => {
                observations.push(Observation::new(
                    run_id,
                    "service",
                    id,
                    "service_discovered",
                    Value::Null,
                    json!(service),
                    "service discovered in this run",
                ));
                storage.upsert_service(service)?;
            }
        }
    }
    for (id, old) in prev {
        if !new.contains_key(id) {
            let mut removed = old.clone();
            removed.status = ASSET_REMOVED.to_string();
            storage.upsert_service(&removed)?;
            observations.push(Observation::new(
                run_id,
                "service",
                id,
                "service_removed",
                json!(old),
                Value::Null,
                "service no longer present in this run",
            ));
        }
    }
    Ok(observations)
}

fn commit_findings(
    storage: &mut Box<dyn Storage>,
    run_id: &str,
    new: &mut HashMap<String, Finding>,
    prev: &HashMap<String, Finding>,
) -> Result<Vec<Observation>> {
    let mut observations = Vec::new();
    for (id, finding) in new.iter_mut() {
        match prev.get(id) {
            Some(old) => {
                finding.first_seen = old.first_seen.clone();
                finding.last_seen = now_utc();
                for spec in diff_finding(old, finding) {
                    observations.push(Observation::new(
                        run_id,
                        "finding",
                        id,
                        spec.kind,
                        spec.before,
                        spec.after,
                        &spec.detail,
                    ));
                }
                storage.upsert_finding(finding)?;
            }
            None => {
                observations.push(Observation::new(
                    run_id,
                    "finding",
                    id,
                    "finding_discovered",
                    Value::Null,
                    json!(finding),
                    "finding discovered in this run",
                ));
                storage.upsert_finding(finding)?;
            }
        }
    }
    for (id, old) in prev {
        if !new.contains_key(id) {
            let mut removed = old.clone();
            removed.status = ASSET_REMOVED.to_string();
            storage.upsert_finding(&removed)?;
            observations.push(Observation::new(
                run_id,
                "finding",
                id,
                "finding_removed",
                json!(old),
                Value::Null,
                "finding no longer present in this run",
            ));
        }
    }
    Ok(observations)
}

fn diff_asset(old: &Asset, new: &Asset) -> Vec<ObsSpec> {
    let mut out = Vec::new();
    if old.status != new.status {
        out.push(ObsSpec {
            kind: "asset_changed",
            before: json!(old.status),
            after: json!(new.status),
            detail: format!("status {} -> {}", old.status, new.status),
        });
    }
    if old.ip != new.ip {
        out.push(ObsSpec {
            kind: "asset_changed",
            before: json!(old.ip),
            after: json!(new.ip),
            detail: format!("ip {:?} -> {:?}", old.ip, new.ip),
        });
    }
    if old.fqdn != new.fqdn {
        out.push(ObsSpec {
            kind: "asset_changed",
            before: json!(old.fqdn),
            after: json!(new.fqdn),
            detail: format!("fqdn {:?} -> {:?}", old.fqdn, new.fqdn),
        });
    }
    if old.reverse_dns != new.reverse_dns {
        out.push(ObsSpec {
            kind: "asset_changed",
            before: json!(old.reverse_dns),
            after: json!(new.reverse_dns),
            detail: format!("reverse_dns {:?} -> {:?}", old.reverse_dns, new.reverse_dns),
        });
    }
    out
}

fn diff_service(old: &Service, new: &Service) -> Vec<ObsSpec> {
    let mut out = Vec::new();
    if old.status != new.status {
        out.push(ObsSpec {
            kind: "service_changed",
            before: json!(old.status),
            after: json!(new.status),
            detail: format!("status {} -> {}", old.status, new.status),
        });
    }
    if old.product != new.product
        || old.version != new.version
        || old.version_str != new.version_str
        || old.banner != new.banner
        || old.service_name != new.service_name
    {
        out.push(ObsSpec {
            kind: "service_changed",
            before: json!({
                "service_name": old.service_name,
                "product": old.product,
                "version": old.version,
                "version_str": old.version_str,
                "banner": old.banner,
            }),
            after: json!({
                "service_name": new.service_name,
                "product": new.product,
                "version": new.version,
                "version_str": new.version_str,
                "banner": new.banner,
            }),
            detail: format!("service {} (port {}) changed", new.service_name, new.port),
        });
    }
    let old_tech: HashSet<&String> = old.technologies.iter().collect();
    let new_tech: HashSet<&String> = new.technologies.iter().collect();
    if old_tech != new_tech {
        out.push(ObsSpec {
            kind: "technology_changed",
            before: json!(old.technologies),
            after: json!(new.technologies),
            detail: format!(
                "technologies changed on service {}:{}",
                new.asset_id, new.port
            ),
        });
    }
    out
}

fn diff_finding(old: &Finding, new: &Finding) -> Vec<ObsSpec> {
    let mut out = Vec::new();
    if old.status != new.status {
        out.push(ObsSpec {
            kind: "finding_changed",
            before: json!(old.status),
            after: json!(new.status),
            detail: format!("status {} -> {}", old.status, new.status),
        });
    }
    if old.severity != new.severity {
        out.push(ObsSpec {
            kind: "severity_changed",
            before: json!(old.severity),
            after: json!(new.severity),
            detail: format!(
                "severity {} -> {} for '{}'",
                old.severity, new.severity, new.title
            ),
        });
    }
    if old.exploitability != new.exploitability {
        out.push(ObsSpec {
            kind: "exploitability_changed",
            before: json!(old.exploitability),
            after: json!(new.exploitability),
            detail: format!(
                "exploitability {:?} -> {:?} for '{}'",
                old.exploitability, new.exploitability, new.title
            ),
        });
    }
    if old.title != new.title
        || old.detail != new.detail
        || old.detail_path != new.detail_path
        || old.reference != new.reference
        || old.target_url != new.target_url
    {
        out.push(ObsSpec {
            kind: "finding_changed",
            before: json!({
                "title": old.title,
                "detail": old.detail,
                "detail_path": old.detail_path,
                "reference": old.reference,
                "target_url": old.target_url,
            }),
            after: json!({
                "title": new.title,
                "detail": new.detail,
                "detail_path": new.detail_path,
                "reference": new.reference,
                "target_url": new.target_url,
            }),
            detail: format!("finding '{}' changed", new.title),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn exploitability_from_severity(severity: &str) -> &'static str {
    match severity {
        "critical" | "high" => "likely",
        "medium" => "possible",
        "low" => "unlikely",
        _ => "none",
    }
}

fn risk_label_from_score(score: u64) -> &'static str {
    match score {
        0..=29 => "LOW RISK",
        30..=69 => "MEDIUM RISK",
        70..=89 => "HIGH RISK",
        _ => "CRITICAL RISK",
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut out: String = value.chars().take(max_chars).collect();
    out.push('…');
    out
}

fn port_from_host_url(url: &str, fallback: Option<&Value>) -> Option<u16> {
    if let Some(v) = fallback.and_then(Value::as_u64) {
        if v > 0 && v <= 65535 {
            return Some(v as u16);
        }
    }
    let host_part = url.split("://").nth(1)?;
    let host_port = host_part.split('/').next()?;
    if let Some(colon) = host_port.rfind(':') {
        if let Some(port_str) = host_port.get(colon + 1..) {
            if let Ok(port) = port_str.parse::<u16>() {
                if port > 0 {
                    return Some(port);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn target_compatibility() {
        assert!(target_compatible("192.168.1.14", "192.168.1.14", ""));
        assert!(target_compatible(
            "http://192.168.1.14:8080/",
            "192.168.1.14",
            ""
        ));
        assert!(target_compatible(
            "example.com",
            "https://www.example.com",
            ""
        ));
        assert!(!target_compatible("10.0.0.1", "192.168.1.14", ""));
        // IPs must not match via substring (192.168.1.1 vs 192.168.1.14).
        assert!(!target_compatible("192.168.1.14", "192.168.1.1", ""));
        // Folder hint anchors subdomain runs.
        assert!(target_compatible(
            "192.168.1.14",
            "192.168.1.14",
            "ingest-test"
        ));
        assert!(target_compatible(
            "example.com",
            "api.example.com",
            "example.com"
        ));
    }

    #[test]
    fn rfc3339_variants() {
        assert!(rfc3339("2026-08-01T07:39:22Z").is_some());
        assert!(rfc3339("2026-08-01 15:05:04 UTC").is_some());
        assert!(rfc3339("1785665136").is_some());
        assert!(rfc3339("garbage").is_none());
    }

    #[test]
    fn md_kv_extraction() {
        let content = "> **Target:** `192.168.1.14` | **Generated:** 2026-08-01 15:05:04 UTC | **Engine:** VulnMalper v8.0.0";
        assert_eq!(
            md_kv(content, "**Target:**").as_deref(),
            Some("192.168.1.14")
        );
        assert_eq!(
            md_kv(content, "**Generated:**").as_deref(),
            Some("2026-08-01 15:05:04 UTC")
        );
    }

    #[test]
    fn service_id_stable() {
        let asset_id = "a";
        assert_eq!(
            service_id(asset_id, 80, "tcp"),
            service_id(asset_id, 80, "tcp")
        );
        assert_ne!(
            service_id(asset_id, 80, "tcp"),
            service_id(asset_id, 81, "tcp")
        );
    }

    #[test]
    fn port_from_host_url_parses() {
        assert_eq!(
            port_from_host_url("http://192.168.1.14:8080/", None),
            Some(8080)
        );
        assert_eq!(port_from_host_url("https://example.com/path", None), None);
        let port_value = json!(22);
        assert_eq!(port_from_host_url("x", Some(&port_value)), Some(22));
    }

    #[test]
    fn severity_exploitability_map() {
        assert_eq!(exploitability_from_severity("critical"), "likely");
        assert_eq!(exploitability_from_severity("info"), "none");
    }

    #[test]
    fn injectable_findings_extracted_from_report() {
        let report = "# PloitMalper - Vulnerability Analysis Report\n\
            \n\
            **Generated:** 123\n\
            **Tool Version:** 0.2.1\n\
            \n\
            ## 1. Executive Summary\n\
            - **Host:** http://192.168.1.2/\n\
            \n\
            ## 4. Injectable Endpoints\n\
            \n\
            1 potential injection point(s) reported:\n\
            \n\
            | # | Endpoint | Affected Host |\n\
            |---|----------|---------------|\n\
            | 1 | `http://192.168.1.2?name=1` | http://192.168.1.2/ |\n\
            \n\
            ## 5. CVE Intelligence\n";
        let findings = injectable_findings(report, "asset-1");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].asset_id, "asset-1");
        assert_eq!(findings[0].tool, "ploitmalper");
        assert_eq!(findings[0].severity, "high");
        assert_eq!(findings[0].exploitability.as_deref(), Some("likely"));
        assert_eq!(
            findings[0].title,
            "Injectable endpoint: http://192.168.1.2?name=1"
        );
        assert_eq!(findings[0].endpoints, vec!["http://192.168.1.2?name=1"]);
        assert_eq!(
            findings[0].target_url.as_deref(),
            Some("http://192.168.1.2?name=1")
        );
    }

    #[test]
    fn injectable_findings_skips_header_and_absent_section() {
        let no_injectable = "# PloitMalper - Vulnerability Analysis Report\n\
            \n\
            ## 4. Injectable Endpoints\n\
            \n\
            No injectable endpoints flagged by the scanner.\n\
            \n\
            ## 5. CVE Intelligence\n";
        assert!(injectable_findings(no_injectable, "asset-1").is_empty());

        let no_section = "# PloitMalper - Vulnerability Analysis Report\n\
            ## 1. Executive Summary\n";
        assert!(injectable_findings(no_section, "asset-1").is_empty());
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("ploitmalper_tests").join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn ingest_process_pipeline_imports_injectable_findings() {
        let dir = temp_dir("ingest_process");
        let target = "192.168.1.2";
        let finding = serde_json::json!({
            "tool": "nikto",
            "severity": "low",
            "title": "Missing security header",
            "target": format!("http://{}/", target),
            "detail": "Suggested security header missing.",
            "reference": ""
        });
        let json = serde_json::json!({
            "vulnmalper": { "version": "8.0.0", "source_target": target },
            "findings": [finding],
            "hosts": [{
                "host": target,
                "url": format!("http://{}/", target),
                "port": 80,
                "scheme": "http",
                "findings": [finding],
                "injectable": [format!("http://{}?name=1", target)]
            }]
        });
        let json_path = dir.join(format!("vulnmalper_{}.json", target));
        std::fs::write(&json_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

        let mut config_mgr = crate::config::ConfigManager::new();
        let processed = crate::process::process_folder(&dir, &mut config_mgr, false).unwrap();
        assert_eq!(processed, 1);

        let report_path = dir.join(format!("vulnmalper_{}_ploitmalper.md", target));
        let report = std::fs::read_to_string(&report_path).unwrap();
        assert!(report.contains("# PloitMalper - Vulnerability Analysis Report"));
        assert!(report.contains("http://192.168.1.2?name=1"));

        let db_path = dir.join("test.db");
        let db_cfg = crate::config::DatabaseConfig {
            backend: "sqlite".to_string(),
            sqlite_path: db_path.to_string_lossy().to_string(),
            configured: true,
            ..Default::default()
        };
        let opts = IngestOptions {
            verbose: false,
            dry_run: false,
            force: false,
            process: false,
            backend: "auto".to_string(),
            pocketbase_url: None,
            sqlite_path: None,
        };
        let summary = ingest_folder(&dir, &db_cfg, &opts).unwrap();
        assert!(summary.artifacts_accepted >= 2);

        let mut storage = crate::db::open_storage_with(&db_cfg, "sqlite", None, None).unwrap();
        let findings = storage.list_all_findings().unwrap();
        let titles: Vec<String> = findings.iter().map(|f| f.title.clone()).collect();
        assert!(
            titles
                .iter()
                .any(|t| t.contains("Injectable endpoint: http://192.168.1.2?name=1")),
            "injectable finding missing from db: {:?}",
            titles
        );
        assert!(titles.iter().any(|t| t.contains("Missing security header")));

        let _ = PathBuf::from(&db_path);
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
