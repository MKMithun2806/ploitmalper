pub mod assets;
pub mod diff;
pub mod findings;
pub mod history;
pub mod runs;
pub mod services;
pub mod tui;

use std::collections::{HashMap, HashSet};
use std::io::{self, IsTerminal};

use serde_json::Value;
use time::OffsetDateTime;

use crate::config::ConfigManager;
use crate::db::models::{Asset, Finding, Observation, Service};
use crate::db::Storage;
use crate::error::{AppError, Result};

// ---------------------------------------------------------------------------
// Command-line argument parsing
// ---------------------------------------------------------------------------

const BOOLEAN_FLAGS: &[&str] = &[
    "verbose", "json", "new", "changed", "fixed", "help", "dry-run", "yes", "tui",
];
const VALUE_FLAGS: &[&str] = &[
    "target",
    "since",
    "port",
    "product",
    "asset",
    "severity",
    "cve",
    "backend",
    "pocketbase-url",
    "sqlite-path",
    "module",
    "payload",
    "workspace",
    "job-timeout",
];

/// Minimal, consistent flag parser shared by all frontend commands.
#[derive(Debug, Default, Clone)]
pub struct Args {
    flags: HashSet<String>,
    values: HashMap<String, String>,
    positionals: Vec<String>,
}

impl Args {
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut flags = HashSet::new();
        let mut values = HashMap::new();
        let mut positionals = Vec::new();

        let mut i = 0usize;
        while i < args.len() {
            let arg = &args[i];
            if let Some(rest) = arg.strip_prefix("--") {
                if let Some((key, value)) = rest.split_once('=') {
                    if VALUE_FLAGS.contains(&key) {
                        values.insert(key.to_string(), value.to_string());
                        i += 1;
                        continue;
                    }
                    return Err(AppError::Message(format!(
                        "unknown option: --{} (use --{} VALUE)",
                        key, key
                    )));
                }
                if VALUE_FLAGS.contains(&rest) {
                    let value = args.get(i + 1).ok_or_else(|| {
                        AppError::Message(format!("option --{} requires a value", rest))
                    })?;
                    values.insert(rest.to_string(), value.clone());
                    i += 2;
                    continue;
                }
                if BOOLEAN_FLAGS.contains(&rest) {
                    flags.insert(rest.to_string());
                    i += 1;
                    continue;
                }
                return Err(AppError::Message(format!("unknown option: --{}", rest)));
            } else if arg.starts_with('-') && arg.len() > 1 {
                let short = &arg[1..];
                match short {
                    "v" => {
                        flags.insert("verbose".to_string());
                    }
                    "h" => {
                        flags.insert("help".to_string());
                    }
                    _ => {
                        return Err(AppError::Message(format!("unknown option: -{}", short)));
                    }
                }
                i += 1;
                continue;
            }
            positionals.push(arg.clone());
            i += 1;
        }

        Ok(Self {
            flags,
            values,
            positionals,
        })
    }

    pub fn has(&self, name: &str) -> bool {
        self.flags.contains(name)
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(|s| s.as_str())
    }

    pub fn positionals(&self) -> &[String] {
        &self.positionals
    }
}

// ---------------------------------------------------------------------------
// Colour helpers (terminal friendly, honour NO_COLOR / non-tty output)
// ---------------------------------------------------------------------------

pub fn color_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    io::stdout().is_terminal()
}

fn paint(text: &str, code: &str) -> String {
    if color_enabled() {
        format!("\x1b[{}m{}\x1b[0m", code, text)
    } else {
        text.to_string()
    }
}

pub fn red(text: &str) -> String {
    paint(text, "31")
}

pub fn green(text: &str) -> String {
    paint(text, "32")
}

pub fn yellow(text: &str) -> String {
    paint(text, "33")
}

pub fn cyan(text: &str) -> String {
    paint(text, "36")
}

pub fn dim(text: &str) -> String {
    paint(text, "2")
}

pub fn bold(text: &str) -> String {
    paint(text, "1")
}

pub fn severity_style(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" => "1;31",
        "high" => "31",
        "medium" => "33",
        "low" => "34",
        "info" | "none" => "2",
        _ => "0",
    }
}

pub fn severity_label(severity: &str) -> String {
    severity.to_uppercase()
}

/// Rank used to sort severities from most to least severe.
pub fn severity_rank(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        "none" => 5,
        _ => 9,
    }
}

// ---------------------------------------------------------------------------
// Table rendering
// ---------------------------------------------------------------------------

pub struct Cell {
    pub text: String,
    pub style: Option<&'static str>,
}

impl Cell {
    pub fn plain(text: String) -> Self {
        Self { text, style: None }
    }

    pub fn styled(text: String, style: &'static str) -> Self {
        Self {
            text,
            style: Some(style),
        }
    }
}

pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<Cell>>,
    max_width: usize,
}

impl Table {
    pub fn new(headers: Vec<String>) -> Self {
        Self {
            headers,
            rows: Vec::new(),
            max_width: 60,
        }
    }

    pub fn add_row(&mut self, cells: Vec<Cell>) {
        self.rows.push(cells);
    }

    pub fn render(&self) -> String {
        let mut widths: Vec<usize> = self.headers.iter().map(|h| h.chars().count()).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if i < widths.len() {
                    widths[i] = widths[i].max(cell.text.chars().count());
                }
            }
        }
        for w in widths.iter_mut() {
            *w = (*w).min(self.max_width);
        }

        let mut out = String::new();
        let header_cells: Vec<String> = self
            .headers
            .iter()
            .enumerate()
            .map(|(i, h)| pad(&truncate(h, widths[i]), widths[i]))
            .collect();
        out.push_str(&header_cells.join("  "));
        out.push('\n');

        out.push_str(
            &widths
                .iter()
                .map(|w| "-".repeat(*w))
                .collect::<Vec<_>>()
                .join("  "),
        );
        out.push('\n');

        for row in &self.rows {
            let mut line = String::new();
            for (i, cell) in row.iter().enumerate() {
                if i > 0 {
                    line.push_str("  ");
                }
                let width = widths.get(i).copied().unwrap_or(self.max_width);
                let padded = pad(&truncate(&cell.text, width), width);
                line.push_str(&match cell.style {
                    Some(code) => paint(&padded, code),
                    None => padded,
                });
            }
            out.push_str(&line);
            out.push('\n');
        }
        out
    }
}

fn pad(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        return text.to_string();
    }
    let mut out = text.to_string();
    out.extend(std::iter::repeat_n(' ', width - len));
    out
}

pub fn truncate(value: &str, width: usize) -> String {
    let count = value.chars().count();
    if count <= width {
        return value.to_string();
    }
    if width <= 1 {
        return "…".to_string();
    }
    let mut out: String = value.chars().take(width - 1).collect();
    out.push('…');
    out
}

// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

fn parse_date_only(s: &str) -> Option<OffsetDateTime> {
    let mut parts = s.split('-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month: u8 = parts.next()?.parse().ok()?;
    let day: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let date =
        time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()?;
    Some(date.midnight().assume_utc())
}

/// Matches `YYYY-MM-DD HH:MM:SS(.fff)? (Z|+HH:MM(:SS)?|...)` in both the
/// standard RFC3339 shape and the space-separated `OffsetDateTime::to_string()`
/// shape produced by the importer.
fn parse_flexible(s: &str) -> Option<OffsetDateTime> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(
            r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?(?:\s*(Z|[+-]\d{2}:\d{2}(?::\d{2})?))?$",
        )
        .expect("valid timestamp regex")
    });

    let caps = re.captures(s.trim())?;
    let year: i32 = caps.get(1)?.as_str().parse().ok()?;
    let month: u8 = caps.get(2)?.as_str().parse().ok()?;
    let day: u8 = caps.get(3)?.as_str().parse().ok()?;
    let hour: u8 = caps.get(4)?.as_str().parse().ok()?;
    let minute: u8 = caps.get(5)?.as_str().parse().ok()?;
    let second: u8 = caps
        .get(6)
        .map(|m| m.as_str().parse().ok())
        .unwrap_or(Some(0))?;

    let date =
        time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()?;
    let time = time::Time::from_hms(hour, minute, second).ok()?;

    match caps.get(7).map(|m| m.as_str()) {
        None | Some("Z") => Some(date.with_time(time).assume_utc()),
        Some(offset) => {
            let sign: i8 = if offset.starts_with('-') { -1 } else { 1 };
            let digits = offset.trim_start_matches(['+', '-']);
            let mut parts = digits.split(':');
            let oh: i8 = parts.next()?.parse().ok()?;
            let om: i8 = parts.next()?.parse().ok()?;
            let utc_offset = time::UtcOffset::from_hms(sign * oh, sign * om, 0).ok()?;
            Some(date.with_time(time).assume_offset(utc_offset))
        }
    }
}

/// Parse RFC3339, the importer's space-separated timestamp shape, `YYYY-MM-DD
/// HH:MM:SS UTC`, `YYYY-MM-DD`, or a unix epoch.
pub fn parse_ts(value: &str) -> Option<OffsetDateTime> {
    let trimmed = value.trim();
    if let Ok(dt) = OffsetDateTime::parse(trimmed, &time::format_description::well_known::Rfc3339) {
        return Some(dt);
    }
    let normalised = trimmed.replace(" UTC", "Z").replace(' ', "T");
    if let Ok(dt) =
        OffsetDateTime::parse(&normalised, &time::format_description::well_known::Rfc3339)
    {
        return Some(dt);
    }
    if let Some(dt) = parse_flexible(trimmed) {
        return Some(dt);
    }
    if let Some(dt) = parse_date_only(trimmed) {
        return Some(dt);
    }
    if let Ok(epoch) = trimmed.parse::<i64>() {
        if let Ok(dt) = OffsetDateTime::from_unix_timestamp(epoch) {
            return Some(dt);
        }
    }
    None
}

/// Compact `YYYY-MM-DD HH:MM` (UTC) representation for tables.
pub fn fmt_ts(value: &str) -> String {
    if value.is_empty() {
        return "-".to_string();
    }
    match parse_ts(value) {
        Some(dt) => {
            let utc = dt.to_offset(time::UtcOffset::UTC);
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}",
                utc.year(),
                u8::from(utc.month()),
                utc.day(),
                utc.hour(),
                utc.minute()
            )
        }
        None => truncate(value, 16).to_string(),
    }
}

/// True if `ts` is at or after `since`.
pub fn ts_since(ts: &str, since: OffsetDateTime) -> bool {
    match parse_ts(ts) {
        Some(dt) => dt >= since,
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Backend access
// ---------------------------------------------------------------------------

/// Open the configured backend, honouring `--backend` / `--pocketbase-url` /
/// `--sqlite-path` overrides, and fail clearly when unconfigured/unreachable.
pub fn open_backend(config_mgr: &ConfigManager, args: &Args) -> Result<Box<dyn Storage>> {
    crate::db::pocketbase::set_verbose(args.has("verbose"));
    let db = config_mgr.get_database_config().clone();
    if !db.configured {
        return Err(AppError::Message(
            "no database configured; run 'ploit-malper db_setup' first".to_string(),
        ));
    }
    let backend = args.get("backend").unwrap_or(db.backend.as_str());
    let mut storage = crate::db::open_storage_with(
        &db,
        backend,
        args.get("pocketbase-url"),
        args.get("sqlite-path"),
    )?;
    if !storage.ping()? {
        return Err(AppError::Message(format!(
            "{} backend is not reachable",
            storage.kind()
        )));
    }
    Ok(storage)
}

// ---------------------------------------------------------------------------
// Id -> name maps
// ---------------------------------------------------------------------------

/// Lookup tables so foreign keys (asset_id, service_id) can be resolved to
/// human-readable names across every frontend command.
pub struct IdMaps {
    pub assets: HashMap<String, Asset>,
    pub services: HashMap<String, Service>,
    pub findings: HashMap<String, Finding>,
}

impl IdMaps {
    pub fn load(storage: &mut Box<dyn Storage>) -> Result<Self> {
        let assets = storage
            .list_assets()?
            .into_iter()
            .map(|a| (a.stable_id.clone(), a))
            .collect();
        let services = storage
            .list_all_services()?
            .into_iter()
            .map(|s| (s.stable_id.clone(), s))
            .collect();
        let findings = storage
            .list_all_findings()?
            .into_iter()
            .map(|f| (f.stable_id.clone(), f))
            .collect();
        Ok(Self {
            assets,
            services,
            findings,
        })
    }

    pub fn asset_name(&self, id: &str) -> String {
        self.assets
            .get(id)
            .map(|a| a.name.clone())
            .unwrap_or_else(|| id.to_string())
    }

    pub fn service_label(&self, id: &str) -> String {
        match self.services.get(id) {
            Some(s) => format!(
                "{}/{}",
                s.port,
                if s.protocol.is_empty() {
                    "tcp"
                } else {
                    &s.protocol
                }
            ),
            None => id.to_string(),
        }
    }

    pub fn service_summary(&self, asset_id: &str) -> String {
        let mut services: Vec<&Service> = self
            .services
            .values()
            .filter(|s| s.asset_id == asset_id && s.status != "removed")
            .collect();
        services.sort_by_key(|s| s.port);
        if services.is_empty() {
            return "-".to_string();
        }
        format!(
            "{} open ({})",
            services.len(),
            services
                .iter()
                .map(|s| s.port.to_string())
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    pub fn finding_title(&self, id: &str) -> String {
        self.findings
            .get(id)
            .map(|f| f.title.clone())
            .unwrap_or_else(|| id.to_string())
    }
}

// ---------------------------------------------------------------------------
// Observation-derived change state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeState {
    New,
    Changed,
    Removed,
    Unchanged,
}

impl ChangeState {
    pub fn label(&self) -> &'static str {
        match self {
            ChangeState::New => "new",
            ChangeState::Changed => "changed",
            ChangeState::Removed => "removed",
            ChangeState::Unchanged => "active",
        }
    }

    pub fn paint(&self, text: &str) -> String {
        match self {
            ChangeState::New => green(text),
            ChangeState::Changed => yellow(text),
            ChangeState::Removed => red(text),
            ChangeState::Unchanged => dim(text),
        }
    }
}

pub fn classify_kind(kind: &str) -> ChangeState {
    if kind.ends_with("_discovered") {
        ChangeState::New
    } else if kind.ends_with("_removed") {
        ChangeState::Removed
    } else if kind.contains("changed") {
        ChangeState::Changed
    } else {
        ChangeState::Unchanged
    }
}

/// Index of observations by subject id for change-state lookups.
pub struct ObsIndex {
    by_subject: HashMap<String, Vec<Observation>>,
    latest_run: String,
}

impl ObsIndex {
    pub fn build(all: &[Observation]) -> Self {
        let mut by_subject: HashMap<String, Vec<Observation>> = HashMap::new();
        for obs in all {
            by_subject
                .entry(obs.subject_id.clone())
                .or_default()
                .push(obs.clone());
        }
        for values in by_subject.values_mut() {
            values.sort_by(|a, b| a.observed_at.cmp(&b.observed_at));
        }
        let latest_run = all
            .iter()
            .max_by(|a, b| a.observed_at.cmp(&b.observed_at))
            .map(|o| o.run_id.clone())
            .unwrap_or_default();
        Self {
            by_subject,
            latest_run,
        }
    }

    pub fn observations_for(&self, id: &str) -> &[Observation] {
        self.by_subject.get(id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// The change state of a record as of the most recent run. `status` is the
    /// record's stored lifecycle status (used to flag removals that predate
    /// the latest run).
    pub fn state(&self, id: &str, status: &str) -> ChangeState {
        if status == crate::db::models::ASSET_REMOVED {
            return ChangeState::Removed;
        }
        let last = self
            .observations_for(id)
            .iter()
            .rev()
            .find(|o| o.run_id == self.latest_run);
        match last {
            Some(obs) => classify_kind(&obs.kind),
            None => ChangeState::Unchanged,
        }
    }

    pub fn latest_run(&self) -> &str {
        &self.latest_run
    }
}

// ---------------------------------------------------------------------------
// Subject resolution (history)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectKind {
    Asset,
    Service,
    Finding,
}

impl SubjectKind {
    pub fn label(&self) -> &'static str {
        match self {
            SubjectKind::Asset => "asset",
            SubjectKind::Service => "service",
            SubjectKind::Finding => "finding",
        }
    }
}

pub struct ResolvedSubject {
    pub kind: SubjectKind,
    pub id: String,
    pub label: String,
}

fn list_some(items: &[String], cap: usize) -> String {
    items
        .iter()
        .take(cap)
        .map(|s| format!("  - {}", s))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Resolve a user-supplied id or name to a specific asset, service, or
/// finding. Supports stable ids, exact names/titles, `asset:port` for
/// services, and unambiguous substring matches.
pub fn resolve_subject(maps: &IdMaps, term: &str) -> Result<ResolvedSubject> {
    let lower = term.trim().to_lowercase();
    if lower.is_empty() {
        return Err(AppError::Message(
            "history requires an asset, service, or finding id/name".to_string(),
        ));
    }

    if let Some(asset) = maps.assets.get(&lower) {
        return Ok(ResolvedSubject {
            kind: SubjectKind::Asset,
            id: asset.stable_id.clone(),
            label: asset.name.clone(),
        });
    }
    if let Some(service) = maps.services.get(&lower) {
        return Ok(ResolvedSubject {
            kind: SubjectKind::Service,
            id: service.stable_id.clone(),
            label: format!("{}:{}", maps.asset_name(&service.asset_id), service.port),
        });
    }
    if let Some(finding) = maps.findings.get(&lower) {
        return Ok(ResolvedSubject {
            kind: SubjectKind::Finding,
            id: finding.stable_id.clone(),
            label: finding.title.clone(),
        });
    }

    let asset_exact: Vec<&Asset> = maps
        .assets
        .values()
        .filter(|a| {
            a.name.eq_ignore_ascii_case(&lower)
                || a.ip
                    .as_deref()
                    .is_some_and(|i| i.eq_ignore_ascii_case(&lower))
                || a.fqdn
                    .as_deref()
                    .is_some_and(|f| f.eq_ignore_ascii_case(&lower))
                || a.reverse_dns
                    .as_deref()
                    .is_some_and(|r| r.eq_ignore_ascii_case(&lower))
        })
        .collect();
    if asset_exact.len() == 1 {
        let a = asset_exact[0];
        return Ok(ResolvedSubject {
            kind: SubjectKind::Asset,
            id: a.stable_id.clone(),
            label: a.name.clone(),
        });
    }

    let finding_exact: Vec<&Finding> = maps
        .findings
        .values()
        .filter(|f| f.title.eq_ignore_ascii_case(&lower))
        .collect();
    if finding_exact.len() == 1 {
        let f = finding_exact[0];
        return Ok(ResolvedSubject {
            kind: SubjectKind::Finding,
            id: f.stable_id.clone(),
            label: f.title.clone(),
        });
    }

    // asset:port -> service
    if let Some((name_part, port_part)) = lower.rsplit_once(':') {
        if let Ok(port) = port_part.parse::<u16>() {
            if let Some(asset) = maps
                .assets
                .values()
                .find(|a| a.name.eq_ignore_ascii_case(name_part))
            {
                if let Some(service) = maps
                    .services
                    .values()
                    .find(|s| s.asset_id == asset.stable_id && s.port == port)
                {
                    return Ok(ResolvedSubject {
                        kind: SubjectKind::Service,
                        id: service.stable_id.clone(),
                        label: format!("{}:{}", asset.name, service.port),
                    });
                }
            }
        }
    }

    // Unambiguous substring matches.
    let asset_contains: Vec<String> = maps
        .assets
        .values()
        .filter(|a| {
            a.name.to_lowercase().contains(&lower)
                || a.ip
                    .as_deref()
                    .is_some_and(|i| i.to_lowercase().contains(&lower))
                || a.fqdn
                    .as_deref()
                    .is_some_and(|f| f.to_lowercase().contains(&lower))
        })
        .map(|a| a.name.clone())
        .collect();
    if asset_contains.len() == 1 {
        let name = &asset_contains[0];
        let asset = maps.assets.values().find(|a| a.name == *name).unwrap();
        return Ok(ResolvedSubject {
            kind: SubjectKind::Asset,
            id: asset.stable_id.clone(),
            label: asset.name.clone(),
        });
    }

    let finding_contains: Vec<String> = maps
        .findings
        .values()
        .filter(|f| f.title.to_lowercase().contains(&lower))
        .map(|f| f.title.clone())
        .collect();
    if finding_contains.len() == 1 {
        let title = &finding_contains[0];
        let finding = maps.findings.values().find(|f| f.title == *title).unwrap();
        return Ok(ResolvedSubject {
            kind: SubjectKind::Finding,
            id: finding.stable_id.clone(),
            label: finding.title.clone(),
        });
    }

    if !asset_contains.is_empty() || !finding_contains.is_empty() {
        let mut lines = Vec::new();
        if !asset_contains.is_empty() {
            lines.push(format!("Assets matching '{}':", term));
            lines.push(list_some(&asset_contains, 5));
        }
        if !finding_contains.is_empty() {
            lines.push(format!("Findings matching '{}':", term));
            lines.push(list_some(&finding_contains, 5));
        }
        lines.push("Be more specific, or use a full id.".to_string());
        return Err(AppError::Message(lines.join("\n")));
    }

    Err(AppError::Message(format!(
        "no asset, service, or finding matches '{}'",
        term
    )))
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

pub fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Print a "nothing matched" message consistent across commands.
pub fn empty_result(what: &str) {
    println!("No {} found.", what);
}

/// Convert a `Value` to a compact single-line rendering for verbose output.
pub fn value_to_short(value: &Value) -> String {
    match value {
        Value::Null => "-".to_string(),
        Value::String(s) => truncate(s, 80).to_string(),
        other => truncate(&other.to_string(), 120).to_string(),
    }
}
