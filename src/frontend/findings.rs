use crate::config::ConfigManager;
use crate::db::models::Finding;
use crate::error::{AppError, Result};
use crate::frontend::{
    empty_result, fmt_ts, open_backend, parse_ts, print_json, severity_label, severity_rank,
    severity_style, ts_since, Args, Cell, IdMaps, LifecycleFilter, ObsIndex, Table,
};

pub fn usage() {
    println!(
        "Usage: ploit-malper findings [--tui] [--severity LEVEL] [--cve ID] [--asset TERM] [--lifecycle STATE] \
         [--new] [--fixed] [--since DATE] [--include-info] [--verbose] [--json] [--backend pocketbase|sqlite]"
    );
}

pub fn cmd_findings(args: &[String], config_mgr: &mut ConfigManager) -> Result<()> {
    let parsed = Args::parse(args)?;
    if parsed.has("help") {
        usage();
        return Ok(());
    }

    let mut storage = open_backend(config_mgr, &parsed)?;

    let findings = storage.list_all_findings()?;
    let observations = storage.list_all_observations()?;
    let obs_index = ObsIndex::build(&observations);
    let maps = IdMaps::load(&mut storage)?;

    let since = match parsed.get("since") {
        Some(raw) => Some(
            parse_ts(raw)
                .ok_or_else(|| AppError::Message(format!("invalid --since date: '{}'", raw)))?,
        ),
        None => None,
    };

    let severity_filter = parsed.get("severity").map(str::to_lowercase);
    // Informational findings stay in the database but are hidden by default so
    // the findings view surfaces real vulnerabilities; --include-info (or an
    // explicit --severity info) opts in.
    let info_requested = severity_filter.as_deref() == Some("info");
    let include_info = parsed.has("include-info") || info_requested;
    let lifecycle_filter = LifecycleFilter::parse_singleton(&parsed, true, true);

    let mut selected: Vec<&Finding> = Vec::new();
    for finding in &findings {
        if !include_info && finding.severity.to_lowercase() == "info" {
            continue;
        }
        if let Some(wanted) = &severity_filter {
            if finding.severity.to_lowercase() != *wanted {
                continue;
            }
        }
        if let Some(cve) = parsed.get("cve") {
            let needle = cve.to_lowercase();
            let hit = finding
                .cves
                .iter()
                .any(|c| c.to_lowercase().contains(&needle))
                || finding.title.to_lowercase().contains(&needle);
            if !hit {
                continue;
            }
        }
        if let Some(asset) = parsed.get("asset") {
            let asset_name = maps.asset_name(&finding.asset_id);
            if !asset_name.to_lowercase().contains(&asset.to_lowercase()) {
                continue;
            }
        }
        if let Some(since) = since {
            if !ts_since(&finding.last_seen, since) {
                continue;
            }
        }
        let state = obs_index.state(&finding.stable_id, &finding.status);
        if let Some(filter) = lifecycle_filter {
            if !filter.matches(state.into()) {
                continue;
            }
        }
        selected.push(finding);
    }

    if parsed.has("json") {
        let data: Vec<Finding> = selected.into_iter().cloned().collect();
        return print_json(&data);
    }

    if selected.is_empty() {
        empty_result("findings");
        return Ok(());
    }

    selected.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then_with(|| a.title.cmp(&b.title))
    });

    if parsed.has("tui") && crate::frontend::tui::interactive() {
        return tui_findings(&selected, &obs_index, &maps);
    }

    let mut table = Table::new(vec![
        "SEVERITY".to_string(),
        "TITLE".to_string(),
        "ASSET".to_string(),
        "PORT".to_string(),
        "FIRST SEEN".to_string(),
        "LAST SEEN".to_string(),
        "CHANGE".to_string(),
    ]);
    for finding in &selected {
        let state = obs_index.state(&finding.stable_id, &finding.status);
        let title = if finding.cves.is_empty() {
            finding.title.clone()
        } else {
            format!("{} ({})", finding.title, finding.cves.join(", "))
        };
        table.add_row(vec![
            Cell::styled(
                severity_label(&finding.severity),
                severity_style(&finding.severity),
            ),
            Cell::plain(title),
            Cell::plain(maps.asset_name(&finding.asset_id)),
            Cell::plain(
                finding
                    .service_id
                    .as_deref()
                    .map(|id| maps.service_label(id))
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Cell::plain(fmt_ts(&finding.first_seen)),
            Cell::plain(fmt_ts(&finding.last_seen)),
            Cell::plain(state.label().to_string()),
        ]);
    }
    println!("{}", table.render());

    if parsed.has("verbose") {
        println!();
        for finding in &selected {
            let asset = maps.asset_name(&finding.asset_id);
            println!(
                "{} ({})  [{}]",
                crate::frontend::bold(&finding.title),
                severity_label(&finding.severity),
                finding.stable_id
            );
            println!(
                "    asset={} service={} tool={} exploitability={} status={}",
                asset,
                finding
                    .service_id
                    .as_deref()
                    .map(|id| maps.service_label(id))
                    .unwrap_or_else(|| "-".to_string()),
                finding.tool,
                finding.exploitability.as_deref().unwrap_or("-"),
                finding.status
            );
            if !finding.cves.is_empty() {
                println!("    cves={}", finding.cves.join(", "));
            }
            if let Some(url) = &finding.target_url {
                println!("    target_url={}", url);
            }
            if let Some(reference) = &finding.reference {
                println!("    reference={}", reference);
            }
            if let Some(detail) = &finding.detail {
                println!("    detail={}", crate::frontend::truncate(detail, 300));
            }
        }
    }

    Ok(())
}

fn tui_findings(selected: &[&Finding], obs_index: &ObsIndex, maps: &IdMaps) -> Result<()> {
    let columns: &[&str] = &[
        "SEVERITY",
        "TITLE",
        "ASSET",
        "PORT",
        "FIRST SEEN",
        "LAST SEEN",
        "CHANGE",
    ];
    let mut rows = Vec::with_capacity(selected.len());
    for finding in selected {
        let state = obs_index.state(&finding.stable_id, &finding.status);
        let title = if finding.cves.is_empty() {
            finding.title.clone()
        } else {
            format!("{} ({})", finding.title, finding.cves.join(", "))
        };
        rows.push(crate::frontend::tui::ViewerRow::new(vec![
            severity_label(&finding.severity),
            title,
            maps.asset_name(&finding.asset_id),
            finding
                .service_id
                .as_deref()
                .map(|id| maps.service_label(id))
                .unwrap_or_else(|| "-".to_string()),
            fmt_ts(&finding.first_seen),
            fmt_ts(&finding.last_seen),
            state.label().to_string(),
        ]));
    }
    let _ = crate::frontend::tui::view_table("Findings", columns, rows)?;
    Ok(())
}
