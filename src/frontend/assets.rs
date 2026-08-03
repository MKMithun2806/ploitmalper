use crate::config::ConfigManager;
use crate::db::models::Asset;
use crate::error::{AppError, Result};
use crate::frontend::{
    bold, fmt_ts, open_backend, parse_ts, print_json, ts_since, Args, Cell, ChangeState, IdMaps,
    ObsIndex, Table,
};

pub fn usage() {
    println!(
        "Usage: ploit-malper assets [--new] [--changed] [--since DATE] [--target TERM] \
         [--verbose] [--json] [--backend pocketbase|sqlite]"
    );
}

pub fn cmd_assets(args: &[String], config_mgr: &mut ConfigManager) -> Result<()> {
    let parsed = Args::parse(args)?;
    if parsed.has("help") {
        usage();
        return Ok(());
    }

    let mut storage = open_backend(config_mgr, &parsed)?;

    let assets = storage.list_assets()?;
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

    let mut selected: Vec<&Asset> = Vec::new();
    for asset in &assets {
        if let Some(target) = parsed.get("target") {
            let needle = target.to_lowercase();
            let hit = asset.name.to_lowercase().contains(&needle)
                || asset
                    .ip
                    .as_deref()
                    .is_some_and(|i| i.to_lowercase().contains(&needle))
                || asset
                    .fqdn
                    .as_deref()
                    .is_some_and(|f| f.to_lowercase().contains(&needle))
                || asset
                    .reverse_dns
                    .as_deref()
                    .is_some_and(|r| r.to_lowercase().contains(&needle));
            if !hit {
                continue;
            }
        }
        if let Some(since) = since {
            if !ts_since(&asset.last_seen, since) {
                continue;
            }
        }
        let state = obs_index.state(&asset.stable_id, &asset.status);
        if parsed.has("new") && state != ChangeState::New {
            continue;
        }
        if parsed.has("changed") && state != ChangeState::Changed {
            continue;
        }
        selected.push(asset);
    }

    if parsed.has("json") {
        let data: Vec<Asset> = selected.into_iter().cloned().collect();
        return print_json(&data);
    }

    if selected.is_empty() {
        crate::frontend::empty_result("assets");
        return Ok(());
    }

    let mut table = Table::new(vec![
        "NAME".to_string(),
        "TYPE".to_string(),
        "SERVICES".to_string(),
        "FIRST SEEN".to_string(),
        "LAST SEEN".to_string(),
        "CHANGE".to_string(),
    ]);
    for asset in &selected {
        let state = obs_index.state(&asset.stable_id, &asset.status);
        table.add_row(vec![
            Cell::plain(asset.name.clone()),
            Cell::plain(asset.asset_type.clone()),
            Cell::plain(maps.service_summary(&asset.stable_id)),
            Cell::plain(fmt_ts(&asset.first_seen)),
            Cell::plain(fmt_ts(&asset.last_seen)),
            Cell::styled(state.label().to_string(), state_style(state)),
        ]);
    }
    println!("{}", table.render());

    if parsed.has("verbose") {
        println!();
        for asset in &selected {
            println!(
                "{} ({})  [{}]",
                bold(&asset.name),
                asset.asset_type,
                asset.stable_id
            );
            println!(
                "    ip={} fqdn={} reverse_dns={} status={}",
                asset.ip.as_deref().unwrap_or("-"),
                asset.fqdn.as_deref().unwrap_or("-"),
                asset.reverse_dns.as_deref().unwrap_or("-"),
                asset.status
            );
            if !asset.metadata.is_null() && asset.metadata.as_object().is_some() {
                println!("    metadata={}", asset.metadata);
            }
            let observations = obs_index.observations_for(&asset.stable_id);
            if !observations.is_empty() {
                let last = observations.last().unwrap();
                println!("    last change: {} ({})", last.kind, last.observed_at);
            }
        }
    }

    Ok(())
}

fn state_style(state: ChangeState) -> &'static str {
    match state {
        ChangeState::New => "32",
        ChangeState::Changed => "33",
        ChangeState::Removed => "31",
        ChangeState::Unchanged => "2",
    }
}
