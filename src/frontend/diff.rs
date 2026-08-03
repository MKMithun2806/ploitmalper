use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::ConfigManager;
use crate::db::models::{Observation, ScanRun};
use crate::error::{AppError, Result};
use crate::frontend::{
    fmt_ts, open_backend, print_json, value_to_short, Args, Cell, IdMaps, Table,
};

pub fn usage() {
    println!(
        "Usage: ploit-malper diff [run-a] [run-b] [--verbose] [--json] \
         [--backend pocketbase|sqlite]"
    );
    println!("       (defaults to comparing the two most recent runs)");
}

pub fn cmd_diff(args: &[String], config_mgr: &mut ConfigManager) -> Result<()> {
    let parsed = Args::parse(args)?;
    if parsed.has("help") {
        usage();
        return Ok(());
    }

    let mut storage = open_backend(config_mgr, &parsed)?;
    let runs = storage.list_scan_runs()?;
    if runs.is_empty() {
        return Err(AppError::Message(
            "no scan runs recorded; ingest a folder with 'ploit-malper ingest <folder>' first"
                .to_string(),
        ));
    }

    let (run_a, run_b) = match parsed.positionals() {
        [] => {
            if runs.len() < 2 {
                return Err(AppError::Message(
                    "only one scan run exists; diff needs two runs (or ingest another folder)"
                        .to_string(),
                ));
            }
            let mut sorted = runs.clone();
            sorted.sort_by(|a, b| b.imported_at.cmp(&a.imported_at));
            (sorted[1].clone(), sorted[0].clone())
        }
        [a, b] => {
            let resolved_a = resolve_run(&runs, a)?;
            let resolved_b = resolve_run(&runs, b)?;
            if resolved_a.stable_id == resolved_b.stable_id {
                return Err(AppError::Message(
                    "run-a and run-b resolve to the same run".to_string(),
                ));
            }
            (resolved_a.clone(), resolved_b.clone())
        }
        _ => {
            return Err(AppError::Message(
                "diff accepts zero or two run ids/names".to_string(),
            ));
        }
    };

    let all_observations = storage.list_all_observations()?;
    let maps = IdMaps::load(&mut storage)?;

    let mut deltas: Vec<DeltaItem> = all_observations
        .iter()
        .filter(|o| o.run_id == run_b.stable_id)
        .map(|o| delta_from_observation(o, &maps))
        .collect();
    deltas.sort_by(|a, b| a.observed_at.cmp(&b.observed_at));

    let added: Vec<&DeltaItem> = deltas.iter().filter(|d| d.category == "added").collect();
    let removed: Vec<&DeltaItem> = deltas.iter().filter(|d| d.category == "removed").collect();
    let changed: Vec<&DeltaItem> = deltas.iter().filter(|d| d.category == "changed").collect();

    if parsed.has("json") {
        let payload = json!({
            "run_a": run_a,
            "run_b": run_b,
            "content_changed": run_a.content_hash != run_b.content_hash,
            "summary": {
                "added": count_by_type(&added),
                "removed": count_by_type(&removed),
                "changed": count_by_type(&changed),
            },
            "added": &added,
            "removed": &removed,
            "changed": &changed,
        });
        return print_json(&payload);
    }

    if deltas.is_empty() {
        println!(
            "No changes between {} and {} (identical content).",
            run_a.stable_id, run_b.stable_id
        );
        return Ok(());
    }

    println!("Diff: {} -> {}", run_a.stable_id, run_b.stable_id);
    println!(
        "  target:    {} ({} target)",
        run_b.target,
        if run_a.target == run_b.target {
            "same"
        } else {
            "different"
        }
    );
    println!(
        "  imported:  {} -> {}",
        fmt_ts(&run_a.imported_at),
        fmt_ts(&run_b.imported_at)
    );
    println!(
        "  content:   {}",
        if run_a.content_hash == run_b.content_hash {
            "identical".to_string()
        } else {
            "changed".to_string()
        }
    );
    println!();
    println!(
        "{}",
        crate::frontend::bold(&format!(
            "Summary: {} added, {} removed, {} changed",
            added.len(),
            removed.len(),
            changed.len()
        ))
    );
    println!(
        "  added:   {}",
        count_by_type(&added)
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  removed: {}",
        count_by_type(&removed)
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  changed: {}",
        count_by_type(&changed)
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(", ")
    );

    render_section("Newly discovered", &added, parsed.has("verbose"));
    render_section("Removed", &removed, parsed.has("verbose"));
    render_section("Changed", &changed, parsed.has("verbose"));

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeltaItem {
    category: &'static str,
    subject_type: String,
    subject_id: String,
    label: String,
    kind: String,
    before: Value,
    after: Value,
    detail: String,
    observed_at: String,
}

fn delta_from_observation(obs: &Observation, maps: &IdMaps) -> DeltaItem {
    let category = if obs.kind.ends_with("_discovered") {
        "added"
    } else if obs.kind.ends_with("_removed") {
        "removed"
    } else {
        "changed"
    };
    let label = match obs.subject_type.as_str() {
        "asset" => maps.asset_name(&obs.subject_id),
        "service" => {
            let service = maps.services.get(&obs.subject_id);
            match service {
                Some(s) => format!("{}:{}", maps.asset_name(&s.asset_id), s.port),
                None => obs.subject_id.clone(),
            }
        }
        "finding" => maps.finding_title(&obs.subject_id),
        other => format!("{}:{}", other, obs.subject_id),
    };
    DeltaItem {
        category,
        subject_type: obs.subject_type.clone(),
        subject_id: obs.subject_id.clone(),
        label,
        kind: obs.kind.clone(),
        before: obs.before.clone(),
        after: obs.after.clone(),
        detail: obs.detail.clone(),
        observed_at: obs.observed_at.clone(),
    }
}

fn count_by_type(items: &[&DeltaItem]) -> Vec<(String, usize)> {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for item in items {
        if let Some(entry) = counts.iter_mut().find(|(key, _)| *key == item.subject_type) {
            entry.1 += 1;
        } else {
            counts.push((item.subject_type.clone(), 1));
        }
    }
    counts.sort();
    counts
}

fn render_section(title: &str, items: &[&DeltaItem], verbose: bool) {
    println!();
    if items.is_empty() {
        println!("{}: none", crate::frontend::dim(title));
        return;
    }
    println!("{}: {}", crate::frontend::bold(title), items.len());
    let mut table = Table::new(vec![
        "TYPE".to_string(),
        "SUBJECT".to_string(),
        "KIND".to_string(),
        "WHEN".to_string(),
    ]);
    for item in items {
        table.add_row(vec![
            Cell::plain(item.subject_type.clone()),
            Cell::plain(item.label.clone()),
            Cell::plain(item.kind.clone()),
            Cell::plain(fmt_ts(&item.observed_at)),
        ]);
    }
    println!("{}", table.render());
    if verbose {
        for item in items {
            println!(
                "  {} {}  [{}]",
                crate::frontend::dim(&item.subject_type),
                item.label,
                item.subject_id
            );
            println!("    kind:   {}", item.kind);
            println!("    detail: {}", item.detail);
            println!("    before: {}", value_to_short(&item.before));
            println!("    after:  {}", value_to_short(&item.after));
        }
    }
}

fn resolve_run<'a>(runs: &'a [ScanRun], term: &str) -> Result<&'a ScanRun> {
    let lower = term.trim().to_lowercase();

    if let Some(run) = runs.iter().find(|r| r.stable_id == lower) {
        return Ok(run);
    }

    let prefix_matches: Vec<&ScanRun> = runs
        .iter()
        .filter(|r| r.stable_id.starts_with(&lower))
        .collect();
    if prefix_matches.len() == 1 {
        return Ok(prefix_matches[0]);
    }

    let target_matches: Vec<&ScanRun> = runs
        .iter()
        .filter(|r| r.target.to_lowercase() == lower)
        .collect();
    if target_matches.len() == 1 {
        return Ok(target_matches[0]);
    }

    if !prefix_matches.is_empty() {
        return Err(AppError::Message(format!(
            "run '{}' is ambiguous; matches:\n{}",
            term,
            prefix_matches
                .iter()
                .map(|r| format!("  - {}", r.stable_id))
                .collect::<Vec<_>>()
                .join("\n")
        )));
    }

    let known: Vec<String> = runs.iter().map(|r| r.stable_id.clone()).collect();
    Err(AppError::Message(format!(
        "no run matches '{}'.\nKnown runs:\n{}",
        term,
        known
            .iter()
            .take(20)
            .map(|r| format!("  - {}", r))
            .collect::<Vec<_>>()
            .join("\n")
    )))
}
