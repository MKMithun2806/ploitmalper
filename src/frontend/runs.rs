use crate::config::ConfigManager;
use crate::db::models::ScanRun;
use crate::error::Result;
use crate::frontend::{empty_result, fmt_ts, open_backend, print_json, Args, Cell, Table};

pub fn usage() {
    println!("Usage: ploit-malper runs [--verbose] [--json] [--backend pocketbase|sqlite]");
}

pub fn cmd_runs(args: &[String], config_mgr: &mut ConfigManager) -> Result<()> {
    let parsed = Args::parse(args)?;
    if parsed.has("help") {
        usage();
        return Ok(());
    }

    let mut storage = open_backend(config_mgr, &parsed)?;
    let runs = storage.list_scan_runs()?;

    if parsed.has("json") {
        return print_json(&runs);
    }

    if runs.is_empty() {
        empty_result("scan runs");
        println!("Ingest a scan folder with 'ploit-malper ingest <folder>' to create runs.");
        return Ok(());
    }

    let mut table = Table::new(vec![
        "RUN ID".to_string(),
        "TARGET".to_string(),
        "STARTED".to_string(),
        "FINISHED".to_string(),
        "ARTIFACTS".to_string(),
        "TOOLS".to_string(),
        "STATS".to_string(),
    ]);
    for run in &runs {
        let artifact_count = run.artifacts.len();
        let stats = stats_summary(run);
        table.add_row(vec![
            Cell::plain(short_id(&run.stable_id)),
            Cell::plain(run.target.clone()),
            Cell::plain(
                run.started_at
                    .as_deref()
                    .map(fmt_ts)
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Cell::plain(
                run.finished_at
                    .as_deref()
                    .map(fmt_ts)
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Cell::plain(artifact_count.to_string()),
            Cell::plain(if run.tools.is_empty() {
                "-".to_string()
            } else {
                run.tools.join(",")
            }),
            Cell::plain(stats),
        ]);
    }
    println!("{}", table.render());

    if parsed.has("verbose") {
        println!();
        for run in &runs {
            println!("{}", crate::frontend::bold(&run.stable_id));
            println!(
                "    target={} folder={} imported_at={}",
                run.target, run.folder, run.imported_at
            );
            println!(
                "    started={} finished={} content_hash={}",
                run.started_at.as_deref().unwrap_or("-"),
                run.finished_at.as_deref().unwrap_or("-"),
                run.content_hash
            );
            println!("    tools={}", run.tools.join(", "));
            for artifact in &run.artifacts {
                println!("    artifact: {}", artifact);
            }
            if !run.stats.is_null() {
                println!("    stats={}", run.stats);
            }
        }
    }

    Ok(())
}

fn short_id(stable_id: &str) -> String {
    crate::frontend::truncate(stable_id, 16)
}

fn stats_summary(run: &ScanRun) -> String {
    if run.stats.is_null() {
        return "-".to_string();
    }
    let obj = match run.stats.as_object() {
        Some(o) => o,
        None => return "-".to_string(),
    };
    let get = |key: &str| {
        obj.get(key)
            .and_then(serde_json::Value::as_u64)
            .map(|v| v.to_string())
            .unwrap_or_else(|| "?".to_string())
    };
    format!(
        "a:{}/s:{}/f:{}/o:{}",
        get("assets"),
        get("services"),
        get("findings"),
        get("observations")
    )
}
