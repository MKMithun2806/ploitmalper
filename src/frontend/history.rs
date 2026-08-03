use crate::config::ConfigManager;
use crate::error::{AppError, Result};
use crate::frontend::{
    fmt_ts, open_backend, print_json, resolve_subject, value_to_short, Args, Cell, IdMaps, Table,
};

pub fn usage() {
    println!(
        "Usage: ploit-malper history <id-or-name> [--verbose] [--json] \
         [--backend pocketbase|sqlite]"
    );
}

pub fn cmd_history(args: &[String], config_mgr: &mut ConfigManager) -> Result<()> {
    let parsed = Args::parse(args)?;
    if parsed.has("help") {
        usage();
        return Ok(());
    }

    let term = parsed.positionals().first().ok_or_else(|| {
        AppError::Message("history requires an asset, service, or finding id/name".to_string())
    })?;

    let mut storage = open_backend(config_mgr, &parsed)?;
    let maps = IdMaps::load(&mut storage)?;
    let subject = resolve_subject(&maps, term)?;

    let mut observations = storage.list_observations_for(subject.kind.label(), &subject.id)?;
    observations.sort_by(|a, b| a.observed_at.cmp(&b.observed_at));

    if parsed.has("json") {
        return print_json(&observations);
    }

    println!(
        "History for {} '{}'  [{}]",
        subject.kind.label(),
        crate::frontend::bold(&subject.label),
        subject.id
    );
    println!("{}", "-".repeat(70));

    if observations.is_empty() {
        println!(
            "No observations recorded for this {}.",
            subject.kind.label()
        );
        return Ok(());
    }

    let mut table = Table::new(vec![
        "WHEN".to_string(),
        "RUN".to_string(),
        "KIND".to_string(),
        "DETAIL".to_string(),
    ]);
    for obs in &observations {
        table.add_row(vec![
            Cell::plain(fmt_ts(&obs.observed_at)),
            Cell::plain(short_run(&obs.run_id)),
            Cell::plain(obs.kind.clone()),
            Cell::plain(obs.detail.clone()),
        ]);
    }
    println!("{}", table.render());

    if parsed.has("verbose") {
        println!();
        for obs in &observations {
            println!(
                "{} [{}] {}",
                fmt_ts(&obs.observed_at),
                obs.run_id,
                crate::frontend::bold(&obs.kind)
            );
            println!("    detail: {}", obs.detail);
            println!("    before: {}", value_to_short(&obs.before));
            println!("    after:  {}", value_to_short(&obs.after));
            println!("    subject: {}:{}", obs.subject_type, obs.subject_id);
        }
    }

    Ok(())
}

fn short_run(run_id: &str) -> String {
    crate::frontend::truncate(run_id, 16)
}
