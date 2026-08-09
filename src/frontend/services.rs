use crate::config::ConfigManager;
use crate::db::models::Service;
use crate::error::Result;
use crate::frontend::{
    empty_result, fmt_ts, open_backend, print_json, Args, Cell, IdMaps, LifecycleFilter, ObsIndex,
    Table,
};

pub fn usage() {
    println!(
        "Usage: ploit-malper services [--port N] [--product TERM] [--asset TERM] [--lifecycle STATE] \
         [--verbose] [--json] [--backend pocketbase|sqlite]"
    );
}

pub fn cmd_services(args: &[String], config_mgr: &mut ConfigManager) -> Result<()> {
    let parsed = Args::parse(args)?;
    if parsed.has("help") {
        usage();
        return Ok(());
    }

    let mut storage = open_backend(config_mgr, &parsed)?;

    let services = storage.list_all_services()?;
    let observations = storage.list_all_observations()?;
    let obs_index = ObsIndex::build(&observations);
    let maps = IdMaps::load(&mut storage)?;

    let port_filter = parsed.get("port").map(|p| p.parse::<u16>());
    let port_filter = match port_filter {
        Some(Ok(port)) => Some(port),
        Some(Err(_)) => {
            return Err(crate::error::AppError::Message(format!(
                "invalid --port value: '{}'",
                parsed.get("port").unwrap()
            )));
        }
        None => None,
    };

    let lifecycle_filter = LifecycleFilter::parse_singleton(&parsed, false, false);

    let mut selected: Vec<&Service> = Vec::new();
    for service in &services {
        if let Some(port) = port_filter {
            if service.port != port {
                continue;
            }
        }
        if let Some(product) = parsed.get("product") {
            let needle = product.to_lowercase();
            let hit = service
                .product
                .as_deref()
                .is_some_and(|p| p.to_lowercase().contains(&needle))
                || service
                    .version
                    .as_deref()
                    .is_some_and(|v| v.to_lowercase().contains(&needle))
                || service
                    .version_str
                    .as_deref()
                    .is_some_and(|v| v.to_lowercase().contains(&needle))
                || service.service_name.to_lowercase().contains(&needle);
            if !hit {
                continue;
            }
        }
        if let Some(asset) = parsed.get("asset") {
            let asset_name = maps.asset_name(&service.asset_id);
            if !asset_name.to_lowercase().contains(&asset.to_lowercase()) {
                continue;
            }
        }
        let state = obs_index.state(&service.stable_id, &service.status);
        if let Some(filter) = lifecycle_filter {
            if !filter.matches(state.into()) {
                continue;
            }
        }
        selected.push(service);
    }

    if parsed.has("json") {
        let data: Vec<Service> = selected.into_iter().cloned().collect();
        return print_json(&data);
    }

    if selected.is_empty() {
        empty_result("services");
        return Ok(());
    }

    let mut table = Table::new(vec![
        "ASSET".to_string(),
        "PORT".to_string(),
        "PROTO".to_string(),
        "SERVICE".to_string(),
        "PRODUCT/VERSION".to_string(),
        "FIRST SEEN".to_string(),
        "LAST SEEN".to_string(),
        "CHANGE".to_string(),
    ]);
    for service in &selected {
        let state = obs_index.state(&service.stable_id, &service.status);
        let product_version = match (&service.product, &service.version) {
            (Some(p), Some(v)) => format!("{} {}", p, v),
            (Some(p), None) => p.clone(),
            (None, Some(v)) => v.clone(),
            (None, None) => "-".to_string(),
        };
        table.add_row(vec![
            Cell::plain(maps.asset_name(&service.asset_id)),
            Cell::plain(service.port.to_string()),
            Cell::plain(if service.protocol.is_empty() {
                "tcp".to_string()
            } else {
                service.protocol.clone()
            }),
            Cell::plain(service.service_name.clone()),
            Cell::plain(product_version),
            Cell::plain(fmt_ts(&service.first_seen)),
            Cell::plain(fmt_ts(&service.last_seen)),
            Cell::plain(state.label().to_string()),
        ]);
    }
    println!("{}", table.render());

    if parsed.has("verbose") {
        println!();
        for service in &selected {
            println!(
                "{}:{} ({})  [{}]",
                maps.asset_name(&service.asset_id),
                service.port,
                service.protocol,
                service.stable_id
            );
            println!(
                "    service={} product={} version={} version_str={} status={}",
                service.service_name,
                service.product.as_deref().unwrap_or("-"),
                service.version.as_deref().unwrap_or("-"),
                service.version_str.as_deref().unwrap_or("-"),
                service.status
            );
            if !service.technologies.is_empty() {
                println!("    technologies={}", service.technologies.join(", "));
            }
            if !service.cpes.is_empty() {
                println!("    cpes={}", service.cpes.join(", "));
            }
            if let Some(banner) = &service.banner {
                println!("    banner={}", crate::frontend::truncate(banner, 200));
            }
        }
    }

    Ok(())
}
