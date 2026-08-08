//! Temporary diagnostic: dump live module.info / module.options responses so
//! the option-model design can be validated against the real server format.

use ploit_malper::config::ConfigManager;
use ploit_malper::engine::msfrpc::MsfRpcClient;
use ploit_malper::msgpack::MsgValue;

fn describe(v: &MsgValue) -> String {
    match v {
        MsgValue::Map(m) => {
            let mut parts = Vec::new();
            for (k, val) in m {
                parts.push(format!("{k}={}", describe(val)));
            }
            format!("{{{}}}", parts.join(", "))
        }
        MsgValue::Array(a) => format!(
            "[{}]",
            a.iter().map(describe).collect::<Vec<_>>().join(", ")
        ),
        MsgValue::String(s) => format!("{s:?}"),
        MsgValue::Bool(b) => format!("{b}"),
        MsgValue::UInt(n) => format!("{n}"),
        MsgValue::Int(n) => format!("{n}"),
        MsgValue::Float(f) => format!("{f}"),
        MsgValue::Nil => "nil".to_string(),
    }
}

#[test]
fn probe_live_metadata() {
    let mut cm = ConfigManager::new();
    cm.load();
    let cfg = cm.get_msfrpc_config().clone();
    let mut client = MsfRpcClient::new(&cfg.host, cfg.port, &cfg.username, &cfg.password, cfg.ssl);
    let login = client.login().expect("login");
    assert!(login.success, "login failed: {}", login.error);

    let probes: &[(&str, &str)] = &[
        ("auxiliary", "scanner/http/robots_txt"),
        ("auxiliary", "scanner/http/http_version"),
        ("auxiliary", "scanner/ssh/ssh_version"),
        ("exploit", "multi/http/apache_path_traversal"),
        ("exploit", "windows/smb/ms17_010_eternalblue"),
        ("exploit", "multi/http/apache_mod_cgi_bash_env_exec"),
    ];
    for (mtype, name) in probes {
        println!("\n===== module.info {mtype}/{name} =====");
        match client.module_info(mtype, name) {
            Ok(info) => println!("INFO {mtype}/{name}: {}", describe(&info)),
            Err(e) => println!("INFO {mtype}/{name} ERROR: {e}"),
        }
        match client.module_options(mtype, name) {
            Ok(opts) => println!("OPTIONS {mtype}/{name}: {}", describe(&opts)),
            Err(e) => println!("OPTIONS {mtype}/{name} ERROR: {e}"),
        }
    }

    // Probe the listing shape.
    match client.list_modules() {
        Ok(all) => {
            println!("\nLIST: {} modules total", all.len());
            let nginx: Vec<_> = all.iter().filter(|m| m.name.contains("nginx")).collect();
            println!(
                "nginx modules: {:?}",
                nginx.iter().map(|m| m.name.as_str()).collect::<Vec<_>>()
            );
            let robots: Vec<_> = all.iter().filter(|m| m.name.contains("robots")).collect();
            println!(
                "robots modules: {:?}",
                robots.iter().map(|m| m.name.as_str()).collect::<Vec<_>>()
            );
        }
        Err(e) => println!("LIST ERROR: {e}"),
    }
    // A module that does not exist on this instance must resolve to
    // module_exists == false (RpcModuleNotFound), not an opaque RPC error.
    let missing = client
        .module_exists("exploit", "multi/http/apache_path_traversal")
        .expect("module_exists must not error");
    println!("\nmodule_exists exploit/multi/http/apache_path_traversal (missing) = {missing}");
    assert!(!missing, "known-missing module must not exist!");

    let known = client
        .module_exists("exploit", "windows/smb/ms17_010_eternalblue")
        .expect("module_exists must not error");
    println!("module_exists exploit/windows/smb/ms17_010_eternalblue (present) = {known}");
    assert!(known, "known module must exist!");

    client.logout();
}
