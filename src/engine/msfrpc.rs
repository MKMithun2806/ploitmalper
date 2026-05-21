use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use rmp_serde::Serializer;
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSFWorkspaceInfo {
    pub name: String,
    pub scope: String,
    pub host_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSFHostInfo {
    pub address: String,
    pub os_name: String,
    pub os_flavor: String,
    pub state: String,
    pub notes_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSFLoginResult {
    pub success: bool,
    pub token: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSFWorkspacesResult {
    pub workspaces: Vec<MSFWorkspaceInfo>,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSFHostsResult {
    pub hosts: Vec<MSFHostInfo>,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSFHostCheckResult {
    pub exists: bool,
    pub error: String,
}

struct MSFSession {
    host: String,
    port: u16,
    ssl: bool,
    token: Option<String>,
}

lazy_static::lazy_static! {
    static ref SESSION: Mutex<Option<MSFSession>> = Mutex::new(None);
}

fn build_url(host: &str, port: u16, ssl: bool) -> String {
    let scheme = if ssl { "https" } else { "http" };
    format!("{}://{}:{}/api/1.1", scheme, host, port)
}

fn encode_msgpack(method: &str, params: Vec<Value>) -> Vec<u8> {
    let msg = Value::Map(vec![
        (Value::String("method".into()), Value::String(method.into())),
        (Value::String("params".into()), Value::Array(params)),
    ]);
    let mut buf = Vec::new();
    msg.serialize(&mut Serializer::new(&mut buf)).unwrap();
    buf
}

fn send_request(url: &str, payload: &[u8], timeout_secs: u64) -> Result<Value, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build();

    let resp = agent
        .post(url)
        .set("Content-Type", "binary/message-pack")
        .send_bytes(payload)
        .map_err(|e| e.to_string())?;

    let mut reader = resp.into_reader();
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut bytes)
        .map_err(|e| e.to_string())?;

    let value: Value = rmp_serde::from_slice(&bytes)
        .map_err(|e| format!("msgpack decode error: {}", e))?;

    Ok(value)
}

fn extract_string(val: &Value) -> String {
    match val {
        Value::String(s) => s.as_str().unwrap_or("").to_string(),
        _ => String::new(),
    }
}

fn extract_u64(val: &Value) -> u64 {
    match val {
        Value::Integer(i) => i.as_u64().unwrap_or(0),
        Value::F64(f) => *f as u64,
        _ => 0,
    }
}

fn val_str(s: &str) -> Value {
    Value::String(s.into())
}

#[pyfunction]
fn msf_login(host: &str, port: u16, username: &str, password: &str, ssl: bool) -> PyResult<String> {
    let url = build_url(host, port, ssl);
    let params = vec![val_str(username), val_str(password)];
    let payload = encode_msgpack("auth.login", params);

    let result = match send_request(&url, &payload, 10) {
        Ok(val) => {
            if let Value::Map(map) = &val {
                for (k, v) in map {
                    if let Value::String(key) = k {
                        if key.as_str() == Some("result") {
                            if extract_string(v) == "success" {
                                for (k2, v2) in map {
                                    if let Value::String(key2) = k2 {
                                        if key2.as_str() == Some("token") {
                                            let token = extract_string(v2);
                                            let mut session = SESSION.lock().unwrap();
                                            *session = Some(MSFSession {
                                                host: host.to_string(),
                                                port,
                                                ssl,
                                                token: Some(token.clone()),
                                            });
                                            return serde_json::to_string(&MSFLoginResult {
                                                success: true,
                                                token,
                                                error: String::new(),
                                            }).map_err(|e| PyValueError::new_err(e.to_string()));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            MSFLoginResult {
                success: false,
                token: String::new(),
                error: "Authentication failed".to_string(),
            }
        }
        Err(e) => MSFLoginResult {
            success: false,
            token: String::new(),
            error: e,
        }
    };

    serde_json::to_string(&result).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn msf_logout() -> PyResult<()> {
    let mut session = SESSION.lock().unwrap();
    if let Some(s) = session.as_ref() {
        if let Some(ref token) = s.token {
            let url = build_url(&s.host, s.port, s.ssl);
            let params = vec![val_str(token)];
            let payload = encode_msgpack("auth.logout", params);
            let _ = send_request(&url, &payload, 5);
        }
    }
    *session = None;
    Ok(())
}

#[pyfunction]
fn msf_is_authenticated() -> PyResult<bool> {
    let session = SESSION.lock().unwrap();
    Ok(session.as_ref().and_then(|s| s.token.as_ref()).is_some())
}

#[pyfunction]
fn msf_get_workspaces() -> PyResult<String> {
    let session = SESSION.lock().unwrap();
    let s = match session.as_ref() {
        Some(s) => s,
        None => {
            return serde_json::to_string(&MSFWorkspacesResult {
                workspaces: vec![],
                error: "Not authenticated".to_string(),
            }).map_err(|e| PyValueError::new_err(e.to_string()));
        }
    };

    let token = s.token.clone().unwrap();
    let url = build_url(&s.host, s.port, s.ssl);
    let params = vec![val_str(&token)];
    let payload = encode_msgpack("db.workspaces", params);

    let result = match send_request(&url, &payload, 15) {
        Ok(val) => {
            let mut workspaces = Vec::new();
            if let Value::Map(map) = &val {
                for (k, v) in map {
                    if let Value::String(key) = k {
                        if key.as_str() == Some("workspaces") {
                            if let Value::Array(ws_arr) = v {
                                for ws in ws_arr {
                                    if let Value::Map(ws_map) = ws {
                                        let mut name = String::new();
                                        let mut scope = String::new();
                                        let mut host_count: u64 = 0;
                                        for (wk, wv) in ws_map {
                                            if let Value::String(wkey) = wk {
                                                match wkey.as_str() {
                                                    Some("name") => name = extract_string(wv),
                                                    Some("scope") => scope = extract_string(wv),
                                                    Some("hosts_count") => host_count = extract_u64(wv),
                                                    _ => {}
                                                }
                                            }
                                        }
                                        workspaces.push(MSFWorkspaceInfo { name, scope, host_count });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            MSFWorkspacesResult {
                workspaces,
                error: String::new(),
            }
        }
        Err(e) => MSFWorkspacesResult {
            workspaces: vec![],
            error: e,
        }
    };

    serde_json::to_string(&result).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn msf_get_hosts(workspace: &str) -> PyResult<String> {
    let session = SESSION.lock().unwrap();
    let s = match session.as_ref() {
        Some(s) => s,
        None => {
            return serde_json::to_string(&MSFHostsResult {
                hosts: vec![],
                error: "Not authenticated".to_string(),
            }).map_err(|e| PyValueError::new_err(e.to_string()));
        }
    };

    let token = s.token.clone().unwrap();
    let url = build_url(&s.host, s.port, s.ssl);
    let ws_filter = Value::Map(vec![
        (Value::String("workspace".into()), val_str(workspace)),
    ]);
    let params = vec![val_str(&token), ws_filter];
    let payload = encode_msgpack("db.hosts", params);

    let result = match send_request(&url, &payload, 15) {
        Ok(val) => {
            let mut hosts = Vec::new();
            if let Value::Map(map) = &val {
                for (k, v) in map {
                    if let Value::String(key) = k {
                        if key.as_str() == Some("hosts") {
                            if let Value::Array(h_arr) = v {
                                for h in h_arr {
                                    if let Value::Map(h_map) = h {
                                        let mut address = String::new();
                                        let mut os_name = String::new();
                                        let mut os_flavor = String::new();
                                        let mut state = String::new();
                                        let mut notes_count: u64 = 0;
                                        for (hk, hv) in h_map {
                                            if let Value::String(hkey) = hk {
                                                match hkey.as_str() {
                                                    Some("address") => address = extract_string(hv),
                                                    Some("os_name") => os_name = extract_string(hv),
                                                    Some("os_flavor") => os_flavor = extract_string(hv),
                                                    Some("state") => state = extract_string(hv),
                                                    Some("notes_count") => notes_count = extract_u64(hv),
                                                    _ => {}
                                                }
                                            }
                                        }
                                        hosts.push(MSFHostInfo {
                                            address,
                                            os_name,
                                            os_flavor,
                                            state,
                                            notes_count,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            MSFHostsResult {
                hosts,
                error: String::new(),
            }
        }
        Err(e) => MSFHostsResult {
            hosts: vec![],
            error: e,
        }
    };

    serde_json::to_string(&result).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn msf_check_host_exists(address: &str, workspace: &str) -> PyResult<String> {
    let hosts_json = msf_get_hosts(workspace)?;
    let hosts_result: MSFHostsResult = serde_json::from_str(&hosts_json)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let exists = hosts_result.hosts.iter().any(|h| h.address == address);

    serde_json::to_string(&MSFHostCheckResult {
        exists,
        error: hosts_result.error,
    }).map_err(|e| PyValueError::new_err(e.to_string()))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(msf_login, m)?)?;
    m.add_function(wrap_pyfunction!(msf_logout, m)?)?;
    m.add_function(wrap_pyfunction!(msf_is_authenticated, m)?)?;
    m.add_function(wrap_pyfunction!(msf_get_workspaces, m)?)?;
    m.add_function(wrap_pyfunction!(msf_get_hosts, m)?)?;
    m.add_function(wrap_pyfunction!(msf_check_host_exists, m)?)?;
    Ok(())
}
