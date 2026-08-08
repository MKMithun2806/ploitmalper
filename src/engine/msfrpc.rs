use std::collections::BTreeMap;
use std::process::{Command, Stdio};

use crate::error::{AppError, Result};
use crate::models::{
    MSFHostCheckResult, MSFHostInfo, MSFHostsResult, MSFLoginResult, MSFModule, MSFWorkspaceInfo,
    MSFWorkspacesResult,
};
use crate::msgpack::{decode, encode, MsgValue};

#[derive(Debug, Clone)]
pub struct MsfRpcClient {
    host: String,
    port: u16,
    ssl: bool,
    username: String,
    password: String,
    token: Option<String>,
}

impl MsfRpcClient {
    pub fn new(host: &str, port: u16, username: &str, password: &str, ssl: bool) -> Self {
        Self {
            host: host.to_string(),
            port,
            ssl,
            username: username.to_string(),
            password: password.to_string(),
            token: None,
        }
    }

    pub fn login(&mut self) -> Result<MSFLoginResult> {
        let url = build_url(&self.host, self.port, self.ssl);
        // Array format: [method, ...params]
        let payload = encode(&msg_array(vec![
            msg_str("auth.login"),
            msg_str(&self.username),
            msg_str(&self.password),
        ]));

        match send_request(&url, &payload, 10) {
            Ok(val) => {
                let success = val.get("result").and_then(MsgValue::as_str) == Some("success");
                let token = val
                    .get("token")
                    .and_then(MsgValue::as_str)
                    .unwrap_or("")
                    .to_string();

                if success && !token.is_empty() {
                    self.token = Some(token.clone());
                    Ok(MSFLoginResult {
                        success: true,
                        token,
                        error: String::new(),
                    })
                } else {
                    let error_msg = val
                        .get("error_message")
                        .or_else(|| val.get("error_string"))
                        .and_then(MsgValue::as_str)
                        .unwrap_or("Authentication failed");
                    Ok(MSFLoginResult {
                        success: false,
                        token: String::new(),
                        error: error_msg.to_string(),
                    })
                }
            }
            Err(error) => Ok(MSFLoginResult {
                success: false,
                token: String::new(),
                error,
            }),
        }
    }

    pub fn logout(&mut self) {
        if let Some(token) = self.token.clone() {
            let url = build_url(&self.host, self.port, self.ssl);
            // Array format: [method, token]
            let payload = encode(&msg_array(vec![msg_str("auth.logout"), msg_str(&token)]));
            let _ = send_request(&url, &payload, 5);
        }
        self.token = None;
    }

    pub fn is_authenticated(&self) -> bool {
        self.token.is_some()
    }

    pub fn get_workspaces(&self) -> Result<MSFWorkspacesResult> {
        let token = match self.token.as_ref() {
            Some(token) => token.clone(),
            None => {
                return Ok(MSFWorkspacesResult {
                    workspaces: vec![],
                    error: "Not authenticated".to_string(),
                });
            }
        };

        let url = build_url(&self.host, self.port, self.ssl);
        // Array format: [method, token]
        let payload = encode(&msg_array(vec![msg_str("db.workspaces"), msg_str(&token)]));

        match send_request(&url, &payload, 15) {
            Ok(val) => Ok(MSFWorkspacesResult {
                workspaces: extract_workspaces(&val),
                error: String::new(),
            }),
            Err(error) => Ok(MSFWorkspacesResult {
                workspaces: vec![],
                error,
            }),
        }
    }

    pub fn get_hosts(&self, workspace: Option<&str>) -> Result<MSFHostsResult> {
        let token = match self.token.as_ref() {
            Some(token) => token.clone(),
            None => {
                return Ok(MSFHostsResult {
                    hosts: vec![],
                    error: "Not authenticated".to_string(),
                });
            }
        };

        let url = build_url(&self.host, self.port, self.ssl);
        // Array format: [method, token, options_hash]
        // The RPC dispatcher extracts the token from args for auth,
        // so we need the workspace filter as the next parameter
        let mut params = vec![msg_str("db.hosts"), msg_str(&token)];
        if let Some(workspace) = workspace {
            params.push(MsgValue::Map(BTreeMap::from([(
                "workspace".to_string(),
                msg_str(workspace),
            )])));
        } else {
            params.push(MsgValue::Map(BTreeMap::new()));
        }
        let payload = encode(&msg_array(params));

        match send_request(&url, &payload, 15) {
            Ok(val) => Ok(MSFHostsResult {
                hosts: extract_hosts(&val),
                error: String::new(),
            }),
            Err(error) => Ok(MSFHostsResult {
                hosts: vec![],
                error,
            }),
        }
    }

    pub fn check_host_exists(
        &self,
        address: &str,
        workspace: Option<&str>,
    ) -> Result<MSFHostCheckResult> {
        let hosts = self.get_hosts(workspace)?;
        Ok(MSFHostCheckResult {
            exists: hosts.hosts.iter().any(|host| host.address == address),
            error: hosts.error,
        })
    }

    /// Generic authenticated RPC call: `[method, token, ...params]`.
    ///
    /// Used by the exploitation layer for module discovery, execution and job
    /// monitoring. Returns the raw msgpack response so the caller can map it
    /// to strongly typed models.
    pub fn rpc_call(
        &self,
        method: &str,
        params: &[MsgValue],
        timeout_secs: u64,
    ) -> Result<MsgValue> {
        let token = self
            .token
            .clone()
            .ok_or_else(|| crate::error::AppError::Message("not authenticated".to_string()))?;
        let url = build_url(&self.host, self.port, self.ssl);
        let mut args = vec![msg_str(method), msg_str(&token)];
        args.extend_from_slice(params);
        let payload = encode(&msg_array(args));
        send_request(&url, &payload, timeout_secs).map_err(crate::error::AppError::Network)
    }

    /// Verify that a module exists on the connected Metasploit instance.
    /// `module_type` is `exploit`, `auxiliary` or `post`.
    ///
    /// Distinguishes three outcomes: the module exists (`Ok(true)`), it does
    /// not exist (`Ok(false)`), or the lookup itself failed (`Err`).
    pub fn module_exists(&self, module_type: &str, name: &str) -> Result<bool> {
        match self.module_info(module_type, name) {
            Ok(_) => Ok(true),
            Err(AppError::RpcModuleNotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Fetch full module metadata via `module.info`.
    ///
    /// The RPC `module.info` handler accepts `[ModuleType, ModuleName]` on
    /// all supported framework releases. A modern server answers with a rich
    /// metadata map for known modules and an error map ― classifiable as
    /// "module not found" or an RPC failure ― for unknown ones. Only very old
    /// frameworks still expect the single full-name signature; when the modern
    /// response signals an argument-shape mismatch (rather than a missing
    /// module) we fall back to that form once.
    pub fn module_info(&self, module_type: &str, name: &str) -> Result<MsgValue> {
        let leaf = strip_type_prefix(module_type, name);
        let modern = self.rpc_call("module.info", &[msg_str(module_type), msg_str(&leaf)], 15)?;
        match response_error(&modern) {
            None => Ok(modern),
            Some(message) => {
                if is_missing_module(&modern) {
                    return Err(AppError::RpcModuleNotFound(message));
                }
                // Not a lookup failure: probably an argument-shape mismatch on
                // a server that only understands the legacy single-name form.
                if looks_like_legacy_signature_error(&modern) {
                    let legacy = self.rpc_call(
                        "module.info",
                        &[msg_str(&full_name(module_type, name))],
                        15,
                    )?;
                    if let Some(legacy_message) = response_error(&legacy) {
                        return Err(classify_lookup(&legacy_message));
                    }
                    return Ok(legacy);
                }
                Err(AppError::Rpc(message))
            }
        }
    }

    /// Fetch the datastore options for a module via `module.options`.
    /// Mirrors the `module.info` lookup logic (modern form first, legacy
    /// single-name fallback reserved for servers that reject the modern one).
    pub fn module_options(&self, module_type: &str, name: &str) -> Result<MsgValue> {
        let leaf = strip_type_prefix(module_type, name);
        let modern = self.rpc_call(
            "module.options",
            &[msg_str(module_type), msg_str(&leaf)],
            15,
        )?;
        match response_error(&modern) {
            None => Ok(modern),
            Some(message) => {
                if is_missing_module(&modern) {
                    return Err(AppError::RpcModuleNotFound(message));
                }
                if looks_like_legacy_signature_error(&modern) {
                    let legacy = self.rpc_call(
                        "module.options",
                        &[msg_str(&full_name(module_type, name))],
                        15,
                    )?;
                    if let Some(legacy_message) = response_error(&legacy) {
                        return Err(classify_lookup(&legacy_message));
                    }
                    return Ok(legacy);
                }
                Err(AppError::Rpc(message))
            }
        }
    }

    /// List every module of the given RPC type currently loaded by the
    /// instance. Returns full refnames including the type prefix, e.g.
    /// `auxiliary/scanner/http/robots_txt`.
    ///
    /// RPC listing methods take no arguments; passing a module name to them is
    /// ignored (or rejected by stricter servers) and would never be a valid
    /// existence probe.
    pub fn list_modules_for_type(&self, module_type: &str) -> Result<Vec<MSFModule>> {
        let method = match module_type {
            "exploit" => "module.exploits",
            "auxiliary" => "module.auxiliary",
            "post" => "module.post",
            other => {
                return Err(AppError::Message(format!(
                    "cannot list modules of unknown type '{other}'"
                )));
            }
        };
        let val = self.rpc_call(method, &[], 15)?;
        if let Some(message) = response_error(&val) {
            return Err(classify_lookup(&message));
        }
        Ok(extract_module_list(&val, module_type))
    }

    /// Load the union of all exploit, auxiliary and post modules known to the
    /// connected instance. Used by the process pipeline so suggestions are
    /// grounded in what the instance can actually run.
    pub fn list_modules(&self) -> Result<Vec<MSFModule>> {
        let mut modules = Vec::new();
        let mut errors = Vec::new();
        for module_type in ["exploit", "auxiliary", "post"] {
            match self.list_modules_for_type(module_type) {
                Ok(mut found) => modules.append(&mut found),
                Err(error) => errors.push(error),
            }
        }
        if modules.is_empty() && !errors.is_empty() {
            return Err(errors.remove(0));
        }
        modules.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(modules)
    }

    /// Execute a module. Returns a map containing `job_id` on success or an
    /// error payload on failure.
    pub fn module_execute(
        &self,
        module_type: &str,
        name: &str,
        options: &BTreeMap<String, String>,
        payload: Option<&str>,
    ) -> Result<MsgValue> {
        let mut opts = BTreeMap::new();
        for (key, value) in options {
            opts.insert(key.clone(), msg_str(value));
        }
        if let Some(payload) = payload {
            opts.insert("PAYLOAD".to_string(), msg_str(payload));
        }
        self.rpc_call(
            "module.execute",
            &[
                msg_str(module_type),
                msg_str(&strip_type_prefix(module_type, name)),
                MsgValue::Map(opts),
            ],
            30,
        )
    }

    /// List all running jobs. Response map: `{ "jobs": { "0": {...}, ... } }`.
    pub fn job_list(&self) -> Result<MsgValue> {
        self.rpc_call("job.list", &[], 15)
    }

    /// Fetch status of a single job by id.
    pub fn job_info(&self, job_id: &str) -> Result<MsgValue> {
        self.rpc_call("job.info", &[msg_str(job_id)], 15)
    }

    /// Stop a running job by id.
    pub fn job_stop(&self, job_id: &str) -> Result<MsgValue> {
        self.rpc_call("job.stop", &[msg_str(job_id)], 15)
    }

    /// List current sessions. Response map: `{ "sessions": { "1": {...}, ... } }`.
    pub fn session_list(&self) -> Result<MsgValue> {
        self.rpc_call("session.list", &[], 15)
    }

    /// List loot records for a workspace.
    pub fn db_loots(&self, workspace: &str) -> Result<MsgValue> {
        let mut opts = BTreeMap::new();
        if !workspace.is_empty() {
            opts.insert("workspace".to_string(), msg_str(workspace));
        }
        self.rpc_call("db.loots", &[MsgValue::Map(opts)], 15)
    }
}

/// Convenience constructors for msgpack values used across the RPC layer.
fn msg_str(value: &str) -> MsgValue {
    MsgValue::String(value.to_string())
}

fn msg_array(values: Vec<MsgValue>) -> MsgValue {
    MsgValue::Array(values)
}

fn build_url(host: &str, port: u16, ssl: bool) -> String {
    let scheme = if ssl { "https" } else { "http" };
    format!("{}://{}:{}/api/", scheme, host, port)
}

/// Strip a leading `exploit/`, `auxiliary/` or `post/` type prefix from a
/// module name. RPC module handlers accept the bare leaf name (or, per the
/// docs, the prefixed form) but the listing methods always return the leaf.
fn strip_type_prefix(module_type: &str, name: &str) -> String {
    for prefix in [module_type, "exploit", "auxiliary", "post"] {
        if let Some(rest) = name.strip_prefix(&format!("{prefix}/")) {
            return rest.to_string();
        }
    }
    name.to_string()
}

/// Rebuild the full refname, e.g. `auxiliary/scanner/http/robots_txt`.
fn full_name(module_type: &str, name: &str) -> String {
    if ["exploit", "auxiliary", "post"]
        .iter()
        .any(|p| name.starts_with(&format!("{}/", p)))
    {
        return name.to_string();
    }
    match module_type {
        "exploit" | "auxiliary" | "post" => format!("{module_type}/{name}"),
        _ => name.to_string(),
    }
}

/// Inspect an RPC response map for an error payload.
///
/// Metasploit returns `{ "error" => true, "error_message" => "..." }` (or
/// `error_string`) on failure and omits the key (or sets it to `false` /
/// `"success"`) on success. Returns the human-readable message for errors.
fn response_error(val: &MsgValue) -> Option<String> {
    match val.get("error") {
        None => None,
        Some(MsgValue::Bool(false)) => None,
        Some(MsgValue::String(value)) if value == "success" => None,
        Some(MsgValue::String(value)) if value == "true" => Some(error_message(val)),
        Some(MsgValue::UInt(0)) | Some(MsgValue::Int(0)) => None,
        Some(_) => Some(error_message(val)),
    }
}

fn error_message(val: &MsgValue) -> String {
    val.get("error_message")
        .or_else(|| val.get("error_string"))
        .and_then(MsgValue::as_str)
        .unwrap_or("MSF-RPC command failed")
        .to_string()
}

/// Map a module lookup failure message to the error type that callers use to
/// distinguish "module really is missing" from any other RPC failure.
fn classify_lookup(message: &str) -> AppError {
    let lower = message.to_lowercase();
    if lower.contains("not found")
        || lower.contains("does not exist")
        || lower.contains("missing")
        || lower.contains("invalid")
    {
        AppError::RpcModuleNotFound(message.to_string())
    } else {
        AppError::Rpc(message.to_string())
    }
}

/// True when an RPC error response is a *module lookup* failure rather than a
/// transport or argument problem. MSF raises from `RPC_Module#_find_module`
/// for missing modules, and its `error_message` mentions the module or "Invalid".
fn is_missing_module(err: &MsgValue) -> bool {
    let message = error_message(err);
    let bar = err
        .get("error_backtrace")
        .and_then(MsgValue::as_array)
        .is_some_and(|frames| {
            frames
                .iter()
                .filter_map(MsgValue::as_str)
                .any(|frame| frame.contains("_find_module"))
        });
    let lower = message.to_lowercase();
    bar || lower.contains("not found")
        || lower.contains("does not exist")
        || lower.contains("invalid module")
        || lower.contains("module not found")
        || lower.contains("missing module")
}

/// True when the server rejected the modern `[ModuleType, ModuleName]` shape
/// itself (an argument-count error), which is the only case where the legacy
/// single-name signature may still be required.
fn looks_like_legacy_signature_error(err: &MsgValue) -> bool {
    let message = err
        .get("error_string")
        .and_then(MsgValue::as_str)
        .unwrap_or("");
    let lower = message.to_lowercase();
    lower.contains("wrong number of arguments") || lower.contains("invalid message format")
}

/// Parse a `module.exploits` / `module.auxiliary` / `module.post` listing
/// response. Newer servers return `{ "modules" => [ "scanner/http/...", ... ] }`
/// (an array); some versions return a name -> description hash. Both are
/// handled so the loader works across releases.
fn extract_module_list(val: &MsgValue, module_type: &str) -> Vec<MSFModule> {
    let mut names: Vec<String> = Vec::new();
    match val.get("modules") {
        Some(MsgValue::Array(items)) => {
            for item in items {
                if let Some(name) = item.as_str() {
                    names.push(name.to_string());
                }
            }
        }
        Some(MsgValue::Map(items)) => {
            names.extend(items.keys().cloned());
        }
        _ => {
            // Some legacy servers return the map directly with no "modules" key.
            if let MsgValue::Map(items) = val {
                names.extend(items.keys().cloned());
            }
        }
    }
    names.sort();
    names.dedup();
    names
        .into_iter()
        .map(|name| MSFModule {
            name: full_name(module_type, &name),
            cve: None,
            rank: String::new(),
            disclosure_date: "unknown".to_string(),
            platforms: Vec::new(),
            required_options: Vec::new(),
        })
        .collect()
}

fn send_request(
    url: &str,
    payload: &[u8],
    timeout_secs: u64,
) -> std::result::Result<MsgValue, String> {
    let mut child = Command::new("curl")
        .arg("-sS")
        .arg("--max-time")
        .arg(timeout_secs.to_string())
        .arg("-H")
        .arg("Content-Type: binary/message-pack")
        .arg("-H")
        .arg("Accept: binary/message-pack")
        .arg("-i")
        .arg("--data-binary")
        .arg("@-")
        .arg(url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn curl: {e}"))?;

    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        stdin
            .write_all(payload)
            .map_err(|e| format!("failed to write request body: {e}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("curl wait failed: {e}"))?;

    let stdout = &output.stdout;
    if stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if !stderr.is_empty() {
            return Err(stderr);
        }
        return Err("empty response from server".to_string());
    }

    // Split headers from body (curl -i includes headers in stdout)
    let body = if let Some(pos) = find_header_body_boundary(stdout) {
        &stdout[pos..]
    } else {
        &stdout[..]
    };

    if body.is_empty() {
        return Err("empty response body from server".to_string());
    }

    decode(body).map_err(|e| {
        let dump_len = body.len().min(512);
        let hex_dump: Vec<String> = body[..dump_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let utf8_dump = String::from_utf8_lossy(&body[..dump_len]);
        format!(
            "{}\n  response body hex ({} bytes): {}\n  response body utf8: {}",
            e,
            dump_len,
            hex_dump.join(" "),
            utf8_dump
        )
    })
}

fn find_header_body_boundary(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

fn extract_workspaces(val: &MsgValue) -> Vec<MSFWorkspaceInfo> {
    let mut workspaces = Vec::new();
    if let Some(map) = val.as_map() {
        if let Some(MsgValue::Array(ws_arr)) = map.get("workspaces") {
            for ws in ws_arr {
                if let Some(ws_map) = ws.as_map() {
                    let name = ws_map
                        .get("name")
                        .and_then(MsgValue::as_str)
                        .unwrap_or("")
                        .to_string();
                    let scope = ws_map
                        .get("scope")
                        .and_then(MsgValue::as_str)
                        .unwrap_or("")
                        .to_string();
                    let host_count = ws_map
                        .get("hosts_count")
                        .or_else(|| ws_map.get("host_count"))
                        .and_then(MsgValue::as_u64)
                        .unwrap_or(0);

                    workspaces.push(MSFWorkspaceInfo {
                        name,
                        scope,
                        host_count,
                    });
                }
            }
        }
    }
    workspaces
}

fn extract_hosts(val: &MsgValue) -> Vec<MSFHostInfo> {
    let mut hosts = Vec::new();
    if let Some(map) = val.as_map() {
        if let Some(MsgValue::Array(host_arr)) = map.get("hosts") {
            for host in host_arr {
                if let Some(host_map) = host.as_map() {
                    let address = host_map
                        .get("address")
                        .and_then(MsgValue::as_str)
                        .unwrap_or("")
                        .to_string();
                    let os_name = host_map
                        .get("os_name")
                        .and_then(MsgValue::as_str)
                        .unwrap_or("")
                        .to_string();
                    let os_flavor = host_map
                        .get("os_flavor")
                        .and_then(MsgValue::as_str)
                        .unwrap_or("")
                        .to_string();
                    let state = host_map
                        .get("state")
                        .and_then(MsgValue::as_str)
                        .unwrap_or("")
                        .to_string();
                    let notes_count = host_map
                        .get("notes_count")
                        .and_then(MsgValue::as_u64)
                        .unwrap_or(0);

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
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_of(pairs: &[(&str, MsgValue)]) -> MsgValue {
        MsgValue::Map(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        )
    }

    #[test]
    fn strips_type_prefix_from_various_forms() {
        assert_eq!(
            strip_type_prefix("auxiliary", "auxiliary/scanner/http/robots_txt"),
            "scanner/http/robots_txt"
        );
        assert_eq!(
            strip_type_prefix("exploit", "exploit/windows/smb/ms17_010_eternalblue"),
            "windows/smb/ms17_010_eternalblue"
        );
        // Already leaf-only: unchanged.
        assert_eq!(
            strip_type_prefix("auxiliary", "scanner/http/robots_txt"),
            "scanner/http/robots_txt"
        );
        // Wrong module_type but explicit prefix present: still stripped.
        assert_eq!(
            strip_type_prefix("post", "auxiliary/scanner/http/robots_txt"),
            "scanner/http/robots_txt"
        );
    }

    #[test]
    fn rebuilds_full_name() {
        assert_eq!(
            full_name("auxiliary", "scanner/http/robots_txt"),
            "auxiliary/scanner/http/robots_txt"
        );
        // Already prefixed: left alone.
        assert_eq!(
            full_name("exploit", "exploit/windows/smb/ms17_010_eternalblue"),
            "exploit/windows/smb/ms17_010_eternalblue"
        );
        // Unknown type: passthrough (no bogus prefix).
        assert_eq!(full_name("payload", "linux/x64/shell"), "linux/x64/shell");
    }

    #[test]
    fn extracts_module_list_from_array_form() {
        let val = map_of(&[(
            "modules",
            MsgValue::Array(vec![
                MsgValue::String("scanner/http/robots_txt".to_string()),
                MsgValue::String("scanner/http/apache_version".to_string()),
            ]),
        )]);
        let modules = extract_module_list(&val, "auxiliary");
        let names: Vec<&str> = modules.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "auxiliary/scanner/http/apache_version",
                "auxiliary/scanner/http/robots_txt"
            ]
        );
    }

    #[test]
    fn extracts_module_list_from_map_form() {
        let val = map_of(&[(
            "modules",
            MsgValue::Map(BTreeMap::from([
                ("scanner/http/robots_txt".to_string(), msg_str("desc")),
                ("scanner/ssh/ssh_version".to_string(), msg_str("desc")),
            ])),
        )]);
        let modules = extract_module_list(&val, "auxiliary");
        assert!(modules
            .iter()
            .any(|m| m.name == "auxiliary/scanner/http/robots_txt"));
        assert!(modules
            .iter()
            .any(|m| m.name == "auxiliary/scanner/ssh/ssh_version"));
    }

    #[test]
    fn extracts_module_names_without_modules_key() {
        // Some legacy servers return the name -> description hash directly.
        let val = MsgValue::Map(BTreeMap::from([(
            "scanner/http/robots_txt".to_string(),
            msg_str("description"),
        )]));
        let modules = extract_module_list(&val, "auxiliary");
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].name, "auxiliary/scanner/http/robots_txt");
    }

    #[test]
    fn response_error_detects_success_and_failure() {
        // No error key: success.
        assert!(response_error(&map_of(&[("result", msg_str("success"))])).is_none());
        // Bool false: success.
        assert!(response_error(&map_of(&[("error", MsgValue::Bool(false))])).is_none());
        // "error" => "success": success.
        assert!(response_error(&map_of(&[("error", msg_str("success"))])).is_none());
        // Bool true with message: failure.
        let err = map_of(&[
            ("error", MsgValue::Bool(true)),
            ("error_message", msg_str("Module not found")),
        ]);
        assert_eq!(response_error(&err).as_deref(), Some("Module not found"));
        // Int 0: success; nonzero: failure.
        assert!(response_error(&map_of(&[("error", MsgValue::Int(0))])).is_none());
        assert!(response_error(&map_of(&[("error", MsgValue::Int(1))])).is_some());
    }

    #[test]
    fn classifies_missing_vs_other_rpc_failures() {
        assert!(matches!(
            classify_lookup("Module not found"),
            AppError::RpcModuleNotFound(_)
        ));
        assert!(matches!(
            classify_lookup("The referenced module does not exist"),
            AppError::RpcModuleNotFound(_)
        ));
        assert!(matches!(
            classify_lookup("Missing module name"),
            AppError::RpcModuleNotFound(_)
        ));
        assert!(matches!(
            classify_lookup("Permission denied"),
            AppError::Rpc(_)
        ));
    }

    #[test]
    fn is_missing_module_detects_backtrace_and_message() {
        // The real payload MSF returns for a missing module: error_message
        // "Invalid Module" and a backtrace rooted at _find_module.
        let err = map_of(&[
            ("error", MsgValue::Bool(true)),
            ("error_string", msg_str("Msf::RPC::Exception")),
            (
                "error_backtrace",
                MsgValue::Array(vec![
                    msg_str("lib/msf/core/rpc/v10/rpc_module.rb:743:in 'Msf::RPC::RPC_Module#_find_module'"),
                    msg_str("lib/msf/core/rpc/v10/rpc_module.rb:218:in 'Msf::RPC::RPC_Module#rpc_info'"),
                ]),
            ),
            ("error_message", msg_str("Invalid Module")),
            ("error_code", MsgValue::Int(500)),
        ]);
        assert!(is_missing_module(&err));

        // Same payload without the backtrace but with an explicit message.
        let msg_only = map_of(&[
            ("error", MsgValue::Bool(true)),
            ("error_message", msg_str("Module not found")),
        ]);
        assert!(is_missing_module(&msg_only));

        // A genuine argument/transport failure must NOT look like a missing
        // module.
        let arg_err = map_of(&[
            ("error", MsgValue::Bool(true)),
            (
                "error_string",
                msg_str("wrong number of arguments (given 1, expected 2)"),
            ),
            (
                "error_message",
                msg_str("wrong number of arguments (given 1, expected 2)"),
            ),
        ]);
        assert!(!is_missing_module(&arg_err));
        assert!(looks_like_legacy_signature_error(&arg_err));

        // A modern-server module-not-found (no backtrace, but message only)
        // is also not an argument-shape error.
        assert!(!looks_like_legacy_signature_error(&msg_only));
    }

    #[test]
    fn legacy_fallback_only_triggers_on_argument_shape_errors() {
        // Simulate what a modern server returns for a missing module: the
        // modern-form error is classified as not-found and never falls back to
        // the legacy single-name signature.
        let decision = |err: &MsgValue| {
            if is_missing_module(err) {
                return "not-found".to_string();
            }
            if looks_like_legacy_signature_error(err) {
                return "legacy-retry".to_string();
            }
            "rpc-failure".to_string()
        };

        let modern_missing = map_of(&[
            ("error", MsgValue::Bool(true)),
            ("error_message", msg_str("Invalid Module")),
        ]);
        assert_eq!(decision(&modern_missing), "not-found");

        let modern_arg_error = map_of(&[
            ("error", MsgValue::Bool(true)),
            (
                "error_string",
                msg_str("wrong number of arguments (given 2, expected 1)"),
            ),
        ]);
        assert_eq!(decision(&modern_arg_error), "legacy-retry");

        let other = map_of(&[
            ("error", MsgValue::Bool(true)),
            ("error_string", msg_str("Permission denied")),
        ]);
        assert_eq!(decision(&other), "rpc-failure");
    }

    #[test]
    fn module_existence_decision_uses_classification() {
        // The pure decision used by module_exists: found when module.info
        // succeeds, missing when it reports not-found, error otherwise.
        let decision = |msg: Option<&str>| match msg {
            None => Ok(true),
            Some(m) if matches!(classify_lookup(m), AppError::RpcModuleNotFound(_)) => Ok(false),
            Some(_) => Err(AppError::Rpc(String::new())),
        };
        assert_eq!(decision(None).unwrap(), true);
        assert_eq!(decision(Some("Module not found")).unwrap(), false);
        assert!(decision(Some("Permission denied")).is_err());
    }
}
