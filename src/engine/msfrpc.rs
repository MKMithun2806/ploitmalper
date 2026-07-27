use std::collections::BTreeMap;
use std::process::{Command, Stdio};

use crate::error::Result;
use crate::models::{
    MSFHostCheckResult, MSFHostInfo, MSFHostsResult, MSFLoginResult, MSFWorkspaceInfo,
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
        let payload = encode(&msg_array(vec![
            msg_str("db.workspaces"),
            msg_str(&token),
        ]));

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
}

fn build_url(host: &str, port: u16, ssl: bool) -> String {
    let scheme = if ssl { "https" } else { "http" };
    format!("{}://{}:{}/api/", scheme, host, port)
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
        stdin.write_all(payload).map_err(|e| format!("failed to write request body: {e}"))?;
    }

    let output = child.wait_with_output().map_err(|e| format!("curl wait failed: {e}"))?;

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
        let header_part = String::from_utf8_lossy(&stdout[..pos]);
        let status_line = header_part.lines().next().unwrap_or("unknown");
        eprintln!("[MSF-RPC] HTTP {status_line}");
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

fn msg_str(value: &str) -> MsgValue {
    MsgValue::String(value.to_string())
}

fn msg_array(values: Vec<MsgValue>) -> MsgValue {
    MsgValue::Array(values)
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
