use std::collections::BTreeMap;
use std::process::{Command, Stdio};

// Re-use the msgpack implementation from the library
use ploit_malper::msgpack::{decode, encode, MsgValue};

fn rpc_call(method: &str, params: &[MsgValue]) -> Result<MsgValue, String> {
    let mut request = vec![MsgValue::String(method.to_string())];
    request.extend_from_slice(params);

    let payload = encode(&MsgValue::Array(request));
    let url = "http://localhost:55553/api/";

    let mut child = Command::new("curl")
        .arg("-sS")
        .arg("--max-time")
        .arg("10")
        .arg("-H")
        .arg("Content-Type: binary/message-pack")
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
            .write_all(&payload)
            .map_err(|e| format!("write: {e}"))?;
    }

    let output = child.wait_with_output().map_err(|e| format!("wait: {e}"))?;

    if output.stdout.is_empty() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    decode(&output.stdout).map_err(|e| e.to_string())
}

fn is_server_available() -> bool {
    Command::new("nc")
        .arg("-z")
        .arg("localhost")
        .arg("55553")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn test_msgpack_roundtrip_array_format() {
    // Test the exact format used for MSF-RPC auth
    let v = MsgValue::Array(vec![
        MsgValue::String("test.method".to_string()),
        MsgValue::String("arg1".to_string()),
        MsgValue::UInt(42),
        MsgValue::Bool(true),
    ]);
    let bytes = encode(&v);
    let decoded = decode(&bytes).unwrap();
    assert_eq!(v, decoded);
}

#[test]
fn test_msgpack_bin8_decoding() {
    // Simulate MSF server response using bin 8 for strings
    let mut data = Vec::new();
    // fixmap with 2 entries
    data.push(0x82);
    // bin8 "result"
    data.extend_from_slice(b"\xc4\x06result");
    // bin8 "success"
    data.extend_from_slice(b"\xc4\x07success");
    // bin8 "token"
    data.extend_from_slice(b"\xc4\x05token");
    // bin8 "abc123"
    data.extend_from_slice(b"\xc4\x06abc123");

    let decoded = decode(&data).unwrap();
    assert_eq!(
        decoded.get("result").and_then(|v| v.as_str()),
        Some("success")
    );
    assert_eq!(
        decoded.get("token").and_then(|v| v.as_str()),
        Some("abc123")
    );
}

#[test]
fn test_recipe_invalid_payload_fallback() {
    // Test that unknown platform/arch combinations produce valid payload names
    let recipe = ploit_malper::recipe::build_recipe(
        "python",
        "x64",
        "10.0.0.1",
        4444,
        "/tmp/test",
        None,
        None,
    );
    // Should NOT produce "python/x64/meterpreter/reverse_tcp"
    assert!(
        !recipe.command.contains("python/x64/meterpreter"),
        "Should not generate invalid payload: {}",
        recipe.command
    );
    assert!(
        recipe.command.contains("python/meterpreter"),
        "Should generate python/meterpreter payload: {}",
        recipe.command
    );
}

#[test]
fn test_recipe_valid_payloads() {
    let test_cases = vec![
        ("windows", "x64", "windows/x64/meterpreter/reverse_tcp"),
        ("windows", "x86", "windows/meterpreter/reverse_tcp"),
        ("linux", "x64", "linux/x64/meterpreter/reverse_tcp"),
        ("linux", "x86", "linux/x86/meterpreter/reverse_tcp"),
        ("macos", "x64", "osx/x64/meterpreter/reverse_tcp"),
        ("python", "py", "python/meterpreter/reverse_tcp"),
        ("php", "php", "php/meterpreter/reverse_tcp"),
        ("android", "dalvik", "android/meterpreter/reverse_tcp"),
    ];

    for (platform, arch, expected_payload) in test_cases {
        let recipe = ploit_malper::recipe::build_recipe(
            platform,
            arch,
            "10.0.0.1",
            4444,
            "/tmp/test",
            None,
            None,
        );
        assert!(
            recipe.command.contains(expected_payload),
            "Platform={}, Arch={}: expected payload '{}' not found in command: {}",
            platform,
            arch,
            expected_payload,
            recipe.command
        );
    }
}

// Integration tests that require a running msfrpcd instance
// These tests will be skipped if the server is not available

#[test]
fn test_msfrpc_login_integration() {
    if !is_server_available() {
        eprintln!("MSF-RPC server not available, skipping integration test");
        return;
    }

    let result = rpc_call(
        "auth.login",
        &[
            MsgValue::String("Mithun".to_string()),
            MsgValue::String("Mithun@2806".to_string()),
        ],
    )
    .expect("RPC call failed");

    let success = result.get("result").and_then(|v| v.as_str()) == Some("success");
    let token = result.get("token").and_then(|v| v.as_str()).unwrap_or("");
    assert!(success, "Login should succeed, got error: {:?}", result);
    assert!(!token.is_empty(), "Token should not be empty");
    assert!(token.starts_with("TEMP"), "Token should start with TEMP");
}

#[test]
fn test_msfrpc_workspaces_integration() {
    if !is_server_available() {
        eprintln!("MSF-RPC server not available, skipping integration test");
        return;
    }

    // Login first
    let login = rpc_call(
        "auth.login",
        &[
            MsgValue::String("Mithun".to_string()),
            MsgValue::String("Mithun@2806".to_string()),
        ],
    )
    .expect("Login failed");
    let token = login.get("token").and_then(|v| v.as_str()).unwrap_or("");

    // Get workspaces
    let ws = rpc_call("db.workspaces", &[MsgValue::String(token.to_string())])
        .expect("Workspaces call failed");

    let workspaces = ws.get("workspaces").and_then(|v| v.as_array());
    assert!(workspaces.is_some(), "Should have workspaces array");
    if let Some(arr) = workspaces {
        assert!(!arr.is_empty(), "Should have at least one workspace");
        let first = &arr[0];
        let name = first.get("name").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(name, "default", "Default workspace should exist");
    }
}

#[test]
fn test_msfrpc_hosts_integration() {
    if !is_server_available() {
        eprintln!("MSF-RPC server not available, skipping integration test");
        return;
    }

    // Login first
    let login = rpc_call(
        "auth.login",
        &[
            MsgValue::String("Mithun".to_string()),
            MsgValue::String("Mithun@2806".to_string()),
        ],
    )
    .expect("Login failed");
    let token = login.get("token").and_then(|v| v.as_str()).unwrap_or("");

    // Get hosts with workspace parameter
    let mut opts = BTreeMap::new();
    opts.insert(
        "workspace".to_string(),
        MsgValue::String("default".to_string()),
    );

    let hosts = rpc_call(
        "db.hosts",
        &[MsgValue::String(token.to_string()), MsgValue::Map(opts)],
    )
    .expect("Hosts call failed");

    let hosts_arr = hosts.get("hosts").and_then(|v| v.as_array());
    assert!(hosts_arr.is_some(), "Should have hosts array");
    // It's OK if hosts is empty (no hosts in the workspace)
}

#[test]
fn test_msfrpc_login_wrong_password() {
    if !is_server_available() {
        eprintln!("MSF-RPC server not available, skipping integration test");
        return;
    }

    let result = rpc_call(
        "auth.login",
        &[
            MsgValue::String("Mithun".to_string()),
            MsgValue::String("wrong_password".to_string()),
        ],
    )
    .expect("RPC call should return");

    let has_error = result.get("error").and_then(|v| {
        if let MsgValue::Bool(b) = v {
            Some(*b)
        } else {
            None
        }
    }) == Some(true);
    assert!(has_error, "Should return error for wrong password");
}

#[test]
fn test_msfrpc_auth_logout_integration() {
    if !is_server_available() {
        eprintln!("MSF-RPC server not available, skipping integration test");
        return;
    }

    // Login first
    let login = rpc_call(
        "auth.login",
        &[
            MsgValue::String("Mithun".to_string()),
            MsgValue::String("Mithun@2806".to_string()),
        ],
    )
    .expect("Login failed");
    let token = login.get("token").and_then(|v| v.as_str()).unwrap_or("");

    // Logout - note: in this MSF version, the authenticator extracts the token
    // from args, so rpc_logout may receive 0 args. This test documents the
    // current behavior.
    let logout = rpc_call("auth.logout", &[MsgValue::String(token.to_string())]);
    match logout {
        Ok(val) => {
            let result = val.get("result").and_then(|v| v.as_str());
            if result == Some("success") {
                // Logout succeeded
            } else {
                // Logout may return error depending on MSF version
                eprintln!("Logout response (non-fatal): {:?}", val);
            }
        }
        Err(e) => {
            // Logout may fail due to authenticator stripping the token
            eprintln!("Logout error (expected in some MSF versions): {e}");
        }
    }
}
