//! The CLI must report failures through its exit status so scripts and CI
//! can tell a failed run from a successful one.

use std::process::{Command, Stdio};

fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ploit-malper"));
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn run(args: &[&str]) -> (i32, String) {
    let output = bin().args(args).output().expect("run ploit-malper");
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.code().unwrap_or(-1), text)
}

#[test]
fn process_without_an_input_file_fails() {
    let (code, text) = run(&["process"]);
    assert_eq!(code, 1, "expected a non-zero exit, got output:\n{text}");
    assert!(text.contains("No input file specified"), "{text}");
}

#[test]
fn process_with_a_missing_input_file_fails() {
    let (code, text) = run(&["process", "/nonexistent/ploit-malper-scan.json"]);
    assert_eq!(code, 1, "expected a non-zero exit, got output:\n{text}");
    assert!(text.contains("File not found"), "{text}");
}

#[test]
fn process_rejects_unknown_options_instead_of_using_them_as_paths() {
    let (code, text) = run(&["process", "--backend", "sqlite", "x.json"]);
    assert_eq!(code, 1, "expected a non-zero exit, got output:\n{text}");
    assert!(text.contains("unknown process option"), "{text}");
    assert!(!text.contains("File not found: sqlite"), "{text}");
}

#[test]
fn process_help_is_a_successful_request() {
    let (code, text) = run(&["process", "--help"]);
    assert_eq!(code, 0, "expected a zero exit, got output:\n{text}");
    assert!(text.contains("Usage:"), "{text}");
}

#[test]
fn unknown_command_fails() {
    let (code, text) = run(&["definitely-not-a-command"]);
    assert_eq!(code, 1, "expected a non-zero exit, got output:\n{text}");
    assert!(text.contains("Unknown command"), "{text}");
}
