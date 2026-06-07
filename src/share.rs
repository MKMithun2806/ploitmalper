use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::error::{AppError, Result};

pub struct FileServerHandle {
    shutdown: Arc<AtomicBool>,
    thread: thread::JoinHandle<()>,
    port: u16,
}

pub fn find_free_port(start_port: u16) -> Result<u16> {
    for port in start_port..start_port.saturating_add(100) {
        if TcpListener::bind(("0.0.0.0", port)).is_ok() {
            return Ok(port);
        }
    }
    Err(AppError::Message("No free port found in range".to_string()))
}

pub fn start_file_server(
    directory: impl Into<PathBuf>,
    port: u16,
) -> Result<(FileServerHandle, u16)> {
    let directory = directory.into();
    let actual_port = find_free_port(port)?;
    let listener = TcpListener::bind(("0.0.0.0", actual_port))?;
    listener.set_nonblocking(true)?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_thread = Arc::clone(&shutdown);
    let thread_directory = directory.clone();

    let thread = thread::spawn(move || {
        while !shutdown_thread.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = handle_client(&mut stream, &thread_directory);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
    });

    Ok((
        FileServerHandle {
            shutdown,
            thread,
            port: actual_port,
        },
        actual_port,
    ))
}

pub fn stop_file_server(server: FileServerHandle) {
    server.shutdown.store(true, Ordering::Relaxed);
    let _ = TcpStream::connect(("127.0.0.1", server.port));
    let _ = server.thread.join();
}

fn handle_client(stream: &mut TcpStream, directory: &Path) -> Result<()> {
    let mut buffer = [0u8; 8192];
    let size = stream.read(&mut buffer)?;
    if size == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..size]);
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or("/").split('?').next().unwrap_or("/");

    if method != "GET" {
        write_response(
            stream,
            405,
            "Method Not Allowed",
            "Only GET is supported",
            "text/plain",
        )?;
        return Ok(());
    }

    if path == "/" || path.is_empty() {
        let body = directory_listing(directory)?;
        write_response(stream, 200, "OK", &body, "text/html; charset=utf-8")?;
        return Ok(());
    }

    let requested = sanitize_path(directory, path);
    match requested {
        Some(file_path) if file_path.is_file() => {
            let data = fs::read(&file_path)?;
            let content_type = guess_mime(&file_path);
            write_binary_response(stream, 200, "OK", &data, content_type)?;
        }
        Some(file_path) if file_path.is_dir() => {
            let body = directory_listing(&file_path)?;
            write_response(stream, 200, "OK", &body, "text/html; charset=utf-8")?;
        }
        _ => {
            write_response(stream, 404, "Not Found", "File not found", "text/plain")?;
        }
    }

    Ok(())
}

fn sanitize_path(base: &Path, request_path: &str) -> Option<PathBuf> {
    let mut relative = PathBuf::new();
    for component in Path::new(request_path).components() {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    Some(base.join(relative))
}

fn directory_listing(directory: &Path) -> Result<String> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_name = entry.file_name().to_string_lossy().to_string();
        let file_type = entry.file_type()?;
        let suffix = if file_type.is_dir() { "/" } else { "" };
        entries.push(format!(
            "<li><a href=\"{name}{suffix}\">{name}{suffix}</a></li>",
            name = html_escape(&file_name),
            suffix = suffix
        ));
    }
    entries.sort();

    Ok(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>PloitMalper Share</title></head><body><h1>PloitMalper Share</h1><ul>{}</ul></body></html>",
        entries.join("\n")
    ))
}

fn guess_mime(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
    content_type: &str,
) -> Result<()> {
    let bytes = body.as_bytes();
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        reason,
        content_type,
        bytes.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}

fn write_binary_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
    content_type: &str,
) -> Result<()> {
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        reason,
        content_type,
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
