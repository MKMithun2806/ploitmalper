"""Local file server for sharing reports across lab instances."""

import os
import threading
import socket
from http.server import HTTPServer, SimpleHTTPRequestHandler
from rich.console import Console

console = Console()


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        console.print(f"  [dim]{format % args}[/dim]")

    def log_request(self, code: str = "-", size: str = "-") -> None:
        pass


def find_free_port(start_port: int = 8888) -> int:
    port = start_port
    while port < start_port + 100:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("0.0.0.0", port))
                return port
            except OSError:
                port += 1
    raise RuntimeError("No free port found in range")


def start_file_server(directory: str, port: int = 8888) -> tuple[HTTPServer, int]:
    os.chdir(directory)
    actual_port = find_free_port(port)
    server = HTTPServer(("0.0.0.0", actual_port), QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, actual_port


def stop_file_server(server: HTTPServer) -> None:
    server.shutdown()
