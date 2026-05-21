"""Full CLI with argument parsing, subcommands, and orchestration."""

import argparse
import json
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table

from ploit_malper.state.config import ConfigManager
from ploit_malper.state.nvd import NVDClient
from ploit_malper.cli.recipe import build_recipe, get_available_platforms, get_available_arches
from ploit_malper.share.server import start_file_server, stop_file_server
from ploit_malper.report.generator import (
    render_findings_table,
    render_module_table,
    generate_markdown_report,
)

console = Console()

try:
    from ploit_malper._core import (
        deduplicate_records,
        normalize_title_py,
        parse_vulnmalper_json,
        suggest_modules,
        suggest_from_title,
        get_all_known_banners,
        msf_login,
        msf_logout,
        msf_is_authenticated,
        msf_get_workspaces,
        msf_get_hosts,
        msf_check_host_exists,
    )
    HAS_RUST = True
except ImportError:
    HAS_RUST = False
    console.print("[!] Rust extension module not available. Some features will be limited.")


def setup_credentials(config_mgr: ConfigManager) -> None:
    console.print(Panel("[bold yellow]PloitMalper Configuration Setup[/bold yellow]", border_style="yellow"))

    console.print("\n[bold cyan]--- MSF-RPC Configuration ---[/bold cyan]")
    console.print("[?] Enter your Metasploit RPC server details.\n")

    host = Prompt.ask("  MSF-RPC Host", default=config_mgr.config.msfrpc.host)
    port = IntPrompt.ask("  MSF-RPC Port", default=config_mgr.config.msfrpc.port)
    username = Prompt.ask("  MSF-RPC Username", default=config_mgr.config.msfrpc.username)
    password = Prompt.ask("  MSF-RPC Password", password=True, default=config_mgr.config.msfrpc.password)
    ssl = Confirm.ask("  Use SSL?", default=config_mgr.config.msfrpc.ssl)
    workspace = Prompt.ask("  Workspace", default=config_mgr.config.msfrpc.workspace)

    config_mgr.config.msfrpc.host = host
    config_mgr.config.msfrpc.port = port
    config_mgr.config.msfrpc.username = username
    config_mgr.config.msfrpc.password = password
    config_mgr.config.msfrpc.ssl = ssl
    config_mgr.config.msfrpc.workspace = workspace

    console.print("\n[bold cyan]--- NVD API Configuration ---[/bold cyan]")
    console.print("[?] Enter your NVD API key for CVE enrichment (optional but recommended).")
    console.print("[?] Get one at: https://nvd.nist.gov/developers/request-an-api-key\n")

    nvd_key = Prompt.ask("  NVD API Key", default=config_mgr.config.nvd.api_key, password=True)
    config_mgr.config.nvd.api_key = nvd_key

    config_mgr.save()

    console.print("\n[+] Configuration saved to ~/.config/ploit_malper/config.json")


def cmd_process(args: argparse.Namespace, config_mgr: ConfigManager) -> None:
    if not args.input_file:
        console.print("[!] No input file specified. Use: ploit-malper process <scan.json>")
        return

    input_path = Path(args.input_file)
    if not input_path.exists():
        console.print(f"[!] File not found: {input_path}")
        return

    console.print(f"[+] Loading scan results from: {input_path}")
    raw_json = input_path.read_text(encoding="utf-8")

    if HAS_RUST:
        console.print("[+] Parsing with Rust engine...")
        parsed_json = parse_vulnmalper_json(raw_json)
        parsed: list[dict] = json.loads(parsed_json)

        console.print(f"[+] Found {len(parsed)} raw findings. Deduplicating...")
        dedup_json = deduplicate_records(parsed_json)
        dedup_result: dict = json.loads(dedup_json)
        records = dedup_result["records"]
        dedup_stats = {
            "total": len(parsed),
            "unique": dedup_result["unique_count"],
            "removed": dedup_result["removed_count"],
        }
    else:
        parsed = json.loads(raw_json)
        if isinstance(parsed, dict):
            parsed = parsed.get("results", parsed.get("findings", []))
        records = parsed
        dedup_stats = {"total": len(parsed), "unique": len(parsed), "removed": 0}

    console.print(f"[+] Deduplication complete: {dedup_stats['unique']} unique, {dedup_stats['removed']} removed\n")

    nvd_client: Optional[NVDClient] = None
    if config_mgr.is_nvd_configured():
        nvd_cfg = config_mgr.get_nvd_config()
        nvd_client = NVDClient(api_key=nvd_cfg.api_key)
        records = nvd_client.enrich_records(records)
        console.print("")

    table = render_findings_table(records)
    console.print(table)

    all_suggestions: list[dict] = []
    if HAS_RUST:
        console.print("\n[+] Analyzing service banners and titles for module suggestions...")
        for record in records:
            service = record.get("service", "")
            title = record.get("title", "")
            if service:
                sug_json = suggest_modules(service)
                sugs: list[dict] = json.loads(sug_json)
                all_suggestions.extend(sugs)
            if title:
                sug_json = suggest_from_title(title, "")
                sugs: list[dict] = json.loads(sug_json)
                for sug in sugs:
                    if sug not in all_suggestions:
                        all_suggestions.append(sug)

        if all_suggestions:
            mod_table = render_module_table(all_suggestions)
            console.print(mod_table)
        else:
            console.print("[?] No module suggestions for detected services.")

    msf_connected = False
    if config_mgr.is_configured() and HAS_RUST:
        console.print("\n[+] Connecting to MSF-RPC for workspace verification...")
        msf_cfg = config_mgr.get_msfrpc_config()
        login_json = msf_login(
            msf_cfg.host,
            msf_cfg.port,
            msf_cfg.username,
            msf_cfg.password,
            msf_cfg.ssl,
        )
        login_result: dict = json.loads(login_json)

        if login_result.get("success"):
            msf_connected = True
            console.print(f"[+] Authenticated to MSF-RPC at {msf_cfg.host}:{msf_cfg.port}")

            ws_json = msf_get_workspaces()
            ws_result: dict = json.loads(ws_json)
            workspaces = ws_result.get("workspaces", [])
            if workspaces:
                ws_table = Table(title="[bold cyan]MSF Workspaces[/bold cyan]", border_style="cyan")
                ws_table.add_column("Name", style="green")
                ws_table.add_column("Scope", style="yellow")
                ws_table.add_column("Hosts", style="cyan")
                for ws in workspaces:
                    ws_table.add_row(ws.get("name", "unknown"), ws.get("scope", "—"), str(ws.get("host_count", 0)))
                console.print(ws_table)

            for record in records[:5]:
                target = record.get("target", "")
                if target:
                    check_json = msf_check_host_exists(target, msf_cfg.workspace)
                    check_result: dict = json.loads(check_json)
                    if check_result.get("exists"):
                        console.print(f"[?] Host {target} already exists in workspace '{msf_cfg.workspace}'")
        else:
            err = login_result.get("error", "Unknown error")
            console.print(f"[yellow][!] Remote MSF-RPC unreachable. Switched entirely to offline matching matrix.[/yellow]")
            console.print(f"[dim]   Error: {err}[/dim]")

    recipes = []
    if Confirm.ask("\n[?] Generate msfvenom payload recipes?", default=False):
        console.print("\n[bold yellow]Payload Recipe Builder[/bold yellow]\n")
        platforms = get_available_platforms()
        console.print("Available platforms: " + ", ".join(platforms))
        platform = Prompt.ask("  Platform", choices=platforms, default="windows")
        arches = get_available_arches(platform)
        console.print("Available architectures: " + ", ".join(arches))
        arch = Prompt.ask("  Architecture", choices=arches, default="x64")
        lhost = Prompt.ask("  LHOST", default="10.0.0.1")
        lport = IntPrompt.ask("  LPORT", default=4444)
        output = Prompt.ask("  Output path", default="/tmp/payload")

        recipe = build_recipe(platform, arch, lhost, lport, output)
        recipes = [json.loads(json.dumps(recipe.__dict__))]

        console.print(f"\n[+] Generated recipe:\n")
        console.print(Panel(
            f"[bold green]{recipe.command}[/bold green]",
            title="msfvenom Command",
            border_style="green",
        ))

    if Confirm.ask("\n[?] Write findings to Markdown report (report.md)?", default=True):
        output_path = generate_markdown_report(
            records=records,
            suggestions=all_suggestions,
            recipes=recipes,
            dedup_stats=dedup_stats,
        )
        console.print(f"\n[+] Report written to: {output_path}")

    if msf_connected and HAS_RUST:
        msf_logout()

    config_mgr.config.last_scan_file = str(input_path)
    config_mgr.save()


def cmd_share(args: argparse.Namespace) -> None:
    directory = args.directory or str(Path.cwd())
    port = args.port or 8888

    console.print(f"[+] Starting file server in: {directory}")
    console.print(f"[+] Port: {port}\n")

    try:
        server, actual_port = start_file_server(directory, port)
        console.print(Panel(
            f"[bold green]File server running at http://0.0.0.0:{actual_port}[/bold green]\n"
            f"[dim]Press Ctrl+C to stop[/dim]",
            border_style="green",
        ))

        import time
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[+] Shutting down file server...")
            stop_file_server(server)
    except RuntimeError as e:
        console.print(f"[!] {e}")


def cmd_reset_config(args: argparse.Namespace, config_mgr: ConfigManager) -> None:
    console.print("[?] Resetting all stored configuration...")
    config_mgr.reset()
    console.print("[+] Configuration reset. Run ploit-malper to set up credentials.")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ploit-malper",
        description="PloitMalper — Vulnerability Post-Processing and Analysis Toolkit",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    process_parser = subparsers.add_parser("process", help="Process and deduplicate scan results")
    process_parser.add_argument("input_file", nargs="?", help="Path to VulnMalper JSON scan file")

    share_parser = subparsers.add_parser("share", help="Start temporary file server for reports")
    share_parser.add_argument("--directory", "-d", help="Directory to serve", default=None)
    share_parser.add_argument("--port", "-p", type=int, help="Port to listen on", default=None)

    subparsers.add_parser("reset-config", help="Reset stored credentials and NVD cache")

    subparsers.add_parser("setup", help="Configure MSF-RPC and NVD API credentials interactively")

    args = parser.parse_args()

    config_mgr = ConfigManager()
    config_loaded = config_mgr.load()

    if args.command == "reset-config":
        cmd_reset_config(args, config_mgr)
        return

    if args.command == "setup":
        setup_credentials(config_mgr)
        return

    if args.command == "share":
        cmd_share(args)
        return

    if args.command == "process":
        if not config_loaded or not config_mgr.is_configured():
            console.print("[?] No MSF-RPC configuration found.")
            if Confirm.ask("  Configure MSF-RPC and NVD API now?", default=True):
                setup_credentials(config_mgr)
            else:
                console.print("[?] Continuing without MSF-RPC integration.\n")
        cmd_process(args, config_mgr)
        return

    console.print(
        Panel(
            "[bold cyan]PloitMalper v0.1.0[/bold cyan]\n"
            "[dim]Vulnerability Post-Processing and Analysis Toolkit[/dim]\n\n"
            "[bold]Commands:[/bold]\n"
            "  [green]process <file>[/green]   Process and deduplicate scan results\n"
            "  [green]share[/green]            Start temporary file server\n"
            "  [green]setup[/green]            Configure MSF-RPC and NVD API credentials\n"
            "  [green]reset-config[/green]     Reset stored configuration",
            border_style="cyan",
        )
    )
