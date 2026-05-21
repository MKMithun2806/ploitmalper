"""CLI entrypoint for PloitMalper."""

import sys
from rich.console import Console

console = Console()


def entrypoint() -> None:
    """Main CLI entry point."""
    from rich.panel import Panel

    console.print(
        Panel(
            "[bold cyan]PloitMalper v0.1.0[/bold cyan]\n"
            "[dim]Vulnerability Post-Processing and Analysis Toolkit[/dim]",
            border_style="cyan",
        )
    )
    console.print("[+] Engine initialized successfully.")
    console.print("[?] Run `ploit-malper --help` for available commands.")


if __name__ == "__main__":
    entrypoint()
