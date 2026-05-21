"""Rich table rendering and Markdown report generation."""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()


def _cvss_label(score: Optional[float]) -> str:
    if score is None:
        return "—"
    if score >= 9.0:
        return f"[bold red]{score:.1f}[/bold red]"
    if score >= 7.0:
        return f"[red]{score:.1f}[/red]"
    if score >= 4.0:
        return f"[yellow]{score:.1f}[/yellow]"
    if score > 0:
        return f"[green]{score:.1f}[/green]"
    return f"[dim]{score:.1f}[/dim]"


def render_findings_table(records: list[dict]) -> Table:
    has_nvd = any(r.get("nvd_cvss_v3") is not None for r in records)

    table = Table(
        title="[bold cyan]Deduplicated Vulnerability Findings[/bold cyan]",
        border_style="cyan",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Target", style="green", width=18)
    table.add_column("Tool", style="yellow", width=10)
    table.add_column("Title", style="white", width=35)
    table.add_column("Severity", style="red", width=10)
    table.add_column("Port", style="dim", width=6)
    table.add_column("CVE", style="cyan", width=16)
    if has_nvd:
        table.add_column("CVSS v3", style="white", width=8)

    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "info": "dim white",
        "unknown": "dim",
    }

    for idx, record in enumerate(records, 1):
        sev = record.get("severity", "unknown").lower()
        sev_style = severity_colors.get(sev, "dim")
        row = [
            str(idx),
            record.get("target", "N/A"),
            record.get("tool", "N/A"),
            record.get("title", "N/A")[:33],
            f"[{sev_style}]{sev.upper()}[/{sev_style}]",
            str(record.get("port", "")),
            record.get("cve", "") or "—",
        ]
        if has_nvd:
            row.append(_cvss_label(record.get("nvd_cvss_v3")))
        table.add_row(*row)

    return table


def render_module_table(suggestions: list[dict]) -> Table:
    table = Table(
        title="[bold cyan]Metasploit Module Suggestions[/bold cyan]",
        border_style="cyan",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Service Banner", style="green", width=20)
    table.add_column("Suggested Module", style="yellow", width=50)
    table.add_column("Confidence", style="cyan", width=12)

    for sug in suggestions:
        table.add_row(
            sug.get("service_banner", "N/A"),
            sug.get("suggested_module", "N/A"),
            f"[bold cyan]{sug.get('confidence', 'N/A').upper()}[/bold cyan]",
        )

    return table


def generate_markdown_report(
    records: list[dict],
    suggestions: list[dict],
    recipes: list[dict],
    dedup_stats: dict,
    output_path: str = "report.md",
) -> str:
    lines: list[str] = []
    has_nvd = any(r.get("nvd_cvss_v3") is not None for r in records)

    lines.append("# PloitMalper — Vulnerability Analysis Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Tool Version:** 0.1.0")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Total records processed:** {dedup_stats.get('total', 0)}")
    lines.append(f"- **Unique findings:** {dedup_stats.get('unique', 0)}")
    lines.append(f"- **Duplicates removed:** {dedup_stats.get('removed', 0)}")
    if has_nvd:
        lines.append(f"- **NVD enrichment:** Enabled")
    lines.append("")

    severity_counts: dict[str, int] = {}
    for r in records:
        sev = r.get("severity", "unknown").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines.append("### Severity Distribution")
    lines.append("")
    for sev in ["critical", "high", "medium", "low", "info", "unknown"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            lines.append(f"- **{sev.upper()}:** {count}")
    lines.append("")

    lines.append("## Findings")
    lines.append("")

    if has_nvd:
        lines.append("| # | Target | Tool | Title | Severity | Port | CVE | CVSS v3 | NVD Severity |")
        lines.append("|---|--------|------|-------|----------|------|-----|---------|--------------|")
        for idx, record in enumerate(records, 1):
            cvss = record.get("nvd_cvss_v3")
            cvss_str = f"{cvss:.1f}" if cvss is not None else "—"
            nvd_sev = (record.get("nvd_cvss_v3_severity") or "—").upper()
            lines.append(
                f"| {idx} "
                f"| {record.get('target', 'N/A')} "
                f"| {record.get('tool', 'N/A')} "
                f"| {record.get('title', 'N/A')} "
                f"| {record.get('severity', 'unknown').upper()} "
                f"| {record.get('port', '—')} "
                f"| {record.get('cve', '—') or '—'} "
                f"| {cvss_str} "
                f"| {nvd_sev} |"
            )
    else:
        lines.append("| # | Target | Tool | Title | Severity | Port | CVE |")
        lines.append("|---|--------|------|-------|----------|------|-----|")
        for idx, record in enumerate(records, 1):
            lines.append(
                f"| {idx} "
                f"| {record.get('target', 'N/A')} "
                f"| {record.get('tool', 'N/A')} "
                f"| {record.get('title', 'N/A')} "
                f"| {record.get('severity', 'unknown').upper()} "
                f"| {record.get('port', '—')} "
                f"| {record.get('cve', '—') or '—'} |"
            )

    lines.append("")

    if has_nvd:
        lines.append("## CVE Details (NVD)")
        lines.append("")
        for record in records:
            cve = record.get("cve")
            if not cve:
                continue
            desc = record.get("nvd_description", "")
            cvss = record.get("nvd_cvss_v3")
            nvd_sev = record.get("nvd_cvss_v3_severity", "")
            published = record.get("nvd_published", "")
            refs = record.get("nvd_references", [])

            lines.append(f"### {cve}")
            lines.append("")
            if cvss is not None:
                lines.append(f"- **CVSS v3 Score:** {cvss:.1f}")
            if nvd_sev:
                lines.append(f"- **NVD Severity:** {nvd_sev.upper()}")
            if published:
                lines.append(f"- **Published:** {published}")
            if desc:
                lines.append(f"- **Description:** {desc}")
            if refs:
                lines.append(f"- **References:**")
                for ref in refs:
                    lines.append(f"  - {ref}")
            lines.append("")

    if suggestions:
        lines.append("## Metasploit Module Suggestions")
        lines.append("")
        lines.append("| Service Banner | Suggested Module | Confidence |")
        lines.append("|---------------|------------------|------------|")
        for sug in suggestions:
            lines.append(
                f"| {sug.get('service_banner', 'N/A')} "
                f"| `{sug.get('suggested_module', 'N/A')}` "
                f"| {sug.get('confidence', 'N/A').upper()} |"
            )
        lines.append("")

    if recipes:
        lines.append("## Payload Command Recipes")
        lines.append("")
        for recipe in recipes:
            lines.append(f"### {recipe.get('platform', 'unknown').title()} / {recipe.get('architecture', 'unknown').title()}")
            lines.append("")
            lines.append(f"- **LHOST:** {recipe.get('lhost')}")
            lines.append(f"- **LPORT:** {recipe.get('lport')}")
            lines.append(f"- **Format:** {recipe.get('format')}")
            lines.append(f"- **Output:** {recipe.get('output_path')}")
            lines.append("")
            lines.append("```bash")
            lines.append(recipe.get("command", ""))
            lines.append("```")
            lines.append("")

    lines.append("---")
    lines.append("*Report generated by PloitMalper v0.1.0*")
    lines.append("")

    content = "\n".join(lines)
    Path(output_path).write_text(content, encoding="utf-8")
    return output_path
