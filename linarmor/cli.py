"""
LinArmor CLI — Command Line Interface

Provides terminal-based access to LinArmor functionality.

Usage:
    linarmor --web                    # Start web UI
    linarmor scan -t 192.168.1.100    # CLI-only scan
    linarmor --update-db              # Update CVE database
    linarmor report --format json     # Generate report
"""

from __future__ import annotations

import sys
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@click.group(invoke_without_command=True)
@click.option("--web", is_flag=True, help="Start the web UI server")
@click.option("--host", default="0.0.0.0", help="Web server host")
@click.option("--port", default=5000, type=int, help="Web server port")
@click.option("--update-db", is_flag=True, help="Update the CVE database")
@click.option("--version", is_flag=True, help="Show version")
@click.pass_context
def main(ctx, web, host, port, update_db, version):
    """🛡️ LinArmor — Linux Security Misconfiguration Discovery Framework"""
    if version:
        console.print("[bold cyan]LinArmor[/] v1.0.0")
        return

    if update_db:
        _update_database()
        return

    if web:
        _start_web(host, port)
        return

    # If no command given, show help
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
@click.option("-t", "--target", required=True, help="Target IP address")
@click.option("--type", "scan_type", default="full",
              type=click.Choice(["full", "quick", "custom"]), help="Scan type")
@click.option("-p", "--ports", default=None, help="Port range (e.g., 1-1000)")
@click.option("-m", "--modules", default=None, help="Comma-separated module list")
@click.option("-o", "--output", default=None, help="Output report file path")
@click.option("--format", "report_format", default="json",
              type=click.Choice(["json", "html"]), help="Report format")
def scan(target, scan_type, ports, modules, output, report_format):
    """Run a security scan against a target."""
    from linarmor.core.engine import ScanEngine
    from linarmor.modules.ssh import SSHModule
    from linarmor.modules.services import ServicesModule
    from linarmor.modules.kernel import KernelModule
    from linarmor.modules.credentials import CredentialsModule
    from linarmor.modules.docker import DockerModule
    from linarmor.modules.nfs import NFSModule
    from linarmor.modules.samba import SambaModule
    from linarmor.modules.sensitive_files import SensitiveFilesModule
    from linarmor.modules.suid import SUIDModule
    from linarmor.modules.permissions import PermissionsModule
    from linarmor.modules.cron import CronModule
    from linarmor.reporting.generators import JSONReporter, HTMLReporter

    console.print(Panel.fit(
        f"[bold cyan]🛡️ LinArmor[/] — Scanning [bold]{target}[/]",
        border_style="cyan"
    ))

    # CLI log callback with rich formatting
    def cli_log(level: str, message: str):
        level_styles = {
            "info": "[blue]INFO[/]",
            "warn": "[yellow]WARN[/]",
            "error": "[red]CRIT[/]",
            "success": "[green] OK [/]",
        }
        style = level_styles.get(level, "[dim]LOG[/]")
        console.print(f"  {style}  {message}")

    # Create and configure engine
    engine = ScanEngine(log_callback=cli_log)

    # Register modules
    all_modules = {
        "ssh": SSHModule(log_callback=cli_log),
        "services": ServicesModule(log_callback=cli_log),
        "kernel": KernelModule(log_callback=cli_log),
        "credentials": CredentialsModule(log_callback=cli_log),
        "docker": DockerModule(log_callback=cli_log),
        "nfs": NFSModule(log_callback=cli_log),
        "samba": SambaModule(log_callback=cli_log),
        "sensitive_files": SensitiveFilesModule(log_callback=cli_log),
        "suid": SUIDModule(log_callback=cli_log),
        "permissions": PermissionsModule(log_callback=cli_log),
        "cron": CronModule(log_callback=cli_log),
    }
    for name, module in all_modules.items():
        engine.register_module(name, module)

    # Parse modules list
    module_list = modules.split(",") if modules else None

    # Configure
    engine.configure(
        ip=target,
        scan_type=scan_type,
        port_range=ports,
        modules=module_list,
    )

    # Run scan (blocking in CLI mode)
    console.print()
    engine.start()

    # Wait for completion
    import time
    while engine.is_running:
        time.sleep(1)

    # Display results
    target_obj = engine.get_target()
    if target_obj:
        console.print()
        _display_results(target_obj)

        # Generate report
        if report_format == "json":
            reporter = JSONReporter()
        else:
            reporter = HTMLReporter()

        from pathlib import Path
        output_path = Path(output) if output else None
        report_path = reporter.generate(target_obj, output_path)
        console.print(f"\n  [bold green]Report saved:[/] {report_path}\n")


@main.command()
@click.option("--format", "report_format", default="json",
              type=click.Choice(["json", "html"]), help="Report format")
@click.option("-o", "--output", default=None, help="Output file path")
def report(report_format, output):
    """Generate a report from the last scan."""
    console.print("[yellow]Use the 'scan' command with --format to generate reports.[/]")


def _start_web(host: str, port: int) -> None:
    """Start the web UI server."""
    try:
        from linarmor.app import run_server
        run_server(host=host, port=port)
    except ImportError as e:
        console.print(f"[red]Error:[/] Could not start web server: {e}")
        console.print("[yellow]Install Flask dependencies: pip install flask flask-socketio[/]")
        sys.exit(1)


def _update_database() -> None:
    """Update the CVE database from NVD."""
    from linarmor.cve.database import CVEDatabase
    from linarmor.cve.updater import NVDUpdater

    def log_cb(level, msg):
        level_styles = {
            "info": "[blue]INFO[/]",
            "warn": "[yellow]WARN[/]",
            "error": "[red]ERROR[/]",
            "success": "[green] OK [/]",
        }
        style = level_styles.get(level, "[dim]LOG[/]")
        console.print(f"  {style}  {msg}")

    console.print(Panel.fit(
        "[bold cyan]🛡️ LinArmor[/] — Updating CVE Database",
        border_style="cyan"
    ))

    db = CVEDatabase()
    updater = NVDUpdater(db=db, log_callback=log_cb)
    stats = updater.update()

    console.print(f"\n  [bold green]Update complete:[/] {stats}")


def _display_results(target) -> None:
    """Display scan results in a rich table."""
    # Summary
    counts = target.severity_counts
    summary = Table(title="📊 Findings Summary", show_header=True, border_style="dim")
    summary.add_column("Severity", style="bold")
    summary.add_column("Count", justify="center")

    severity_styles = {
        "critical": "bold red",
        "high": "bold yellow",
        "medium": "yellow",
        "low": "green",
        "info": "cyan",
    }

    for sev, count in counts.items():
        style = severity_styles.get(sev, "")
        summary.add_row(sev.upper(), str(count), style=style)

    summary.add_row("TOTAL", str(target.total_findings), style="bold white")
    console.print(summary)

    # Findings table
    if target.findings:
        console.print()
        findings_table = Table(title="⚠️ Security Findings", show_header=True, border_style="dim")
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("Finding", max_width=50)
        findings_table.add_column("Module", width=15)
        findings_table.add_column("CVE", width=16)
        findings_table.add_column("CVSS", width=6, justify="center")

        for f in sorted(target.findings, key=lambda x: x.cvss_score, reverse=True):
            style = severity_styles.get(f.severity.value, "")
            findings_table.add_row(
                f.severity.value.upper(),
                f.title[:50],
                f.module,
                f.cve_id or "—",
                str(f.cvss_score),
                style=style,
            )

        console.print(findings_table)


if __name__ == "__main__":
    main()
