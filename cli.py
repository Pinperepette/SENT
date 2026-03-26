#!/usr/bin/env python3
"""
CLI interface for SENT — Supply chain ENTry point analysis.

Commands:
  watch     — Start polling for new releases (daemon mode)
  analyze   — Analyze a specific package version
  top       — Show top risky packages from DB
  inspect   — Show full diff report for a package
  poll      — Run a single polling cycle
"""

import json
import sys
from pathlib import Path

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent))

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich import print as rprint

from storage import db as store

console = Console()


@click.group()
def main():
    """SENT — Supply chain security analysis system."""
    pass


@main.command()
@click.option("--pypi", "-p", type=int, default=150, help="Number of top PyPI packages")
@click.option("--npm", "-n", type=int, default=50, help="Number of top npm packages")
def bootstrap(pypi, npm):
    """Seed the dependency graph with top packages (run once)."""
    store.init_db()
    from graph.bootstrap import bootstrap_graph
    bootstrap_graph(pypi_top=pypi, npm_top=npm)


@main.command()
@click.argument("filepath")
@click.option("--no-transitive", is_flag=True, help="Only direct deps, skip transitive resolution")
def sbom(filepath, no_transitive):
    """Import your SBOM (requirements.txt, package.json) and boost those packages."""
    store.init_db()
    from graph.sbom import import_sbom
    import_sbom(filepath, resolve_transitive=not no_transitive)


@main.command()
@click.option("--ecosystem", "-e", type=click.Choice(["pypi", "npm", "wordpress", "all"]), default="all")
@click.option("--interval", "-i", type=int, default=None, help="Poll interval in seconds")
@click.option("--threshold", "-t", type=float, default=None, help="Score threshold override")
@click.option("--sbom-file", type=click.Path(exists=True), default=None, help="SBOM file to boost (requirements.txt, package.json)")
def watch(ecosystem, interval, threshold, sbom_file):
    """Start polling for new releases and analyzing them."""
    import config
    if interval:
        config.POLL_INTERVAL = interval
    if threshold:
        config.SCORE_THRESHOLD = threshold

    if sbom_file:
        store.init_db()
        from graph.sbom import import_sbom
        import_sbom(sbom_file)

    from main import run_daemon
    ecosystems = None if ecosystem == "all" else [ecosystem]
    run_daemon(ecosystems)


@main.command()
@click.argument("package_name")
@click.option("--ecosystem", "-e", type=click.Choice(["pypi", "npm", "wordpress"]), default="pypi")
@click.option("--version", "-v", default="", help="Version to analyze (default: latest)")
@click.option("--old-version", "-o", default="", help="Previous version (default: auto-detect)")
@click.option("--ai-backend", "-a",
              type=click.Choice(["auto", "claude-code", "api", "rules"]),
              default="auto",
              help="AI backend: claude-code (CLI), api (Anthropic), rules (no AI), auto")
@click.option("--dyana", is_flag=True, default=False,
              help="Run dynamic analysis via dyana sandbox (requires Docker)")
def analyze(package_name, ecosystem, version, old_version, ai_backend, dyana):
    """Analyze a specific package version diff."""
    from main import analyze_single

    with console.status(f"Analyzing {ecosystem}/{package_name}..."):
        report = analyze_single(package_name, ecosystem, version, old_version,
                                ai_backend=ai_backend)

    _print_report(report.to_dict())

    if dyana:
        from analysis.detonator import detonate, dyana_available, docker_running
        if not dyana_available():
            console.print("[red]dyana not installed. Run: pip install dyana[/red]")
            return
        console.print(f"\n[bold]Dynamic analysis (dyana sandbox):[/bold]")
        ver = version or (report.version if hasattr(report, 'version') else "")
        dr = detonate(package_name, ver)
        if dr.success:
            if dr.network_activity:
                console.print(f"  [blue]Network ({len(dr.network_activity)}):[/blue]")
                for line in dr.network_activity[:10]:
                    console.print(f"    {line}")
            if dr.filesystem_activity:
                console.print(f"  [yellow]Filesystem ({len(dr.filesystem_activity)}):[/yellow]")
                for line in dr.filesystem_activity[:10]:
                    console.print(f"    {line}")
            if dr.security_events:
                console.print(f"  [red]Security ({len(dr.security_events)}):[/red]")
                for line in dr.security_events[:10]:
                    console.print(f"    {line}")
            if not (dr.network_activity or dr.filesystem_activity or dr.security_events):
                console.print("  [green]No suspicious runtime behavior detected.[/green]")
        else:
            console.print(f"  [red]{dr.error}[/red]")


@main.command()
@click.option("--limit", "-n", type=int, default=20)
def top(limit):
    """Show top risky packages from analysis history."""
    store.init_db()
    results = store.get_top_risky(limit)

    if not results:
        console.print("[dim]No analysis results yet. Run 'analyze' or 'watch' first.[/dim]")
        return

    table = Table(title="Top Risky Packages", show_lines=True)
    table.add_column("Score", style="bold red", width=6, justify="right")
    table.add_column("Package", style="bold")
    table.add_column("Eco", width=5)
    table.add_column("Version", width=20)
    table.add_column("Flags", width=6, justify="right")
    table.add_column("AI", width=12)
    table.add_column("Summary", max_width=50)

    for r in results:
        score = r["risk_score"]
        style = "red" if score >= 80 else "yellow" if score >= 30 else "green"
        ai = r.get("ai_classification", "")
        ai_style = {"malicious": "bold red", "suspicious": "yellow", "benign": "green"}.get(ai, "dim")

        table.add_row(
            f"[{style}]{score}[/{style}]",
            r["package"],
            r["ecosystem"],
            f"{r.get('previous_version', '?')} → {r['version']}",
            str(len(r.get("flags", []))),
            f"[{ai_style}]{ai or '-'}[/{ai_style}]",
            r.get("summary", "")[:50],
        )

    console.print(table)


@main.command()
@click.argument("package_name")
@click.option("--ecosystem", "-e", type=click.Choice(["pypi", "npm", "wordpress"]), default="pypi")
@click.option("--version", "-v", default="", help="Specific version (default: latest report)")
@click.option("--json-output", "-j", is_flag=True, help="Output raw JSON")
def inspect(package_name, ecosystem, version, json_output):
    """Show full diff report for a package."""
    store.init_db()
    report = store.get_report(package_name, ecosystem, version)

    if not report:
        console.print(f"[red]No report found for {ecosystem}/{package_name}[/red]")
        console.print("Run: sent analyze <package> first")
        return

    if json_output:
        click.echo(json.dumps(report, indent=2))
        return

    _print_report(report)


@main.command()
@click.option("--ecosystem", "-e", type=click.Choice(["pypi", "npm", "wordpress", "all"]), default="all")
@click.option("--threshold", "-t", type=float, default=None, help="Score threshold (default: 8.0, use 0 to analyze all)")
def poll(ecosystem, threshold):
    """Run a single polling cycle."""
    if threshold is not None:
        import config
        config.SCORE_THRESHOLD = threshold
    store.init_db()
    from graph.dependency_graph import graph
    graph.load_from_db()
    console.print(f"[dim]Graph: {graph.total_packages()} packages, {graph.total_edges()} edges[/dim]")
    from main import poll_once
    ecosystems = None if ecosystem == "all" else [ecosystem]
    poll_once(ecosystems)


@main.command()
def metrics():
    """Show runtime metrics (queue, workers, cache). Reads from DB — works from any terminal."""
    store.init_db()
    from main import load_metrics_from_db

    m = load_metrics_from_db()
    if not m:
        console.print("[dim]No metrics yet. Start monitoring with: sent watch -t 8 -i 30[/dim]")
        return

    table = Table(title="Runtime Metrics", show_lines=True)
    table.add_column("Category", style="bold")
    table.add_column("Metric")
    table.add_column("Value", justify="right")

    table.add_row("Queue", "Enqueued", str(m.get("queue_enqueued", 0)))
    table.add_row("Queue", "Dropped (backpressure)", str(m.get("queue_dropped", 0)))
    table.add_row("Queue", "Processed", str(m.get("queue_processed", 0)))
    table.add_row("Queue", "Peak size", str(m.get("queue_peak", 0)))
    table.add_row("Queue", "Avg wait", f"{m.get('queue_avg_wait_ms', 0)} ms")
    table.add_row("Workers", "Analyzed", str(m.get("workers_analyzed", 0)))
    table.add_row("Workers", "Failed", str(m.get("workers_failed", 0)))
    table.add_row("Workers", "Avg total time", f"{m.get('workers_avg_ms', 0)} ms")
    cache_bytes = m.get("cache_bytes_saved", 0)
    hit_rate = m.get("cache_hit_rate", 0)
    table.add_row("Cache", "Hits", str(m.get("cache_hits", 0)))
    table.add_row("Cache", "Misses", str(m.get("cache_misses", 0)))
    table.add_row("Cache", "Hit rate", f"{hit_rate:.0%}")
    table.add_row("Cache", "Bytes saved", f"{cache_bytes / 1024 / 1024:.1f} MB")

    updated = m.get("updated_at", "")
    console.print(table)
    if updated:
        console.print(f"[dim]Last updated: {updated}[/dim]")


def _print_report(report: dict):
    """Pretty-print a diff report."""
    score = report["risk_score"]
    score_color = "red" if score >= 80 else "yellow" if score >= 30 else "green"

    # Header
    console.print(Panel(
        f"[bold]{report['package']}[/bold] ({report['ecosystem']})\n"
        f"Version: {report.get('previous_version', '?')} → {report['version']}\n"
        f"Risk Score: [{score_color}][bold]{score}[/bold][/{score_color}]\n"
        f"AI Classification: {report.get('ai_classification', 'N/A')}\n"
        f"Timestamp: {report.get('timestamp', '')}",
        title="Diff Report",
    ))

    # File changes
    added = report.get("files_added", [])
    removed = report.get("files_removed", [])
    modified = report.get("files_modified", [])

    if added or removed or modified:
        console.print("\n[bold]File Changes:[/bold]")
        for f in added[:15]:
            console.print(f"  [green]+ {f}[/green]")
        for f in removed[:15]:
            console.print(f"  [red]- {f}[/red]")
        for f in modified[:15]:
            console.print(f"  [yellow]~ {f}[/yellow]")
        total = len(added) + len(removed) + len(modified)
        if total > 45:
            console.print(f"  [dim]... and {total - 45} more files[/dim]")

    # Flags
    flags = report.get("flags", [])
    if flags:
        console.print(f"\n[bold]Suspicious Patterns ({len(flags)}):[/bold]")

        # Group by category
        by_cat: dict[str, list] = {}
        for f in flags:
            cat = f.get("category", "unknown")
            by_cat.setdefault(cat, []).append(f)

        cat_colors = {
            "execution": "red",
            "obfuscation": "magenta",
            "network": "blue",
            "sensitive": "red bold",
            "supply_chain": "yellow",
        }

        for cat, cat_flags in sorted(by_cat.items(), key=lambda x: -sum(f["score"] for f in x[1])):
            color = cat_colors.get(cat, "white")
            total_score = sum(f["score"] for f in cat_flags)
            console.print(f"\n  [{color}]{cat.upper()}[/{color}] ({len(cat_flags)} hits, +{total_score} points)")

            for f in cat_flags[:10]:
                console.print(
                    f"    [{color}]{f['pattern']}[/{color}] "
                    f"[dim]{f['file']}:{f['line']}[/dim]"
                )
                console.print(f"      {f['snippet'][:120]}")

            if len(cat_flags) > 10:
                console.print(f"    [dim]... and {len(cat_flags) - 10} more[/dim]")
    else:
        console.print("\n[green]No suspicious patterns detected.[/green]")

    # Behavioral features (new pipeline)
    features = report.get("features")
    if features:
        nz = {k: v for k, v in features.items() if v and v != 0 and v != 0.0}
        if nz:
            console.print(f"\n[bold]Behavioral Features:[/bold]")
            for k, v in sorted(nz.items()):
                console.print(f"  {k}: [cyan]{v}[/cyan]")

    # Anomalies (baseline comparison)
    anomalies = report.get("anomalies")
    if anomalies and anomalies.get("anomaly_count", 0) > 0:
        console.print(f"\n[bold]Baseline Anomalies ({anomalies['anomaly_count']}):[/bold]")
        for key in ("new_network", "new_exec", "new_env_access", "new_subprocess",
                     "new_file_io", "new_obfuscation", "new_dynamic_attrs"):
            if anomalies.get(key):
                console.print(f"  [red bold]NEW BEHAVIOR:[/red bold] {key.replace('new_', '')}")
        novel = anomalies.get("novel_imports", [])
        if novel:
            console.print(f"  [red]Novel imports:[/red] {', '.join(novel[:10])}")

    # Scoring explanations
    explanations = report.get("scoring_explanations")
    if explanations:
        console.print(f"\n[bold]Score Breakdown:[/bold]")
        for exp in explanations:
            if "COMBO" in exp:
                console.print(f"  [red]{exp}[/red]")
            elif "ANOMALY" in exp:
                console.print(f"  [yellow]{exp}[/yellow]")
            else:
                console.print(f"  [dim]{exp}[/dim]")

    # Summary
    summary = report.get("summary", "")
    if summary:
        console.print(f"\n[bold]Summary:[/bold] {summary}")


if __name__ == "__main__":
    main()
