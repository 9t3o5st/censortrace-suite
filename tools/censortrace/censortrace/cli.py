"""CensorTrace v2 — Typer/Rich CLI (async core).

Commands:
  scan      full concurrent scan (all probes) with live progress + rich tables
  probe     run one or more named probes
  probes    list the registered plugin modules
  legacy    invoke the original v0.2 argparse tool (kept for compatibility)

Exit code reflects severity: 0 clean, 1 degraded/warn, 2 interference detected.
"""

from __future__ import annotations

import asyncio
import json
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                           TimeElapsedColumn)
from rich.table import Table
from rich.text import Text

from . import __version__, config
from .config import ProbeConfig
from .core import POSITIVE_VERDICTS, Verdict, all_probes
from .report import run_scan, write_reports

app = typer.Typer(
    name="censortrace",
    help="CensorTrace v2 — asynchronous, plugin-based censorship diagnostics "
         "(Iran NIN heuristics built in).",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

VERDICT_STYLE = {
    Verdict.PASS: "bold green",
    Verdict.WARN: "yellow",
    Verdict.DEGRADED: "yellow",
    Verdict.BLOCKED: "bold red",
    Verdict.POISONED: "bold magenta",
    Verdict.THROTTLED: "red",
    Verdict.SKIPPED: "dim",
    Verdict.ERROR: "cyan",
}


def _load_probes() -> None:
    """Import every module in censortrace.probes so @register runs."""
    import importlib
    import pkgutil
    from . import probes as probes_pkg
    for m in pkgutil.iter_modules(probes_pkg.__path__):
        if m.name.startswith("_"):
            continue
        importlib.import_module(f"censortrace.probes.{m.name}")


def _render_results(results) -> Table:
    table = Table(title="Probe results", expand=False, header_style="bold")
    table.add_column("probe", style="cyan", no_wrap=True)
    table.add_column("verdict", no_wrap=True)
    table.add_column("ms", justify="right")
    table.add_column("findings", justify="right")
    table.add_column("headline")
    for r in results:
        verdict = Text(r.verdict.value.upper(), style=VERDICT_STYLE.get(r.verdict, ""))
        headline = (r.findings[0].message[:90] if r.findings
                    else (r.error or "no findings"))
        table.add_row(r.probe, verdict, f"{r.elapsed_ms:.0f}",
                      str(len(r.findings)), headline)
    return table


def _summary_panel(report: dict) -> Panel:
    s = report["summary"]
    colour = "red" if s["positives"] else "green"
    body = (f"[{colour}]overall: {s['overall']}[/]  \n"
            f"probes: {s['probes_run']}   positives: {s['positives']}   "
            f"duration: {report.get('scan_duration_s', '?')}s\n"
            f"vantage: AS {report['vantage_point'].get('autonomous_system_number', '?')}"
            f" / {report['vantage_point'].get('country_code', '?').upper()}"
            f" -> target [cyan]{report['target']['domain']}[/]")
    return Panel(body, title="CensorTrace summary", border_style=colour)


async def _execute(domain: str, names: Optional[list[str]], out_prefix: Optional[str],
                   formats: tuple[str, ...], concurrency: int, port: int,
                   verbose: bool) -> int:
    _load_probes()
    registry = all_probes()
    selected = names or sorted(registry)
    unknown = [n for n in selected if n not in registry]
    if unknown:
        console.print(f"[red]unknown probe(s): {', '.join(unknown)}[/] "
                      f"(available: {', '.join(sorted(registry))})")
        raise typer.Exit(2)

    cfg = ProbeConfig(domain=domain, tls_port=port, max_concurrency=concurrency)

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )
    done_tasks: dict[str, object] = {}

    def on_start(p) -> None:
        tid = progress.add_task(f"[cyan]{p.name:<8}[/] {p.description[:52]}",
                                total=len(selected))

    def on_done(p, res) -> None:
        # advance the bar for this probe's task by matching description prefix
        for t in progress.tasks:
            if t.description.startswith(f"[cyan]{p.name:<8}[/]"):
                progress.advance(t)
                break
        if verbose:
            style = VERDICT_STYLE.get(res.verdict, "")
            for f in res.findings:
                console.print(f"  [{style}]{p.name}[/{style}] "
                              f"[dim]{f.indicator} ({f.severity})[/] {f.message}")

    with progress:
        results, report = await run_scan(cfg, selected, on_start, on_done)

    console.print()
    console.print(_render_results(results))
    console.print(_summary_panel(report))

    high = [r for r in results if r.verdict in POSITIVE_VERDICTS]
    if out_prefix:
        paths = write_reports(report, out_prefix, formats)
        console.print(f"[green]reports written:[/] {', '.join(paths)}")
    elif "--json" in []:  # pragma: no cover
        console.print_json(json.dumps(report))

    if any(f.severity == "high" for r in results for f in r.findings):
        return 2
    if high:
        return 2
    if any(r.verdict in (Verdict.WARN, Verdict.DEGRADED, Verdict.ERROR)
           for r in results):
        return 1
    return 0


@app.command()
def scan(
    domain: str = typer.Option("youtube.com", "--domain", "-d",
                               help="Target domain to measure."),
    probes: Optional[list[str]] = typer.Option(None, "--probe", "-p",
                                               help="Run only these probes (repeatable)."),
    output: Optional[str] = typer.Option(None, "--output", "-o",
                                         help="Report path prefix (writes .json/.yaml)."),
    yaml_out: bool = typer.Option(True, "--yaml/--no-yaml"),
    concurrency: int = typer.Option(12, "--concurrency", "-c"),
    port: int = typer.Option(443, "--tls-port"),
    verbose: bool = typer.Option(False, "--verbose", "-v",
                                 help="Stream findings live."),
    version: bool = typer.Option(False, "--version", help="Show version and exit."),
) -> None:
    """Run the concurrent censorship scan."""
    if version:
        console.print(f"CensorTrace {__version__}")
        raise typer.Exit()
    formats = ("json", "yaml") if yaml_out else ("json",)
    code = asyncio.run(_execute(domain, probes, output, formats, concurrency,
                                port, verbose))
    raise typer.Exit(code)


@app.command()
def probe(
    names: list[str] = typer.Argument(..., help="Probe names to run."),
    domain: str = typer.Option("youtube.com", "--domain", "-d"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run specific probes (e.g. `censortrace probe ech quic`)."""
    code = asyncio.run(_execute(domain, names, output, ("json",), 12, 443, verbose))
    raise typer.Exit(code)


@app.command()
def list_probes() -> None:
    """Show the plugin registry."""
    _load_probes()
    table = Table(title="Registered probes")
    table.add_column("name", style="cyan")
    table.add_column("description")
    for name, cls in sorted(all_probes().items()):
        table.add_row(name, cls.description)
    console.print(table)


@app.command()
def legacy(
    args: list[str] = typer.Argument(None, help="Passed through to v0.2 script."),
) -> None:
    """Invoke the original argparse-based censortrace.py unchanged."""
    import subprocess
    import sys
    from pathlib import Path
    script = Path(__file__).resolve().parent.parent / "censortrace.py"
    if not script.exists():
        console.print(f"[red]legacy script not found:[/] {script}")
        raise typer.Exit(2)
    subprocess.run([sys.executable, str(script), *(args or [])])


def main() -> None:  # entry point for pyproject scripts
    app()


if __name__ == "__main__":
    main()
