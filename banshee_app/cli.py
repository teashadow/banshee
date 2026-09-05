"""CLI for banshee."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from .banner import BANSHEE_BANNER
from .pipeline import family_verdict, latest_summary, list_runs, run_target, shodan_host, shodan_search

console = Console()


def _banner() -> None:
    console.print(f"[bold magenta]{BANSHEE_BANNER}[/bold magenta]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """MAD recon pipeline."""


@main.command("run")
@click.argument("target")
@click.option("--quick", is_flag=True, help="Skip nuclei stage.")
@click.option("--program", default=None,
              help="🔴 scope-программа для гейта авторизации. Без неё скан НЕ запускается (fail-safe).")
def run_cmd(target: str, quick: bool, program: str | None) -> None:
    """Recon-конвейер (asset-discovery QA). 🔴 Только по in-scope целям — гейт periscope."""
    from .pipeline import ScopeBlocked
    try:
        run_dir = run_target(target, quick=quick, program=program)
    except ScopeBlocked as e:
        # 🔴 «нет» офенсив-инструмента: цель вне scope — не сканирую. rc 1 стоп.
        console.print(f"[red]СКАН ЗАПРЕЩЁН[/red]: {e}")
        raise SystemExit(1)
    console.print(f"[green]Completed[/green] {run_dir}")


@main.command("gate")
@click.argument("target")
@click.argument("program")
def gate_cmd(target: str, program: str) -> None:
    """Только проверить гейт scope (без скана): пустит ли banshee к этой цели."""
    from .pipeline import ScopeBlocked, scope_gate
    try:
        g = scope_gate(target, program)
    except ScopeBlocked as e:
        console.print(f"[red]ВНЕ SCOPE[/red]: {e}")
        raise SystemExit(1)
    console.print(f"[green]IN-SCOPE[/green]: {g['почему']}")
    raise SystemExit(0)


@main.command("shodan")
@click.argument("args", nargs=-1)
def shodan_cmd(args: tuple[str, ...]) -> None:
    """Search Shodan or inspect a host."""
    if not args:
        raise click.UsageError("provide a query or use 'banshee shodan host <ip>'")
    if args[0] == "host":
        if len(args) != 2:
            raise click.UsageError("usage: banshee shodan host <ip>")
        console.print_json(json.dumps(shodan_host(args[1])))
        return
    query = " ".join(args).strip()
    table = Table(title=f"Shodan Search: {query}")
    table.add_column("IP")
    table.add_column("Port")
    table.add_column("Org")
    table.add_column("Product")
    for item in shodan_search(query)["matches"]:
        table.add_row(str(item.get("ip_str", "")), str(item.get("port", "")), str(item.get("org", "")), str(item.get("product", "")))
    console.print(table)


@main.command("report")
@click.argument("target")
def report_cmd(target: str) -> None:
    """Show the latest summary for a target."""
    console.print(Markdown(latest_summary(target).read_text(encoding="utf-8")))


@main.command("verdict")
@click.argument("target")
def verdict_cmd(target: str) -> None:
    """Семейный вердикт последнего прогона: JSON + rc (0 чисто · 1 находки · 2 не состоялось)."""
    from .storage import latest_run_dir
    result = family_verdict(latest_run_dir(target))
    console.print_json(json.dumps(result, ensure_ascii=False))
    raise SystemExit(result["rc"])


@main.command("list")
def list_cmd() -> None:
    """List recon runs."""
    table = Table(title="Recon Runs")
    table.add_column("Target")
    table.add_column("Latest Run")
    table.add_column("Path")
    for row in list_runs():
        table.add_row(row["target"], row["latest_run"], row["path"])
    console.print(table)


if __name__ == "__main__":
    main()
