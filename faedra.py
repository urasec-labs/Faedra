#!/usr/bin/env python3
"""
Faedra Pro - Command Line Interface
Author: Uras AKAS | urasakas.com

Interactive numbered menu by default.
Subcommands still work for scripting: recon, full, modules, tools, dashboard...
"""

from __future__ import annotations
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.prompt import Prompt, Confirm

from core.config import load_config
from core.orchestrator import Orchestrator
from core.models import ScanJob
from core.report import generate_html_report, generate_pdf_report

app = typer.Typer(
    name="faedra",
    help="Faedra Pro — Professional Security Analysis Framework\nAuthor: Uras AKAS | urasakas.com",
    add_completion=False,
    invoke_without_command=True,
)
console = Console()


def banner():
    console.print(Panel.fit(
        "[bold red]FAEDRA PRO[/bold red]  v2.1\n"
        "[dim]Professional Security Analysis & Automation Framework[/dim]\n"
        "[cyan]Author: Uras AKAS | urasakas.com[/cyan]",
        border_style="red",
    ))


def show_menu():
    console.print()
    console.print(Panel.fit(
        "[bold]Ana Menü[/bold]\n\n"
        "[cyan]1[/cyan]  Hızlı Recon          [dim](quick profil)[/dim]\n"
        "[cyan]2[/cyan]  Bug Bounty Tarama    [dim](bugbounty profil)[/dim]\n"
        "[cyan]3[/cyan]  Derin Analiz         [dim](deep profil)[/dim]\n"
        "[cyan]4[/cyan]  Sürekli İzleme       [dim](monitor)[/dim]\n"
        "[cyan]5[/cyan]  Modülleri Listele\n"
        "[cyan]6[/cyan]  Dış Araç Durumu\n"
        "[cyan]7[/cyan]  Web Dashboard\n"
        "[cyan]8[/cyan]  Özel Modül Seçimi\n"
        "[cyan]0[/cyan]  Çıkış",
        title="[bold red]FAEDRA PRO[/bold red]",
        border_style="red",
    ))
    console.print()


def ask_target() -> str:
    while True:
        target = Prompt.ask("[bold]Hedef[/bold] (domain veya IP)").strip()
        if target:
            return target
        console.print("[red]Hedef boş olamaz.[/red]")


def ask_safe_mode() -> bool:
    return Confirm.ask("Safe Mode açık kalsın mı?", default=True)


def run_modules_list():
    orch = Orchestrator()
    table = Table(title="Available Modules", box=box.ROUNDED)
    table.add_column("#", style="dim", width=3)
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="dim")
    table.add_column("Active?", justify="center")
    table.add_column("Description")
    for i, name in enumerate(orch.list_modules(), 1):
        mod = orch.get_module(name)
        table.add_row(
            str(i),
            name,
            getattr(mod, "version", "?"),
            "Yes" if (mod and mod.is_active) else "No",
            mod.description if mod else "",
        )
    console.print(table)


def run_tools_status():
    from utils.tools import detect_all, TOOLS
    table = Table(title="External Tools", box=box.ROUNDED)
    table.add_column("Tool", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Description")
    status = detect_all()
    for name, desc in TOOLS.items():
        ok = status.get(name, False)
        table.add_row(name, "[green]OK[/green]" if ok else "[red]missing[/red]", desc)
    console.print(table)
    console.print("\n[dim]Eksik araçlar kurulu değilse ilgili adımlar atlanır.[/dim]")


def run_custom_modules():
    orch = Orchestrator()
    names = orch.list_modules()
    console.print("\n[bold]Modüller:[/bold]")
    for i, name in enumerate(names, 1):
        console.print(f"  [cyan]{i}[/cyan]  {name}")
    raw = Prompt.ask(
        "\nSeçim (virgülle; örn: 1,3,5) veya isim yaz",
        default="",
    ).strip()
    if not raw:
        console.print("[yellow]Seçim yapılmadı.[/yellow]")
        return
    selected = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if part.isdigit():
            idx = int(part) - 1
            if 0 <= idx < len(names):
                selected.append(names[idx])
        elif part in names:
            selected.append(part)
    if not selected:
        console.print("[red]Geçerli modül seçilmedi.[/red]")
        return
    target = ask_target()
    safe = ask_safe_mode()
    console.print(f"[dim]Seçilen modüller: {', '.join(selected)}[/dim]\n")
    asyncio.run(_run(target, profile="custom", safe=safe, module_names=selected))


def interactive_loop():
    banner()
    console.print(
        "[yellow]Uyarı:[/yellow] Sadece [bold]yetkili olduğun[/bold] sistemlerde kullan.\n"
    )
    while True:
        show_menu()
        choice = Prompt.ask(
            "[bold]Seçimin[/bold]",
            choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"],
            default="1",
        )

        if choice == "0":
            console.print("\n[green]Görüşürüz.[/green]")
            break

        if choice == "1":
            target = ask_target()
            safe = ask_safe_mode()
            asyncio.run(_run(target, profile="quick", safe=safe))

        elif choice == "2":
            target = ask_target()
            safe = ask_safe_mode()
            asyncio.run(_run(target, profile="bugbounty", safe=safe))

        elif choice == "3":
            target = ask_target()
            safe = ask_safe_mode()
            asyncio.run(_run(target, profile="deep", safe=safe))

        elif choice == "4":
            target = ask_target()
            hours = Prompt.ask("Kaç saatte bir taransın?", default="24")
            try:
                interval = max(1, int(hours))
            except ValueError:
                interval = 24
            console.print(f"[yellow]Monitor başlıyor ({interval}h). Durdurmak için Ctrl+C.[/yellow]\n")
            try:
                while True:
                    asyncio.run(_run(target, profile="monitor", safe=True))
                    console.print(f"\n[dim]{interval} saat bekleniyor...[/dim]\n")
                    import time
                    time.sleep(interval * 3600)
            except KeyboardInterrupt:
                console.print("\n[green]İzleme durduruldu.[/green]")

        elif choice == "5":
            run_modules_list()

        elif choice == "6":
            run_tools_status()

        elif choice == "7":
            console.print("[cyan]Dashboard açılıyor → http://127.0.0.1:8787[/cyan]")
            console.print("[dim]Durdurmak için Ctrl+C[/dim]\n")
            try:
                import dashboard as dash
                dash.main()
            except KeyboardInterrupt:
                console.print("\n[green]Dashboard kapatıldı.[/green]")

        elif choice == "8":
            run_custom_modules()

        if choice in {"1", "2", "3", "8"}:
            if not Confirm.ask("\nMenüye dönülsün mü?", default=True):
                console.print("\n[green]Görüşürüz.[/green]")
                break


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """Argümansız çalıştırılırsa interaktif menü açılır."""
    if ctx.invoked_subcommand is None:
        interactive_loop()


@app.command()
def recon(
    target: str = typer.Argument(..., help="Target domain or IP"),
    profile: str = typer.Option("quick", "--profile", "-p"),
    safe: bool = typer.Option(True, "--safe/--no-safe"),
):
    """Run a recon-oriented pipeline."""
    banner()
    asyncio.run(_run(target, profile=profile, safe=safe))


@app.command()
def full(
    target: str = typer.Argument(..., help="Target domain or IP"),
    profile: str = typer.Option("bugbounty", "--profile", "-p"),
    safe: bool = typer.Option(True, "--safe/--no-safe"),
    modules: Optional[str] = typer.Option(None, "--modules", "-m"),
):
    """Run a full authorized assessment pipeline."""
    banner()
    mod_list = [m.strip() for m in modules.split(",")] if modules else None
    asyncio.run(_run(target, profile=profile, safe=safe, module_names=mod_list))


@app.command()
def modules():
    """List available modules."""
    banner()
    run_modules_list()


@app.command()
def tools():
    """Show external tool availability."""
    banner()
    run_tools_status()


@app.command()
def monitor(
    target: str = typer.Argument(...),
    interval_hours: int = typer.Option(24, "--interval", "-i"),
):
    """Continuous monitoring mode."""
    banner()
    console.print(f"[yellow]Continuous mode for {target} (every {interval_hours}h)[/yellow]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")
    try:
        while True:
            asyncio.run(_run(target, profile="monitor", safe=True))
            console.print(f"\n[dim]Sleeping {interval_hours} hours...[/dim]\n")
            import time
            time.sleep(interval_hours * 3600)
    except KeyboardInterrupt:
        console.print("\n[green]Monitoring stopped.[/green]")


@app.command()
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8787, "--port"),
):
    """Start the local web dashboard."""
    banner()
    import dashboard as dash
    dash.HOST = host
    dash.PORT = port
    dash.main()


@app.command()
def version():
    """Show version info."""
    config = load_config()
    console.print(f"[bold]{config.app.name}[/bold] v{config.app.version}")
    console.print(f"Author: {config.app.author}")


@app.command(name="menu")
def menu_cmd():
    """Open interactive menu."""
    interactive_loop()


async def _run(
    target: str,
    profile: str = "quick",
    safe: bool = True,
    module_names: Optional[List[str]] = None,
):
    config = load_config()
    config.app.safe_mode = safe

    console.print(
        "[yellow]Reminder:[/yellow] Only scan systems you are [bold]authorized[/bold] to test.\n"
    )

    orch = Orchestrator(config)
    job: ScanJob = await orch.run_job(
        target=target,
        profile=profile,
        module_names=module_names,
        operator="Uras AKAS | urasakas.com",
    )

    _print_summary(job)
    _save_json(job)

    try:
        html_path = generate_html_report(job, config.paths.reports_dir)
        console.print(f"[green]HTML report:[/green] {html_path}")
    except Exception as e:
        console.print(f"[yellow]HTML report failed:[/yellow] {e}")

    try:
        pdf_path = generate_pdf_report(job, config.paths.reports_dir)
        if pdf_path:
            console.print(f"[green]PDF report:[/green]  {pdf_path}")
        else:
            console.print("[dim]PDF skipped (reportlab not installed)[/dim]")
    except Exception as e:
        console.print(f"[yellow]PDF report failed:[/yellow] {e}")


def _print_summary(job: ScanJob):
    console.print()
    table = Table(title="Scan Summary", box=box.DOUBLE_EDGE)
    table.add_column("Metric", style="bold")
    table.add_column("Value", style="green")
    s = job.summary
    table.add_row("Target", job.target)
    table.add_row("Profile", job.profile)
    table.add_row("Modules run", str(s.get("modules_run", 0)))
    table.add_row("Successful", str(s.get("successful_modules", 0)))
    table.add_row("Total assets", str(s.get("total_assets", 0)))
    table.add_row("Total findings", str(s.get("total_findings", 0)))
    sev = s.get("findings_by_severity", {})
    for k in ("critical", "high", "medium", "low", "info"):
        if k in sev:
            table.add_row(f"Findings ({k})", str(sev[k]))
    console.print(table)

    all_findings = []
    for r in job.results:
        all_findings.extend(r.findings)
    if all_findings:
        console.print("\n[bold]Top Findings[/bold]")
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        for f in sorted(all_findings, key=lambda x: order.get(x.severity.value, 9))[:12]:
            color = {
                "critical": "red", "high": "bright_red", "medium": "yellow",
                "low": "blue", "info": "dim",
            }.get(f.severity.value, "white")
            console.print(
                f"  [{color}][{f.severity.value.upper()}][/{color}] {f.title}  "
                f"[dim]({f.module} → {f.asset})[/dim]"
            )


def _save_json(job: ScanJob):
    reports_dir = Path("data/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = reports_dir / f"faedra_{job.target.replace('.', '_')}_{ts}.json"
    path.write_text(json.dumps(job.model_dump(), indent=2, default=str), encoding="utf-8")
    console.print(f"\n[green]JSON report:[/green] {path}")


if __name__ == "__main__":
    app()
