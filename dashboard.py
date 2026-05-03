import sys
import os
import time
import random
import threading
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
import database
from config import REFRESH_INTERVAL, LOG_COLORS, SEVERITY_ORDER


console = Console(theme=None, force_terminal=True)


def style_text(text, bold=False):
    prefix = "[bold]" if bold else ""
    suffix = "[/bold]" if bold else ""
    return f"{prefix}[green]{text}[/green]{suffix}"


MATRIX_CHARS = "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEF"


def matrix_rain(duration=2):
    columns = console.width if hasattr(console, 'width') else 80
    lines = [" "] * (console.height - 2 if hasattr(console, 'height') else 24)

    for _ in range(duration * 20):
        col = random.randint(0, columns - 1)
        char = random.choice(MATRIX_CHARS)

        for i in range(len(lines)):
            if random.random() < 0.3:
                lines[i] = lines[i][:col] + char + lines[i][col+1:]

        console.clear()
        for line in lines:
            console.print(line, end="")
        time.sleep(0.05)


def show_loading_sequence():
    print()

    steps = [
        ("INITIALIZING SOC PROTOCOLS...", "cyan"),
        ("LOADING THREAT DATABASES...", "yellow"),
        ("ACTIVATING NETWORK MONITORS...", "green"),
        ("ENABLING VIRUSTOTAL API...", "magenta"),
        ("CONNECTING TO LOG STREAMS...", "cyan"),
    ]

    print()

    colors = {"cyan": "\033[96m", "yellow": "\033[93m", "green": "\033[92m", "magenta": "\033[95m"}
    reset = "\033[0m"

    for i, (step, color) in enumerate(steps):
        progress = "[%s]" % ("=" * (i + 1) + " " * (len(steps) - i - 1))
        print(f"{colors[color]}{progress} {step}{reset}")
        time.sleep(0.4)

    print()
    print(f"{colors['cyan']}========================================={reset}")
    print(f"{colors['green']}  SYSTEM READY - MONITORING ACTIVE     {reset}")
    print(f"{colors['cyan']}========================================={reset}")
    print()

    time.sleep(1)


def create_header():
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = Text(f">>> SOC DASHBOARD - LIVE MONITOR | {current_time} <<<", justify="center", style="bold cyan")
    return Panel(title, style="cyan", padding=(0, 1))


def create_alerts_panel(alerts):
    table = Table(show_header=True, header_style="bold cyan", box=None)
    table.add_column("Time", style="cyan", width=18)
    table.add_column("Type", style="yellow", width=15)
    table.add_column("IP", style="green", width=15)
    table.add_column("Severity", width=10)
    table.add_column("Details", style="white")

    for alert in alerts:
        severity = alert[4]
        color = LOG_COLORS.get(severity, "yellow")

        severity_text = Text(severity, style=f"bold {color}", justify="center")
        details = alert[5] if alert[5] else ""

        table.add_row(
            Text(alert[1][:19], style="cyan"),
            Text(alert[2], style="yellow"),
            Text(alert[3] or "-", style="green"),
            severity_text,
            Text(details[:50], style="white")
        )

    return Panel(table, title="[bold cyan]>>> LIVE ALERTS <<<[/bold cyan]", border_style="cyan", padding=(1, 1))


def create_stats_panel(stats):
    table = Table(box=None, padding=0)
    table.add_column("Metric", style="cyan", justify="left")
    table.add_column("Value", style="yellow", justify="right")

    table.add_row(Text("Total Alerts Today", style="bold white"), Text(str(stats["total_today"]), style="bold yellow"))

    for severity, count in stats["by_severity"].items():
        color = LOG_COLORS.get(severity, "yellow")
        table.add_row(f"  {severity}", Text(str(count), style=color))

    for threat_type, count in stats["by_type"].items():
        table.add_row(Text(f"  {threat_type}", style="white"), Text(str(count), style="yellow"))

    if stats["top_ips"]:
        table.add_row("", "")
        table.add_row("[bold cyan]Top Attacking IPs[/bold cyan]", "")
        for ip, count in stats["top_ips"]:
            table.add_row(Text(f"  {ip}", style="green"), Text(str(count), style="red"))

    return Panel(table, title="[bold cyan]>>> STATISTICS <<<[/bold cyan]", border_style="cyan", padding=(1, 1))


def create_logs_panel(logs):
    if not logs:
        return Panel("[dim cyan]Waiting for logs...[/dim cyan]", title="[bold cyan]>>> LIVE LOG MONITOR <<<[/bold cyan]", border_style="cyan")

    lines = []
    for log in logs:
        timestamp = log[0][:19]
        source = os.path.basename(log[1]) if log[1] else "log"
        raw = log[2][:60]

        if "Failed" in raw or "failed" in raw:
            color = "red"
        elif "Accepted" in raw or "success" in raw:
            color = "green"
        else:
            color = "white"

        lines.append(f"[cyan]{timestamp}[/cyan] [[yellow]{source}[/yellow]] [{color}]{raw}[/{color}]")

    return Panel("\n".join(lines), title="[bold cyan]>>> LIVE LOG MONITOR <<<[/bold cyan] [green](scanning)[/green]", border_style="cyan", padding=(1, 1))


def run_live_dashboard(stop_event):
    while not stop_event.is_set():
        try:
            alerts = database.get_alerts(limit=15)
            alerts_sorted = sorted(alerts, key=lambda x: SEVERITY_ORDER.get(x[4], 99))
            stats = database.get_alert_stats()
            logs = database.get_recent_logs(10)

            console.clear()
            console.print(create_header())
            console.print("[bold green]>>> MONITORING ACTIVE <<<[/bold green] | [cyan]Watching:[/cyan] [yellow]sample.log[/yellow], [yellow]auth.log[/yellow], [yellow]syslog[/yellow]")
            console.print()
            console.print(create_alerts_panel(alerts_sorted))
            console.print(create_stats_panel(stats))
            console.print(create_logs_panel(logs))
            console.print("[dim cyan]Press Ctrl+C to return to menu...[/dim cyan]")

            time.sleep(REFRESH_INTERVAL)

        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(REFRESH_INTERVAL)


def display_alerts(alerts):
    table = Table(title="[cyan]>>> ALERTS FOUND <<<[/cyan]", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="magenta", width=5)
    table.add_column("Timestamp", style="cyan", width=18)
    table.add_column("Type", style="yellow", width=15)
    table.add_column("IP", style="green", width=15)
    table.add_column("Severity", width=12)
    table.add_column("Details", style="white")
    table.add_column("Resolved", width=8, style="dim")

    for alert in alerts:
        severity = alert[4]
        color = LOG_COLORS.get(severity, "yellow")
        severity_text = Text(severity, style=f"bold {color}")

        resolved = Text("YES" if alert[6] else "NO", style="green" if alert[6] else "red")

        table.add_row(
            Text(str(alert[0]), style="magenta"),
            Text(alert[1][:19], style="cyan"),
            Text(alert[2], style="yellow"),
            Text(alert[3] or "-", style="green"),
            severity_text,
            Text(alert[5][:50] if alert[5] else "", style="white"),
            resolved
        )

    console.print(table)


def print_menu():
    print("\n\033[96m=========================================\033[0m")
    print("\033[96m          \033[93mSOC DASHBOARD MENU\033[96m             \033[0m")
    print("\033[96m=========================================\033[0m")
    print("  \033[91m[\033[93m1\033[91m]\033[0m \033[92mStart live monitoring\033[0m")
    print("  \033[91m[\033[93m2\033[91m]\033[0m \033[96mView all alerts (filterable)\033[0m")
    print("  \033[91m[\033[93m3\033[91m]\033[0m \033[95mAnalyse a .pcap file\033[0m")
    print("  \033[91m[\033[93m4\033[91m]\033[0m \033[94mExport PDF report\033[0m")
    print("  \033[91m[\033[93m5\033[91m]\033[0m \033[91mMark alert as resolved\033[0m")
    print("  \033[91m[\033[93m6\033[91m]\033[0m \033[90mExit\033[0m")
    print()