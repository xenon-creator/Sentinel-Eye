import os
import sys
import time
import threading
from rich.console import Console
from database import init_db, get_alerts, resolve_alert
from dashboard import run_live_dashboard, display_alerts, print_menu, show_loading_sequence
from monitor import start_monitoring, stop_monitoring
from network import analyze_pcap_file
from report import generate_pdf_report
from config import VIRUSTOTAL_API_KEY


console = Console()
monitor = None
stop_event = threading.Event()


def quick_loading(steps):
    print()
    for i, step in enumerate(steps):
        progress = "[%s]" % ("=" * (i + 1) + " " * (len(steps) - i - 1))
        print(f"\033[93m{progress} {step}\033[0m")
        time.sleep(0.3)
    print()


def view_alerts_menu():
    print("\n  FILTER OPTIONS:")
    print("  \033[91m[\033[93m1\033[91m]\033[0m \033[92mAll alerts\033[0m")
    print("  \033[91m[\033[93m2\033[91m]\033[0m \033[91mCRITICAL only\033[0m")
    print("  \033[91m[\033[93m3\033[91m]\033[0m \033[93mHIGH only\033[0m")
    print("  \033[91m[\033[93m4\033[91m]\033[0m \033[96mMEDIUM only\033[0m")
    print("  \033[91m[\033[93m5\033[91m]\033[0m \033[92mLOW only\033[0m")

    choice = console.input("\nSelect filter [1-5]: ").strip()

    severity_map = {"1": None, "2": "CRITICAL", "3": "HIGH", "4": "MEDIUM", "5": "LOW"}
    severity = severity_map.get(choice)

    quick_loading(["LOADING ALERTS DATABASE...", "FETCHING RECORDS...", "ANALYZING DATA..."])

    alerts = get_alerts(severity=severity, limit=100)

    if not alerts:
        console.print("[yellow]No alerts found.[/yellow]")
    else:
        display_alerts(alerts)


def analyze_pcap_menu():
    filepath = console.input("\nEnter path to .pcap file: ").strip()

    if not os.path.exists(filepath):
        console.print(f"[red]File not found: {filepath}[/red]")
        return

    quick_loading(["LOADING PCAP FILE...", "PARSING PACKETS...", "ANALYZING THREATS...", "CHECKING IP REPUTATION..."])
    result = analyze_pcap_file(filepath)

    if "error" in result:
        console.print(f"[red]Error: {result['error']}[/red]")
    else:
        console.print(f"[green]Analysis complete![/green]")
        console.print(f"  Packets: {result['packets']}")
        console.print(f"  Unique IPs: {result['unique_ips']}")
        console.print(f"  Alerts created: {result['alerts_created']}")


def export_pdf_menu():
    quick_loading(["COMPILING ALERT DATA...", "GENERATING STATISTICS...", "BUILDING PDF REPORT...", "APPLYING STYLES..."])
    try:
        filepath = generate_pdf_report()
        console.print(f"[green]Report saved to: {filepath}[/green]")
    except Exception as e:
        console.print(f"[red]Error generating report: {e}[/red]")


def resolve_alert_menu():
    quick_loading(["LOADING ALERT DATABASE...", "VERIFYING ALERT ID..."])
    try:
        alert_id = int(console.input("\nEnter alert ID to resolve: ").strip())
        resolve_alert(alert_id)
        console.print(f"[green]Alert {alert_id} marked as resolved.[/green]")
    except ValueError:
        console.print("[red]Invalid alert ID.[/red]")


def start_live_monitoring():
    global monitor, stop_event

    if monitor:
        console.print("[yellow]Monitoring already running.[/yellow]")
        return

    if not VIRUSTOTAL_API_KEY:
        console.print("[yellow]Warning: VIRUSTOTAL_API_KEY not set. IP reputation checks disabled.[/yellow]")

    console.print("[cyan]Starting live monitoring...[/cyan]\n")
    show_loading_sequence()

    monitor = start_monitoring()
    stop_event.clear()

    try:
        run_live_dashboard(stop_event)
    except KeyboardInterrupt:
        pass
    finally:
        if monitor:
            stop_monitoring(monitor)
            monitor = None


def main():
    init_db()

    console.clear()
    print()
    print("\033[93m=========================================\033[0m")
    print("\033[93m    Sentinel SOC Dashboard v1.0          \033[0m")
    print("\033[93m=========================================\033[0m")

    startup_steps = [
        "INITIALIZING DATABASE...",
        "LOADING CONFIGURATION...",
        "STARTING SERVICES...",
        "READY TO MONITOR"
    ]
    print()
    for i, step in enumerate(startup_steps):
        progress = "[%s]" % ("=" * (i + 1) + " " * (len(startup_steps) - i - 1))
        print(f"\033[93m{progress} {step}\033[0m")
        time.sleep(0.25)
    print()

    if not VIRUSTOTAL_API_KEY:
        console.print("[yellow]Note: Set VIRUSTOTAL_API_KEY env var for IP reputation checks[/yellow]")
        console.print("[yellow]      Get free key at: https://www.virustotal.com/gui/join-free\n[/yellow]")

    while True:
        print_menu()
        choice = console.input("Select option [1-6]: ").strip()

        if choice == "1":
            start_live_monitoring()
        elif choice == "2":
            view_alerts_menu()
        elif choice == "3":
            analyze_pcap_menu()
        elif choice == "4":
            export_pdf_menu()
        elif choice == "5":
            resolve_alert_menu()
        elif choice == "6":
            print()
            exit_steps = [
                "SAVING DATABASE...",
                "CLOSING CONNECTIONS...",
                "SHUTTING DOWN..."
            ]
            for i, step in enumerate(exit_steps):
                progress = "[%s]" % ("=" * (i + 1) + " " * (len(exit_steps) - i - 1))
                print(f"\033[93m{progress} {step}\033[0m")
                time.sleep(0.3)
            print()
            print("\033[93mGOODBYE!\033[0m")
            sys.exit(0)
        else:
            console.print("[red]Invalid option. Please try again.[/red]")


if __name__ == "__main__":
    main()