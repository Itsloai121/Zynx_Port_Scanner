#!/usr/bin/env python3
"""
Zynx Port Scanner
A threaded TCP connect scanner with lightweight service banner grabbing.

Use only against systems you own or are explicitly authorized to assess.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

try:
    from rich import box
    from rich.align import Align
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("[!] Missing dependency: rich\n    Install it with: python -m pip install rich")
    raise SystemExit(1)

APP_NAME = "ZYNX PORT SCANNER"
VERSION = "1.0.0"

# A curated quick-scan set and a broader list of frequently used TCP ports.
QUICK_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 465, 587, 993, 995, 1433, 3306,
    3389, 5432, 5900, 6379, 8080, 8443,
]

COMMON_PORTS = sorted(set([
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 81, 88, 110, 111, 119,
    123, 135, 137, 138, 139, 143, 161, 162, 179, 194, 389, 443, 445,
    465, 500, 502, 514, 515, 520, 523, 548, 554, 587, 593, 631, 636,
    646, 873, 902, 989, 990, 993, 995, 1025, 1080, 1099, 1433, 1521,
    1723, 1883, 1900, 2049, 2082, 2083, 2086, 2087, 2181, 2222, 2375,
    2376, 2483, 2484, 3000, 3128, 3268, 3306, 3389, 3690, 4000, 4444,
    4567, 5000, 5001, 5432, 5601, 5631, 5672, 5900, 5985, 5986, 6000,
    6379, 6443, 7001, 7002, 7070, 7443, 8000, 8008, 8080, 8081, 8088,
    8443, 8888, 9000, 9090, 9200, 9300, 9418, 10000, 11211, 27017,
]))

TLS_PORTS = {
    443, 465, 636, 853, 989, 990, 992, 993, 995,
    8443, 9443,
}
HTTP_PORTS = {
    80, 81, 3000, 5000, 5001, 7000, 7001, 7002,
    8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090,
}

SERVICE_OVERRIDES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 1883: "mqtt", 3000: "http-alt",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb",
}


@dataclass(frozen=True)
class ScanResult:
    port: int
    service: str
    banner: str
    latency_ms: float


@dataclass
class ScanSummary:
    target: str
    resolved_ip: str
    mode: str
    started_at: str
    finished_at: str
    duration_seconds: float
    scanned_ports: int
    open_ports: int
    workers: int
    timeout_seconds: float
    results: list[ScanResult]


class ZynxScanner:
    def __init__(self) -> None:
        self.console = Console(highlight=False)
        self.session_started = datetime.now()
        self.session_clock = time.monotonic()
        self.workers = min(256, max(64, (os.cpu_count() or 4) * 32))
        self.timeout = 0.8
        self.last_summary: ScanSummary | None = None

    @staticmethod
    def format_duration(seconds: float) -> str:
        seconds = max(0, int(seconds))
        hours, remainder = divmod(seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    def session_uptime(self) -> str:
        return self.format_duration(time.monotonic() - self.session_clock)

    def header(self) -> Panel:
        grid = Table.grid(expand=True)
        grid.add_column(ratio=1)
        grid.add_column(justify="right", ratio=1)
        grid.add_row(
            f"[bold cyan]STARTED[/]  {self.session_started.strftime('%H:%M:%S')}",
            f"[bold cyan]SESSION UPTIME[/]  {self.session_uptime()}",
        )
        grid.add_row(
            f"[dim]VERSION {VERSION}  •  THREADED TCP CONNECT[/]",
            "[bold bright_magenta]zynx[/]",
        )
        return Panel(
            grid,
            title="[bold white] ZYNX // PORT SCANNER [/]",
            subtitle="[dim]AUTHORIZED SECURITY TESTING ONLY[/]",
            border_style="bright_blue",
            box=box.DOUBLE,
            padding=(0, 1),
        )

    def show_notice(self) -> None:
        self.console.print(Panel(
            "[bold yellow]Use responsibly.[/] Scan only devices and networks you own or have explicit permission to test. "
            "This tool performs TCP connection checks and limited banner probes; it does not exploit services or attempt stealth.",
            title="[bold yellow]SCOPE & AUTHORIZATION[/]",
            border_style="yellow",
            box=box.ROUNDED,
        ))

    def draw_menu(self) -> None:
        self.console.clear()
        self.console.print(self.header())
        self.console.print("[bold bright_cyan]MAIN MENU[/]  [dim]Choose a scan or utility[/]\n")

        table = Table(box=box.ROUNDED, border_style="bright_blue", show_lines=True, expand=True)
        table.add_column("KEY", style="bold cyan", justify="center", width=6)
        table.add_column("FUNCTION", style="bold white", width=25)
        table.add_column("WHAT IT DOES", style="white")
        rows = [
            ("1", "Quick scan", "Checks 25 frequently exposed TCP ports; fastest starting point."),
            ("2", "Common ports", "Checks a broader curated list of common TCP service ports."),
            ("3", "Custom ports", "Checks only the ports you enter, e.g. 22,80,443,8080."),
            ("4", "Custom range", "Checks an inclusive range, e.g. 1-1024 or 8000-9000."),
            ("5", "Full TCP scan", "Checks every TCP port from 1 to 65535; can take longer."),
            ("6", "View last results", "Displays open ports and the captured service banners from the last scan."),
            ("7", "Export last results", "Saves the last scan as a CSV or JSON report."),
            ("8", "Performance settings", "Adjust connection timeout and concurrent worker count."),
            ("0", "Exit", "Close the tool."),
        ]
        for key, name, description in rows:
            table.add_row(key, name, description)
        self.console.print(table)
        self.console.print(
            f"[dim]Workers: [cyan]{self.workers}[/]  •  Timeout: [cyan]{self.timeout:.1f}s[/]  •  "
            "Results are kept in memory until you exit.[/]"
        )

    def ask(self, prompt: str, default: str | None = None) -> str:
        suffix = f" [dim](default: {default})[/]" if default is not None else ""
        value = self.console.input(f"[bold bright_cyan]»[/] {prompt}{suffix}: ").strip()
        return value if value else (default or "")

    def resolve_target(self, target: str) -> tuple[int, str, tuple]:
        target = target.strip()
        if target.startswith("[") and target.endswith("]"):
            target = target[1:-1]
        if not target or any(ch in target for ch in "/\\\r\n\t "):
            raise ValueError("Enter one hostname or IP address, not a URL, CIDR, or list of targets.")
        try:
            ipaddress.ip_address(target)
        except ValueError:
            # Hostnames are resolved once; worker threads use the resolved socket address.
            pass
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        if not infos:
            raise ValueError("The target did not resolve to an address.")
        # Prefer IPv4 if DNS returned both families; IPv6-only targets still work.
        infos.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)
        family, socktype, proto, _canonname, address = infos[0]
        resolved_ip = address[0]
        return family, resolved_ip, address

    @staticmethod
    def service_name(port: int) -> str:
        if port in SERVICE_OVERRIDES:
            return SERVICE_OVERRIDES[port]
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "unknown"

    @staticmethod
    def clean_banner(raw: bytes) -> str:
        if not raw:
            return "No banner received"
        decoded = raw.decode("utf-8", errors="replace")
        decoded = "".join(ch if ch.isprintable() else " " for ch in decoded)
        decoded = re.sub(r"\s+", " ", decoded).strip()
        return decoded[:220] if decoded else "Non-text response"

    def grab_banner(self, sock: socket.socket, target: str, port: int) -> str:
        probe_timeout = min(self.timeout, 0.55)
        try:
            sock.settimeout(probe_timeout)
            if port in TLS_PORTS:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    server_name = None
                    try:
                        ipaddress.ip_address(target)
                    except ValueError:
                        server_name = target
                    with context.wrap_socket(sock, server_hostname=server_name) as tls_sock:
                        tls_sock.settimeout(probe_timeout)
                        request_host = target.replace("\r", "").replace("\n", "")
                        tls_sock.sendall(
                            f"HEAD / HTTP/1.0\r\nHost: {request_host}\r\nConnection: close\r\n\r\n".encode("ascii", "ignore")
                        )
                        return self.clean_banner(tls_sock.recv(1024))
                except (OSError, ssl.SSLError, socket.timeout):
                    return "TLS endpoint; no readable HTTP banner"
            if port in HTTP_PORTS:
                request_host = target.replace("\r", "").replace("\n", "")
                sock.sendall(
                    f"HEAD / HTTP/1.0\r\nHost: {request_host}\r\nConnection: close\r\n\r\n".encode("ascii", "ignore")
                )
                try:
                    return self.clean_banner(sock.recv(1024))
                except socket.timeout:
                    return "HTTP service; no response banner"
            try:
                return self.clean_banner(sock.recv(1024))
            except socket.timeout:
                return "No banner received"
        except (OSError, ssl.SSLError):
            return "Banner unavailable"

    def scan_port(self, family: int, resolved_ip: str, base_address: tuple, port: int, target_host: str) -> ScanResult | None:
        if family == socket.AF_INET6:
            address = (resolved_ip, port, base_address[2], base_address[3])
        else:
            address = (resolved_ip, port)
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                started = time.perf_counter()
                error_code = sock.connect_ex(address)
                latency_ms = (time.perf_counter() - started) * 1000
                if error_code != 0:
                    return None
                banner = self.grab_banner(sock, target_host, port)
                return ScanResult(
                    port=port,
                    service=self.service_name(port),
                    banner=banner,
                    latency_ms=round(latency_ms, 2),
                )
        except (OSError, ValueError):
            return None

    def parse_custom_ports(self, value: str) -> list[int]:
        ports: set[int] = set()
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                pieces = part.split("-")
                if len(pieces) != 2:
                    raise ValueError(f"Invalid range: {part}")
                start, end = (int(p.strip()) for p in pieces)
                if start > end:
                    raise ValueError(f"Range start must be <= end: {part}")
                if start < 1 or end > 65535:
                    raise ValueError("Ports must be between 1 and 65535.")
                if end - start > 65534:
                    raise ValueError("The requested range is too large.")
                ports.update(range(start, end + 1))
            else:
                port = int(part)
                if not 1 <= port <= 65535:
                    raise ValueError("Ports must be between 1 and 65535.")
                ports.add(port)
        if not ports:
            raise ValueError("Enter at least one valid port.")
        if len(ports) > 65535:
            raise ValueError("No more than 65535 unique ports can be scanned.")
        return sorted(ports)

    def choose_scan(self, choice: str) -> tuple[str, list[int]] | None:
        if choice == "1":
            return "Quick scan", QUICK_PORTS.copy()
        if choice == "2":
            return "Common ports", COMMON_PORTS.copy()
        if choice == "3":
            raw = self.ask("Ports (example: 22,80,443,8000-8010)")
            return "Custom ports", self.parse_custom_ports(raw)
        if choice == "4":
            raw = self.ask("Port range (example: 1-1024)")
            ports = self.parse_custom_ports(raw)
            if len(ports) > 20000:
                self.console.print("[yellow]Large range selected. This may take a while.[/]")
            return "Custom range", ports
        if choice == "5":
            return "Full TCP scan", list(range(1, 65536))
        return None

    def run_scan(self, mode: str, ports: list[int]) -> None:
        self.console.print(self.header())
        target = self.ask("Target hostname or IP (example: 192.0.2.10)")
        family, resolved_ip, base_address = self.resolve_target(target)
        self.console.print(Panel(
            f"[bold]Target:[/] {target}\n[bold]Resolved address:[/] {resolved_ip}\n"
            f"[bold]Profile:[/] {mode}\n[bold]Ports:[/] {len(ports):,}\n"
            f"[bold]Workers:[/] {self.workers}\n[bold]Connect timeout:[/] {self.timeout:.2f}s",
            title="[cyan]SCAN CONFIGURATION[/]", border_style="cyan", box=box.ROUNDED,
        ))
        self.console.print(
            "[yellow]Confirm that you own this target or have explicit authorization to scan it.[/]"
        )
        confirmation = self.ask("Type YES to begin (anything else cancels)")
        if confirmation != "YES":
            self.console.print(Panel("Scan cancelled. No ports were tested.", border_style="yellow", box=box.ROUNDED))
            return

        scan_started_wall = datetime.now().isoformat(timespec="seconds")
        started = time.perf_counter()
        results: list[ScanResult] = []
        completed = 0
        errors = 0
        worker_count = min(self.workers, len(ports))

        progress = Progress(
            SpinnerColumn(style="bright_cyan"),
            TextColumn("[bold cyan]{task.description}[/]"),
            BarColumn(bar_width=None, complete_style="bright_cyan", finished_style="green"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console,
            expand=True,
        )
        task_id = progress.add_task("Connecting to TCP ports", total=len(ports))

        def live_header() -> Panel:
            elapsed = time.perf_counter() - started
            status = (
                f"[bold]TARGET[/] {target}  [dim]({resolved_ip})[/]   "
                f"[bold]OPEN[/] [green]{len(results)}[/]   "
                f"[bold]SESSION[/] {self.session_uptime()}   "
                f"[bold]SCAN[/] {self.format_duration(elapsed)}"
            )
            return Panel(status, title="[bold white] ZYNX // LIVE SCAN [/]")

        self.console.print("[dim]Press Ctrl+C to cancel the scan.[/]")
        try:
            with Live(Group(live_header(), progress), console=self.console, refresh_per_second=8, transient=True) as live:
                with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="zynx-scan") as executor:
                    # Keep a small bounded queue: avoids allocating one Future per port on 65,535-port scans.
                    port_iter = iter(ports)
                    pending = set()
                    queue_limit = min(len(ports), worker_count * 4)
                    for _ in range(queue_limit):
                        try:
                            port = next(port_iter)
                        except StopIteration:
                            break
                        pending.add(executor.submit(self.scan_port, family, resolved_ip, base_address, port, target))

                    while pending:
                        finished, pending = wait(pending, return_when=FIRST_COMPLETED)
                        for future in finished:
                            completed += 1
                            try:
                                result = future.result()
                                if result is not None:
                                    results.append(result)
                            except Exception:
                                errors += 1
                            try:
                                next_port = next(port_iter)
                                pending.add(executor.submit(self.scan_port, family, resolved_ip, base_address, next_port, target))
                            except StopIteration:
                                pass
                            progress.update(task_id, completed=completed)
                        # Refresh the header alongside progress; socket work stays in worker threads.
                        if completed % 8 < len(finished) or completed == len(ports):
                            live.update(Group(live_header(), progress), refresh=True)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Cancellation requested. Waiting for active connection attempts to finish...[/]")
            raise

        duration = time.perf_counter() - started
        results.sort(key=lambda item: item.port)
        summary = ScanSummary(
            target=target,
            resolved_ip=resolved_ip,
            mode=mode,
            started_at=scan_started_wall,
            finished_at=datetime.now().isoformat(timespec="seconds"),
            duration_seconds=round(duration, 3),
            scanned_ports=completed,
            open_ports=len(results),
            workers=worker_count,
            timeout_seconds=self.timeout,
            results=results,
        )
        self.last_summary = summary
        self.show_results(summary, errors)

    def show_results(self, summary: ScanSummary, errors: int = 0) -> None:
        rate = summary.scanned_ports / summary.duration_seconds if summary.duration_seconds else 0
        self.console.print(Panel(
            f"[bold]Target:[/] {summary.target}  [dim]({summary.resolved_ip})[/]\n"
            f"[bold]Profile:[/] {summary.mode}\n"
            f"[bold]Ports checked:[/] {summary.scanned_ports:,}    "
            f"[bold]Open:[/] [green]{summary.open_ports}[/]    "
            f"[bold]Duration:[/] {summary.duration_seconds:.2f}s\n"
            f"[bold]Average throughput:[/] {rate:,.0f} ports/sec    [bold]Workers:[/] {summary.workers}"
            + (f"\n[yellow]Worker exceptions: {errors}[/]" if errors else ""),
            title="[bold green]SCAN COMPLETE[/]", border_style="green", box=box.DOUBLE,
        ))
        self.display_results(summary.results)

    def display_results(self, results: Iterable[ScanResult]) -> None:
        rows = list(results)
        if not rows:
            self.console.print(Panel("No open TCP ports were found in the selected scan profile.", border_style="yellow"))
            return
        table = Table(title="OPEN TCP PORTS", box=box.ROUNDED, border_style="green", expand=True)
        table.add_column("PORT", style="bold cyan", justify="right", width=8)
        table.add_column("SERVICE", style="bold white", width=18)
        table.add_column("LATENCY", justify="right", width=11)
        table.add_column("BANNER / SERVICE RESPONSE", overflow="fold")
        for result in rows:
            # Text() prevents remote banner contents from being interpreted as Rich markup.
            table.add_row(
                str(result.port),
                result.service,
                f"{result.latency_ms:.2f} ms",
                Text(result.banner),
            )
        self.console.print(table)
        self.console.print("[dim]Banner text is best-effort identification, not proof of exact software or version.[/]")

    def view_last_results(self) -> None:
        if self.last_summary is None:
            self.console.print(Panel("There are no scan results yet. Run a scan first.", border_style="yellow"))
            return
        summary = self.last_summary
        self.console.print(Panel(
            f"[bold]Target:[/] {summary.target} ({summary.resolved_ip})\n"
            f"[bold]Profile:[/] {summary.mode}  •  [bold]Scanned:[/] {summary.scanned_ports:,}  •  "
            f"[bold]Open:[/] {summary.open_ports}  •  [bold]Duration:[/] {summary.duration_seconds:.2f}s",
            title="[cyan]LAST SCAN[/]", border_style="cyan",
        ))
        self.display_results(summary.results)

    def export_last_results(self) -> None:
        if self.last_summary is None:
            self.console.print(Panel("There are no scan results to export. Run a scan first.", border_style="yellow"))
            return
        kind = self.ask("Export format (csv/json)", "csv").lower()
        if kind not in {"csv", "json"}:
            raise ValueError("Format must be csv or json.")
        default_name = f"zynx_{self.last_summary.resolved_ip.replace(':', '_')}_{datetime.now():%Y%m%d_%H%M%S}.{kind}"
        filename = self.ask("Output filename", default_name)
        path = Path(filename).expanduser()
        if path.suffix.lower() != f".{kind}":
            path = path.with_suffix(f".{kind}")
        payload = asdict(self.last_summary)
        if kind == "json":
            path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        else:
            with path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(["target", "resolved_ip", "mode", "scanned_at", "port", "service", "latency_ms", "banner"])
                for result in self.last_summary.results:
                    writer.writerow([
                        self.last_summary.target,
                        self.last_summary.resolved_ip,
                        self.last_summary.mode,
                        self.last_summary.started_at,
                        result.port,
                        result.service,
                        result.latency_ms,
                        result.banner,
                    ])
        self.console.print(Panel(f"Report saved to: [bold green]{path.resolve()}[/]", title="[green]EXPORT COMPLETE[/]", border_style="green"))

    def settings(self) -> None:
        self.console.print(Panel(
            f"Current timeout: [cyan]{self.timeout:.2f}s[/]\nCurrent workers: [cyan]{self.workers}[/]\n\n"
            "[dim]Lower timeouts finish faster but may miss slow or filtered services. More workers increase concurrency and resource use.[/]",
            title="[cyan]PERFORMANCE SETTINGS[/]", border_style="cyan",
        ))
        raw_timeout = self.ask("Connection timeout in seconds (0.2-5.0)", f"{self.timeout:.2f}")
        raw_workers = self.ask("Concurrent workers (16-512)", str(self.workers))
        timeout_value = float(raw_timeout)
        worker_value = int(raw_workers)
        if not 0.2 <= timeout_value <= 5.0:
            raise ValueError("Timeout must be between 0.2 and 5.0 seconds.")
        if not 16 <= worker_value <= 512:
            raise ValueError("Workers must be between 16 and 512.")
        self.timeout = timeout_value
        self.workers = worker_value
        self.console.print(Panel("Performance settings updated.", border_style="green"))

    def run(self) -> None:
        self.show_notice()
        while True:
            self.draw_menu()
            choice = self.ask("Select an option")
            try:
                if choice == "0":
                    self.console.print(Panel(
                        f"[bold bright_magenta]zynx[/]  •  Session duration: {self.session_uptime()}\nThanks for using Zynx Port Scanner.",
                        title="[cyan]EXIT[/]", border_style="bright_blue", box=box.DOUBLE,
                    ))
                    break
                elif choice in {"1", "2", "3", "4", "5"}:
                    profile = self.choose_scan(choice)
                    if profile is not None:
                        self.run_scan(*profile)
                elif choice == "6":
                    self.view_last_results()
                elif choice == "7":
                    self.export_last_results()
                elif choice == "8":
                    self.settings()
                else:
                    raise ValueError("Choose one of the listed menu options.")
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Action cancelled.[/]")
            except (ValueError, OSError, socket.gaierror) as exc:
                self.console.print(Panel(f"[bold red]Error:[/] {exc}", title="[red]INPUT / NETWORK ERROR[/]", border_style="red", box=box.ROUNDED))
            self.console.input("\n[dim]Press Enter to return to the main menu...[/]")


def main() -> int:
    try:
        ZynxScanner().run()
        return 0
    except KeyboardInterrupt:
        print("\nZynx closed.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
