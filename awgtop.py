from __future__ import annotations

import argparse
from concurrent.futures import Future, ThreadPoolExecutor
import ipaddress
import json
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

try:
    from rich.align import Align
    from rich.console import Group
    from rich.live import Live
    from rich.markup import escape
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("Missing Rich. Install in a venv: pip install rich", file=sys.stderr)
    raise SystemExit(2)

PUBKEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")


@dataclass(frozen=True)
class Peer:
    key: str
    endpoint: str
    allowed_ips: str
    handshake: int
    received: int  # server received from peer = client upload
    sent: int      # server sent to peer = client download


def parse_dump(data: str) -> list[Peer]:
    peers: list[Peer] = []
    for line in data.splitlines()[1:]:
        fields = line.rstrip("\r").split("\t")
        # The first line is the interface; peer rows use WireGuard-compatible
        # columns. AWG 3.1 can append extra fields without changing these.
        if len(fields) < 8 or not PUBKEY.fullmatch(fields[0]):
            continue
        try:
            peers.append(Peer(
                key=fields[0],
                endpoint=fields[2] if fields[2] != "(none)" else "—",
                allowed_ips=fields[3],
                handshake=int(fields[4]),
                received=int(fields[5]),
                sent=int(fields[6]),
            ))
        except ValueError:
            continue
    return peers


def fetch(container: str, interface: str) -> list[Peer]:
    cmd = ["docker", "exec", container, "awg", "show", interface, "dump"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or f"Exit status {proc.returncode}")
    return parse_dump(proc.stdout)


def size(n: float) -> str:
    value = max(0.0, float(n))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if value < 1024 or unit == "PiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return "—"


def age(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h {int(seconds % 3600 // 60)}m"
    return f"{int(seconds // 86400)}d"


def load_names(filepath: str | None) -> dict[str, str]:
    if not filepath:
        return {}
    content = json.loads(Path(filepath).read_text(encoding="utf-8"))
    if not isinstance(content, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in content.items()
    ):
        raise ValueError('Names file must be JSON: {"public_key": "device name"}')
    return content


CLIENTS_TABLE_PATH = "/opt/amnezia/awg/clientsTable"


def parse_clients_table(raw: str) -> dict[str, str]:
    """Extract only key -> clientName; never display the original JSON."""
    content = json.loads(raw)
    if isinstance(content, list):
        entries = content
    elif isinstance(content, dict):
        entries = content.get("clients")
        if not isinstance(entries, list):
            raise ValueError("clientsTable has an unexpected JSON object structure")
    else:
        raise ValueError("clientsTable is not a JSON list")

    names: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        pubkey = entry.get("clientId")
        user_data = entry.get("userData")
        name = user_data.get("clientName") if isinstance(user_data, dict) else None
        if name is None:
            name = entry.get("clientName")
        if (isinstance(pubkey, str) and PUBKEY.fullmatch(pubkey)
                and isinstance(name, str) and name.strip()):
            names[pubkey] = name.strip()[:100]
    return names


class ClientsTableCache:
    """Periodically refresh Amnezia labels without modifying the VPN."""

    def __init__(self, container: str, interval: float = 30.0):
        self.container = container
        self.interval = interval
        self.updated_at = 0.0
        self.names: dict[str, str] = {}
        self.error: str | None = None

    def refresh(self) -> None:
        now = time.monotonic()
        if self.updated_at and now - self.updated_at < self.interval:
            return
        self.updated_at = now
        try:
            proc = subprocess.run(
                ["docker", "exec", self.container, "cat", CLIENTS_TABLE_PATH],
                capture_output=True, text=True, timeout=8, check=False,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"Could not read clientsTable (exit {proc.returncode})")
            self.names = parse_clients_table(proc.stdout)
            self.error = None
        except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            # Keep previously read names if a transient refresh fails.
            self.error = str(exc)[:140]


def endpoint_ip(endpoint: str) -> str | None:
    """Parse an AWG endpoint, either 1.2.3.4:port or [ipv6]:port."""
    if endpoint.startswith("["):
        addr = endpoint.partition("]")[0][1:]
    elif ":" in endpoint:
        addr, _, port = endpoint.rpartition(":")
        if not port.isdecimal():
            return None
    else:
        return None
    try:
        return str(ipaddress.ip_address(addr))
    except ValueError:
        return None


def reverse_dns(ip: str) -> str | None:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        host = host.rstrip(".").strip()
        if host and host != ip and len(host) <= 253:
            return host
    except (OSError, UnicodeError):
        pass
    return None


class PTRCache:
    """Non-blocking, cached PTR guesses. No DNS requests if disabled."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="awgtop-ptr") if enabled else None
        self.pending: dict[str, Future[str | None]] = {}
        self.cached: dict[str, tuple[str | None, float]] = {}

    def guess(self, endpoint: str) -> str | None:
        if not self.enabled or self.pool is None:
            return None
        ip = endpoint_ip(endpoint)
        if ip is None or not ipaddress.ip_address(ip).is_global:
            return None
        now = time.monotonic()
        cached = self.cached.get(ip)
        if cached and now - cached[1] < 3600:
            return cached[0]
        future = self.pending.get(ip)
        if future is not None:
            if not future.done():
                return None
            self.pending.pop(ip, None)
            try:
                host = future.result()
            except Exception:
                host = None
            self.cached[ip] = (host, now)
            return host
        # Bound queued lookups if there are a very large number of peers.
        if len(self.pending) < 32:
            self.pending[ip] = self.pool.submit(reverse_dns, ip)
        return None


def display(peers: list[Peer], prev: dict[str, Peer], elapsed: float,
            names: dict[str, str], clients: ClientsTableCache, ptr: PTRCache,
            container: str, interface: str,
            online_after: int, refresh: float) -> Panel:
    now = time.time()
    online = sum(p.handshake > 0 and 0 <= now - p.handshake <= online_after for p in peers)
    total_down = sum(p.sent for p in peers)
    total_up = sum(p.received for p in peers)
    table = Table(
        expand=True, header_style="bold cyan", box=None,
        row_styles=["none", "dim"], pad_edge=False,
    )
    table.add_column("STATE", no_wrap=True, width=9)
    table.add_column("CLIENT KEY", style="bold", no_wrap=True, min_width=11)
    table.add_column("ВОЗМ. ИМЯ", no_wrap=True, min_width=16, max_width=28, overflow="ellipsis")
    table.add_column("VPN IP", no_wrap=True, min_width=11)
    table.add_column("HANDSHAKE", no_wrap=True, justify="right")
    table.add_column("↓ DOWN", no_wrap=True, justify="right")
    table.add_column("↑ UP", no_wrap=True, justify="right")
    table.add_column("↓ Mb/s", no_wrap=True, justify="right")
    table.add_column("↑ Mb/s", no_wrap=True, justify="right")
    table.add_column("ENDPOINT", overflow="ellipsis")
    if ptr.enabled:
        table.add_column("PUBLIC PTR", overflow="ellipsis", max_width=30)

    ordered = sorted(
        peers,
        key=lambda p: (
            p.handshake > 0 and 0 <= now - p.handshake <= online_after,
            (max(0, p.sent - prev[p.key].sent) + max(0, p.received - prev[p.key].received))
            if p.key in prev else 0,
            p.handshake,
        ),
        reverse=True,
    )
    for p in ordered:
        since = now - p.handshake if p.handshake else None
        active = since is not None and 0 <= since <= online_after
        state = "[bold green]● RECENT[/]" if active else "[dim]○ IDLE[/]"
        before = prev.get(p.key)
        down = (max(0, p.sent - before.sent) * 8 / (elapsed * 1e6)) if before and elapsed > 0 else 0
        up = (max(0, p.received - before.received) * 8 / (elapsed * 1e6)) if before and elapsed > 0 else 0
        # Actual Amnezia labels first, manual aliases second; PTR is NOT a device name.
        official = clients.names.get(p.key)
        manual = names.get(p.key)
        if official:
            possible_name = escape(official) + " [dim](Amnezia)[/]"
        elif manual:
            possible_name = escape(manual) + " [dim](вручную)[/]"
        else:
            possible_name = "[dim]Не определено[/]"
        ips = p.allowed_ips.split(",")[0] if p.allowed_ips not in ("(none)", "") else "—"
        cells = [
            state, escape(p.key[:9] + "…"), possible_name, escape(ips),
            age(since) if since is not None and since >= 0 else "never",
            size(p.sent), size(p.received),
            f"[green]{down:,.2f}[/]", f"[yellow]{up:,.2f}[/]", escape(p.endpoint),
        ]
        if ptr.enabled:
            hostname = ptr.guess(p.endpoint)
            cells.append(escape(hostname) if hostname else "[dim]—[/]")
        table.add_row(*cells)
    if not peers:
        table.add_row(*(["—", "No peers"] + ["—"] * (len(table.columns) - 2)))

    title = Text("  AWG TOP  ", style="bold white on dark_cyan")
    subtitle = Text(f"  {container} / {interface}  •  refresh {refresh:g}s  •  Ctrl+C to quit", style="dim")
    headline = Text()
    headline.append(f"  {online}/{len(peers)} recently connected  ", style="bold green")
    headline.append(f"    ↓ {size(total_down)}    ↑ {size(total_up)}", style="bold")
    named_count = sum(bool(clients.names.get(p.key) or names.get(p.key)) for p in peers)
    foot_message = (
        f"  ↓ server → client | ↑ client → server | RECENT = handshake within {online_after}s (not online proof)\n"
        f"  Device labels: {named_count}/{len(peers)} identified | (Amnezia) = clientsTable | (вручную) = --names JSON.\n"
        "  Public PTR (optional) is a provider/endpoint hostname, not a device name. "
        "Counters reset with interface."
    )
    if clients.error:
        foot_message += "\n  [clientsTable unavailable: check JSON structure or Docker permissions]"
    foot = Text(foot_message, style="dim")
    contents = Group(Align.left(Group(title, subtitle)), headline, Text(""), table, Text(""), foot)
    return Panel(contents, border_style="cyan", padding=(1, 2), title="[bold cyan]AmneziaWG traffic dashboard[/]")


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only AmneziaWG per-peer TUI with possible-name column")
    parser.add_argument("--container", default="amnezia-awg2")
    parser.add_argument("--interface", default="awg0")
    parser.add_argument("--refresh", type=float, default=2.0)
    parser.add_argument("--active-seconds", type=int, default=180)
    parser.add_argument("--names", help="Optional JSON: full public key -> device label")
    parser.add_argument("--show-ptr", action="store_true", help="Show public endpoint PTR in a separate column")
    parser.add_argument("--no-ptr", action="store_true", help="Legacy flag (PTR is disabled by default)")
    parser.add_argument("--names-refresh", type=float, default=30.0, help="Interval to refresh clientsTable in seconds")
    args = parser.parse_args()
    if args.refresh < 0.5:
        parser.error("--refresh must be at least 0.5 seconds")
    if args.active_seconds <= 0:
        parser.error("--active-seconds must be positive")
    try:
        names = load_names(args.names)
    except (OSError, ValueError) as exc:
        parser.error(f"--names: {exc}")
    if args.names_refresh < 2:
        parser.error("--names-refresh must be at least 2 seconds")
    ptr = PTRCache(enabled=args.show_ptr and not args.no_ptr)
    clients = ClientsTableCache(args.container, args.names_refresh)
    try:
        last: dict[str, Peer] = {}
        previous_time: float | None = None
        with Live(screen=True, auto_refresh=False, transient=True) as live:
            while True:
                start = time.monotonic()
                try:
                    rows = fetch(args.container, args.interface)
                    clients.refresh()
                    now = time.monotonic()
                    delta = now - previous_time if previous_time is not None else 0.0
                    live.update(
                        display(rows, last, delta, names, clients, ptr, args.container, args.interface,
                                args.active_seconds, args.refresh), refresh=True,
                    )
                    last = {p.key: p for p in rows}
                    previous_time = now
                except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
                    live.update(Panel(
                        f"[bold red]Unable to query AWG:[/] {escape(str(exc))}\n\n"
                        "Check Docker permissions and interface name.",
                        title="AWG TOP", border_style="red",
                    ), refresh=True)
                time.sleep(max(0, args.refresh - (time.monotonic() - start)))
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
