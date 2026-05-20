"""
Network connection monitor.
Uses psutil to snapshot active TCP/UDP connections every N seconds.
Detects:
  - New outbound connections to suspicious / unusual ports
  - Known C2 port patterns
  - Beaconing (regular interval outbound to same remote)
  - High connection-rate bursts (potential C2 or data exfil)
  - Unexpected listening services
"""
import ipaddress
import platform
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional, Set, Tuple

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

from collectors.base import LogEntry, BaseCollector

# ── Well-known suspicious / C2 ports ─────────────────────────
_SUSPICIOUS_PORTS: Dict[int, str] = {
    4444:  "Metasploit default listener",
    4445:  "Metasploit alt listener",
    1337:  "L33t/hacker convention port",
    31337: "Back Orifice / classic backdoor",
    6666:  "IRC / backdoor convention",
    6667:  "IRC unencrypted",
    6668:  "IRC alt",
    1234:  "Generic backdoor",
    5555:  "ADB / Android debug / generic backdoor",
    9001:  "Tor relay port",
    9050:  "Tor SOCKS proxy",
    9051:  "Tor control port",
    8888:  "Jupyter / potential web shell",
    2222:  "SSH alt – possible pivoting",
    8443:  "HTTPS alt – common C2",
    12345: "Classic backdoor (NetBus era)",
    27374: "SubSeven trojan",
    65535: "Common exploit/scan probe port",
}

# Ports that are suspicious ONLY for outbound connections from non-servers
_OUTBOUND_WATCH: Set[int] = {25, 587, 465}  # SMTP exfil

# Private / RFC-1918 ranges — connections to these are usually internal
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


def _is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


class NetworkMonitor:
    """
    Periodically snapshots active connections via psutil.
    Emits LogEntry objects through `on_entry` callback.
    """

    def __init__(self, config, on_entry: Callable[[LogEntry], None]):
        self._config = config
        self._on_entry = on_entry
        self._interval = getattr(config, "network_interval", 15)
        self._platform = platform.system().lower()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # State tracking
        # key: (laddr_ip, laddr_port, raddr_ip, raddr_port, pid) → first seen
        self._known_conns: Dict[tuple, datetime] = {}
        self._known_listeners: Set[int] = set()

        # Beaconing: remote_ip → deque of connection timestamps
        self._beacon_tracker: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=20))
        # Outbound burst: remote_ip → count in last minute
        self._burst_tracker: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=200))

    # ── Lifecycle ──────────────────────────────────────────────

    def start(self):
        if not _HAS_PSUTIL:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="netmon")
        self._thread.start()

    def stop(self):
        self._running = False

    # ── Main loop ──────────────────────────────────────────────

    def _loop(self):
        # Warm-up: populate known state without alerting
        try:
            self._snapshot(alert=False)
        except Exception:
            pass
        while self._running:
            time.sleep(self._interval)
            try:
                self._snapshot(alert=True)
            except Exception:
                pass

    def _snapshot(self, alert: bool):
        now = datetime.now()
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            conns = []

        current_keys: Set[tuple] = set()

        for c in conns:
            if not c.raddr:
                # Listening port tracking
                if c.laddr and c.status == "LISTEN":
                    port = c.laddr.port
                    if port not in self._known_listeners:
                        self._known_listeners.add(port)
                        if alert:
                            self._emit_new_listener(c, now)
                continue

            rip = c.raddr.ip
            rport = c.raddr.port
            lip = c.laddr.ip if c.laddr else ""
            lport = c.laddr.port if c.laddr else 0
            pid = c.pid or 0
            key = (lip, lport, rip, rport, pid)
            current_keys.add(key)

            if key not in self._known_conns:
                self._known_conns[key] = now
                if alert:
                    self._analyse_new_conn(c, rip, rport, pid, now)

        # Track beaconing / burst
        if alert:
            self._check_beaconing(now)

        # Prune stale known connections (gone for > 5 min)
        stale_cutoff = now - timedelta(minutes=5)
        self._known_conns = {
            k: v for k, v in self._known_conns.items()
            if k in current_keys or v > stale_cutoff
        }

    # ── Analysis helpers ───────────────────────────────────────

    def _analyse_new_conn(self, conn, rip: str, rport: int,
                          pid: int, now: datetime):
        proc_name = self._proc_name(pid)

        # 1. Suspicious port
        if rport in _SUSPICIOUS_PORTS:
            reason = _SUSPICIOUS_PORTS[rport]
            self._emit(
                level="CRITICAL",
                category="network",
                src_ip=conn.laddr.ip if conn.laddr else "",
                dst_ip=rip,
                dst_port=rport,
                protocol=conn.type.name if conn.type else "TCP",
                message=(f"Suspicious outbound connection to {rip}:{rport} "
                         f"({reason}) — process: {proc_name}"),
                matched_rules=["Suspicious Outbound"],
                tags=["suspicious_port", f"port:{rport}"],
                ts=now,
            )

        # 2. External SMTP (exfil indicator)
        elif rport in _OUTBOUND_WATCH and not _is_private(rip):
            self._emit(
                level="WARNING",
                category="network",
                src_ip=conn.laddr.ip if conn.laddr else "",
                dst_ip=rip,
                dst_port=rport,
                protocol="TCP",
                message=(f"Outbound SMTP-like connection to {rip}:{rport} "
                         f"— possible exfiltration — process: {proc_name}"),
                matched_rules=["Large Outbound Transfer"],
                tags=["smtp_outbound"],
                ts=now,
            )

        # Beacon tracking: external connections only
        if not _is_private(rip):
            self._burst_tracker[rip].append(now)
            self._beacon_tracker[rip].append(now)

    def _check_beaconing(self, now: datetime):
        cutoff_1m = now - timedelta(minutes=1)
        cutoff_5m = now - timedelta(minutes=5)

        for rip, times in list(self._beacon_tracker.items()):
            # Trim to last 5 min
            recent = [t for t in times if t >= cutoff_5m]
            self._beacon_tracker[rip] = deque(recent, maxlen=20)

            if len(recent) < 5:
                continue

            # Check regularity: beacon = low std-dev in intervals
            intervals = [(recent[i+1] - recent[i]).total_seconds()
                         for i in range(len(recent)-1)]
            if not intervals:
                continue
            mean = sum(intervals) / len(intervals)
            variance = sum((x - mean)**2 for x in intervals) / len(intervals)
            std = variance ** 0.5

            # Coefficient of variation < 0.25 → very regular → beaconing
            if mean > 0 and (std / mean) < 0.25 and mean < 120:
                self._emit(
                    level="WARNING",
                    category="network",
                    dst_ip=rip,
                    dst_port=0,
                    message=(f"Beaconing detected to {rip}: {len(recent)} "
                             f"connections in 5m with interval "
                             f"{mean:.1f}s ±{std:.1f}s"),
                    matched_rules=["Beaconing Detected"],
                    tags=["beaconing", f"remote:{rip}"],
                    ts=now,
                )
                # Reset to avoid repeat
                self._beacon_tracker[rip].clear()

    def _emit_new_listener(self, conn, now: datetime):
        port = conn.laddr.port
        pid = conn.pid or 0
        proc = self._proc_name(pid)
        if port < 1024 and proc not in ("", "unknown"):
            self._emit(
                level="INFO",
                category="network",
                dst_port=port,
                message=f"New listening service on port {port} — process: {proc}",
                matched_rules=[],
                tags=["new_listener", f"port:{port}"],
                ts=now,
            )

    # ── Emit helper ────────────────────────────────────────────

    def _emit(self, *, level: str, category: str, message: str,
              matched_rules: List[str], tags: List[str], ts: datetime,
              src_ip: str = "", dst_ip: str = "",
              dst_port: int = 0, protocol: str = "TCP"):
        entry = LogEntry(
            timestamp=ts,
            source="network-monitor",
            level=level,
            message=message,
            platform=self._platform,
            raw=message,
            matched_rules=matched_rules,
            tags=tags,
            category=category,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            is_anomaly=(level in ("WARNING", "CRITICAL")),
            anomaly_score=0.8 if level == "CRITICAL" else 0.5,
        )
        self._on_entry(entry)

    # ── Utils ──────────────────────────────────────────────────

    @staticmethod
    def _proc_name(pid: int) -> str:
        if not pid:
            return "unknown"
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "unknown"

    def get_active_connections(self) -> List[Dict]:
        """Return current connection snapshot for the dashboard."""
        if not _HAS_PSUTIL:
            return []
        result = []
        try:
            for c in psutil.net_connections(kind="inet"):
                if not c.raddr:
                    continue
                result.append({
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}",
                    "rip":   c.raddr.ip,
                    "rport": c.raddr.port,
                    "status": c.status or "",
                    "pid":   c.pid or 0,
                    "proc":  self._proc_name(c.pid or 0),
                    "suspicious": c.raddr.port in _SUSPICIOUS_PORTS,
                    "external":   not _is_private(c.raddr.ip),
                })
        except Exception:
            pass
        return result[:200]
