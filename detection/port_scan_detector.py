"""
Port scan detector — multi-source approach.

Detection sources (in priority order):
  1. /proc/net/tcp + /proc/net/tcp6  — SYN_RECV half-open connections.
     This is the most reliable method for nmap SYN scans (-sS) because
     those never reach ESTABLISHED so psutil misses them entirely.
     Polled every 1 second in a dedicated thread.

  2. Log-based (firewall/syslog patterns) — UFW BLOCK, iptables DROP,
     "connection refused", auth failures. Catches scans even without
     raw socket access.

  3. psutil ESTABLISHED connections — catches nmap -sT (connect scan)
     and application-level scanners.

All three sources feed the same sliding-window unique-port counter
per source IP.  A scan alert fires when one source hits
`unique_port_threshold` distinct destination ports inside
`window_seconds`.
"""
import re
import socket
import struct
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional, Set, Tuple

from collectors.base import LogEntry

# ── Log patterns that reveal scans ──────────────────────────────
# Covers: UFW, iptables, nftables, fail2ban, sshd, nginx, apache
_LOG_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    # UFW:  [UFW BLOCK] ... SRC=1.2.3.4 ... DPT=22
    (re.compile(r'UFW BLOCK.*?SRC=(\d{1,3}(?:\.\d{1,3}){3}).*?DPT=(\d+)', re.I),
     'ufw', 'firewall'),
    # iptables / nftables generic DROP
    (re.compile(r'(?:DROP|REJECT|BLOCK).*?SRC=(\d{1,3}(?:\.\d{1,3}){3}).*?DPT=(\d+)', re.I),
     'iptables', 'firewall'),
    # nftables: ... ip saddr 1.2.3.4 ... dport 22
    (re.compile(r'ip\s+saddr\s+(\d{1,3}(?:\.\d{1,3}){3})\s+.*?dport\s+(\d+)', re.I),
     'nftables', 'firewall'),
    # Kernel: possible SYN flood from 1.2.3.4 port 12345
    (re.compile(r'SYN flood.*?from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(\d+)', re.I),
     'kernel', 'synflood'),
    # sshd: Failed/Invalid from 1.2.3.4 port 12345
    (re.compile(r'(?:Failed|Invalid).*?from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(\d+)', re.I),
     'sshd', 'auth'),
    # Generic "from IP port PORT" (nginx, apache, etc.)
    (re.compile(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s+port\s+(\d+))?', re.I),
     'generic', 'log'),
    # Generic SRC= DPT= (iptables -j LOG)
    (re.compile(r'SRC=(\d{1,3}(?:\.\d{1,3}){3}).*?DPT=(\d+)', re.I),
     'iptables', 'firewall'),
]

# SYN_RECV hex state in /proc/net/tcp
_SYN_RECV = '02'
# TIME_WAIT — also worth tracking for fast connect-scanners
_TIME_WAIT = '06'
_SCAN_STATES = {_SYN_RECV, _TIME_WAIT}

# Private / loopback ranges — skip these as scan sources
_SKIP_PREFIXES = ('127.', '0.0.0.0', '::1', '::')


def _hex_to_ip4(hex_str: str) -> str:
    """Convert little-endian hex IP from /proc/net/tcp to dotted-decimal."""
    try:
        packed = int(hex_str, 16).to_bytes(4, 'little')
        return socket.inet_ntoa(packed)
    except Exception:
        return ''


def _hex_to_ip6(hex_str: str) -> str:
    """Convert /proc/net/tcp6 hex address (big-endian per 4-byte word)."""
    try:
        # 32 hex chars = 16 bytes, stored as 4 little-endian 32-bit words
        words = [int(hex_str[i:i+8], 16).to_bytes(4, 'little')
                 for i in range(0, 32, 8)]
        packed = b''.join(words)
        return socket.inet_ntop(socket.AF_INET6, packed)
    except Exception:
        return ''


def _read_proc_net_tcp() -> List[Tuple[str, int]]:
    """
    Return list of (remote_ip, local_port) for SYN_RECV / TIME_WAIT
    entries from /proc/net/tcp and /proc/net/tcp6.
    These represent incoming half-open or recently-closed connections —
    exactly what port scans leave behind.
    """
    results: List[Tuple[str, int]] = []

    for path, v6 in (('/proc/net/tcp', False), ('/proc/net/tcp6', True)):
        try:
            with open(path, 'r') as f:
                lines = f.readlines()[1:]  # skip header
        except (FileNotFoundError, PermissionError, OSError):
            continue

        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            state = parts[3]
            if state not in _SCAN_STATES:
                continue

            # local_addr:port (parts[1]), remote_addr:port (parts[2])
            local_raw, remote_raw = parts[1], parts[2]
            try:
                local_port = int(local_raw.split(':')[1], 16)
                rem_hex    = remote_raw.split(':')[0]
                rem_port   = int(remote_raw.split(':')[1], 16)
            except (IndexError, ValueError):
                continue

            rem_ip = _hex_to_ip6(rem_hex) if v6 else _hex_to_ip4(rem_hex)
            if not rem_ip or rem_ip.startswith(tuple(_SKIP_PREFIXES)):
                continue

            results.append((rem_ip, local_port))

    return results


def _run_ss() -> List[Tuple[str, int]]:
    """
    Fallback: run `ss -nt state syn-recv` to find SYN_RECV connections.
    Works even without /proc/net/tcp access.
    Output line: RECV-Q SEND-Q Local:Port  Remote:IP:Port ...
    """
    results: List[Tuple[str, int]] = []
    try:
        out = subprocess.run(
            ['ss', '-nt', 'state', 'syn-recv'],
            capture_output=True, text=True, timeout=3
        ).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5 or not parts[3][0].isdigit():
                continue
            try:
                local  = parts[3]   # ip:port or [ipv6]:port
                remote = parts[4]
                local_port = int(local.rsplit(':', 1)[-1])
                remote_ip  = remote.rsplit(':', 1)[0].strip('[]')
                if not remote_ip.startswith(tuple(_SKIP_PREFIXES)):
                    results.append((remote_ip, local_port))
            except (ValueError, IndexError):
                continue
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return results


class PortScanDetector:
    """
    Sliding-window unique-port counter.  Fires a scan alert when
    `unique_port_threshold` distinct destination ports are seen from
    a single source IP within `window_seconds`.

    Feed it via:
      process_proc_entry(src_ip, dst_port)   ← /proc/net/tcp polling
      process_log_entry(LogEntry)            ← syslog/firewall parsing
      process_connection(src_ip, dst_port)   ← psutil ESTABLISHED
    """

    def __init__(
        self,
        config=None,
        on_scan: Optional[Callable[[LogEntry], None]] = None,
        unique_port_threshold: int = 12,
        window_seconds: int = 60,
    ):
        # Caller is responsible for passing config values as explicit params.
        # We keep `config` only for platform detection.
        self._threshold = unique_port_threshold
        self._window    = timedelta(seconds=window_seconds)
        self._on_scan   = on_scan
        self._lock      = threading.Lock()
        self._platform  = __import__('platform').system().lower()

        # src_ip → list[(ts, dst_port)]
        self._events: Dict[str, List[Tuple[datetime, int]]] = defaultdict(list)
        # src_ip → set of unique ports in current window
        self._ports:  Dict[str, Set[int]]                   = defaultdict(set)
        # dedup: last alert time per src_ip
        self._alerted: Dict[str, datetime]                  = {}
        # proc monitoring thread
        self._running = False
        self._proc_thread: Optional[threading.Thread]       = None

    # ── Lifecycle ────────────────────────────────────────────────

    def start(self):
        """Start the 1-second /proc/net/tcp polling thread."""
        self._running = True
        self._proc_thread = threading.Thread(
            target=self._proc_loop, daemon=True, name='portscan-proc')
        self._proc_thread.start()

    def stop(self):
        self._running = False

    # ── /proc/net/tcp poller ─────────────────────────────────────

    def _proc_loop(self):
        # Use /proc/net/tcp if available; otherwise use ss
        use_proc = True
        try:
            open('/proc/net/tcp').close()
        except (FileNotFoundError, PermissionError):
            use_proc = False

        while self._running:
            try:
                pairs = _read_proc_net_tcp() if use_proc else _run_ss()
                now   = datetime.now()
                for src_ip, dst_port in pairs:
                    self._record(src_ip, dst_port, now, source='proc')
            except Exception:
                pass
            time.sleep(1)          # poll every second — crucial for fast nmap scans

    # ── Log-entry analysis ────────────────────────────────────────

    def process_log_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        """
        Try every known firewall/auth pattern against the log message.
        Returns a scan-alert LogEntry if threshold is crossed.
        """
        text = (entry.message or '') + ' ' + (entry.raw or '')
        now  = entry.timestamp or datetime.now()

        for pattern, _src, _kind in _LOG_PATTERNS:
            m = pattern.search(text)
            if not m:
                continue
            ip = m.group(1)
            try:
                port = int(m.group(2)) if m.lastindex >= 2 and m.group(2) else 0
            except (ValueError, IndexError):
                port = 0
            if ip and not ip.startswith(tuple(_SKIP_PREFIXES)):
                alert = self._record(ip, port, now, source='log')
                if alert:
                    return alert
        return None

    # ── psutil / network-monitor path ────────────────────────────

    def process_connection(
        self, src_ip: str, dst_port: int,
        ts: Optional[datetime] = None
    ) -> Optional[LogEntry]:
        if src_ip and not src_ip.startswith(tuple(_SKIP_PREFIXES)):
            return self._record(src_ip, dst_port, ts or datetime.now(),
                                source='psutil')
        return None

    # ── Core sliding-window logic ─────────────────────────────────

    def _record(
        self, src_ip: str, dst_port: int,
        ts: datetime, source: str = 'unknown'
    ) -> Optional[LogEntry]:
        with self._lock:
            cutoff = ts - self._window
            evs    = self._events[src_ip]

            # Prune stale events
            evs[:] = [(t, p) for t, p in evs if t >= cutoff]
            self._ports[src_ip] = {p for _, p in evs}

            # Record new event
            if dst_port:
                evs.append((ts, dst_port))
                self._ports[src_ip].add(dst_port)

            unique = len(self._ports[src_ip])
            if unique < self._threshold:
                return None

            # Dedup: suppress repeat alerts for same IP within 5 min
            last = self._alerted.get(src_ip, datetime.min)
            if ts - last < timedelta(minutes=5):
                return None

            self._alerted[src_ip] = ts
            scan_rate = len(evs)

        return self._make_alert(src_ip, dst_port, unique, scan_rate, source)

    # ── Alert builder ─────────────────────────────────────────────

    def _make_alert(
        self, src_ip: str, dst_port: int,
        unique_ports: int, total_attempts: int, source: str
    ) -> LogEntry:
        msg = (
            f"Port scan detected from {src_ip}: "
            f"{unique_ports} unique ports probed in {int(self._window.total_seconds())}s "
            f"({total_attempts} total attempts, detected via {source})"
        )
        entry = LogEntry(
            timestamp     = datetime.now(),
            source        = f"portscan/{src_ip}",
            level         = "CRITICAL",
            message       = msg,
            platform      = self._platform,
            raw           = msg,
            matched_rules = ["Port Scan Detected"],
            tags          = ["portscan", f"src:{src_ip}", f"method:{source}"],
            is_anomaly    = True,
            anomaly_score = 0.97,
            category      = "portscan",
            src_ip        = src_ip,
            dst_port      = dst_port,
        )
        if self._on_scan:
            self._on_scan(entry)
        return entry

    # ── Stats ─────────────────────────────────────────────────────

    def get_top_scanners(self, n: int = 10) -> List[Dict]:
        with self._lock:
            return sorted(
                [{'ip': ip, 'unique_ports': len(ports),
                  'count': len(self._events.get(ip, []))}
                 for ip, ports in self._ports.items() if ports],
                key=lambda x: -x['unique_ports'],
            )[:n]
