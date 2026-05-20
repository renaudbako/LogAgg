"""
DNS monitor.

Detects suspicious DNS activity by:
  1. Parsing system resolver logs (systemd-resolved, dnsmasq, named, syslog)
  2. Optionally sniffing raw DNS packets on UDP/53 via scapy (if available)

Detection signals
-----------------
  - High-entropy subdomain  →  possible DNS tunneling / DGA
  - Unusually long FQDN     →  DNS tunneling
  - High query rate from one host  →  data exfiltration or C2 beacon
  - Queries to known bad TLDs (.onion, .bit, .bazar, .coin, etc.)
  - Rapid NXDOMAIN responses  →  DGA domain cycling
"""
import math
import re
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional

from collectors.base import LogEntry

# ── Entropy helper ───────────────────────────────────────────
def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


# ── Known suspicious TLDs ─────────────────────────────────────
_BAD_TLDS = {
    ".onion", ".bit", ".bazar", ".coin", ".lib",
    ".emc", ".chan", ".fur", ".locker",
}

# ── DNS log patterns ──────────────────────────────────────────
# systemd-resolved: "query for <domain>"
# dnsmasq: "query[A] <domain> from <ip>"
# named:   "client <ip>#port: query: <domain>"
# syslog generic DNS
_PATTERNS = [
    re.compile(r"query\[(?:A+|AAAA)\]\s+([\w.\-]+)\s+from\s+([\d.]+)", re.I),
    re.compile(r"query for\s+([\w.\-]+)(?:\s+from\s+([\d.]+))?", re.I),
    re.compile(r"client\s+([\d.]+)#\d+.*query:\s+([\w.\-]+)", re.I),
    re.compile(r"NXDOMAIN.*?([\w.\-]{10,})", re.I),
    re.compile(r"resolved\s+([\w.\-]+)\s+to", re.I),
]


class DNSMonitor:
    """
    Monitors DNS activity.  Operates in two modes:
      - Log-based: parse systemd journal or syslog for DNS entries
      - Entry-based: call `process_log_entry(entry)` from the log pipeline
    """

    ENTROPY_THRESHOLD  = 3.8    # high entropy subdomain
    LENGTH_THRESHOLD   = 50     # chars in subdomain part
    RATE_THRESHOLD     = 30     # queries per minute from one host
    NXDOMAIN_THRESHOLD = 15     # NXDOMAIN count per minute (DGA cycling)

    def __init__(self, config, on_entry: Callable[[LogEntry], None]):
        self._config   = config
        self._on_entry = on_entry
        self._platform = __import__("platform").system().lower()
        self._interval = getattr(config, "dns_monitor_interval", 30)
        self._running  = False
        self._thread: Optional[threading.Thread] = None

        # Rate trackers: src_ip → deque of timestamps
        self._query_rate: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=500))
        self._nxdomain_rate: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=200))
        # dedup: (signal_type, domain) → last alerted
        self._alerted: Dict[tuple, datetime] = {}
        self._lock = threading.Lock()

    # ── Lifecycle ─────────────────────────────────────────────

    def start(self):
        self._running = True
        if self._platform == "linux":
            self._thread = threading.Thread(
                target=self._journal_loop, daemon=True, name="dnsmon")
            self._thread.start()

    def stop(self):
        self._running = False

    # ── Log pipeline entry point ──────────────────────────────

    def process_log_entry(self, entry: LogEntry):
        """
        Called from the main pipeline for every log entry.
        Extracts domain + src from the message if it looks DNS-related.
        """
        text = entry.message + " " + entry.raw
        self._parse_text(text, entry.timestamp or datetime.now())

    # ── Internal: journal polling (Linux) ─────────────────────

    def _journal_loop(self):
        cmd = ["journalctl", "-f", "-u", "systemd-resolved",
               "-u", "dnsmasq", "-u", "named",
               "--no-pager", "-o", "short"]
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True)
        except FileNotFoundError:
            return

        while self._running:
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.5)
                continue
            self._parse_text(line.strip(), datetime.now())

        proc.terminate()

    # ── Parsing ───────────────────────────────────────────────

    def _parse_text(self, text: str, ts: datetime):
        domain, src_ip = None, "unknown"
        is_nxdomain = "NXDOMAIN" in text.upper()

        for pat in _PATTERNS:
            m = pat.search(text)
            if not m:
                continue
            groups = [g for g in m.groups() if g]
            if not groups:
                continue
            # Heuristic: longer group is domain, dotted-decimal is IP
            for g in groups:
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", g):
                    src_ip = g
                elif "." in g and len(g) > 4:
                    domain = g.lower().rstrip(".")
            if domain:
                break

        if not domain:
            return

        with self._lock:
            self._query_rate[src_ip].append(ts)
            if is_nxdomain:
                self._nxdomain_rate[domain].append(ts)
            self._analyse(domain, src_ip, ts, is_nxdomain)

    def _analyse(self, domain: str, src: str,
                 ts: datetime, is_nxdomain: bool):
        parts       = domain.split(".")
        subdomain   = parts[0] if len(parts) > 2 else domain
        tld         = "." + parts[-1] if parts else ""
        entropy     = _shannon(subdomain)
        sub_len     = len(subdomain)

        # ── Suspicious TLD ────────────────────────────────────
        if tld in _BAD_TLDS:
            self._maybe_emit(("bad_tld", domain), ts, "CRITICAL",
                f"DNS query to suspicious TLD {tld}: {domain}  src={src}",
                ["DNS Tunneling"], ["bad_tld", f"tld:{tld}"])

        # ── High-entropy subdomain (possible DGA / tunneling) ─
        elif entropy > self.ENTROPY_THRESHOLD and sub_len > 10:
            self._maybe_emit(("entropy", domain[:30]), ts, "WARNING",
                f"High-entropy DNS subdomain ({entropy:.2f} bits): "
                f"{domain}  src={src}",
                ["DNS Tunneling"], ["high_entropy_dns"])

        # ── Very long subdomain (data encoding) ──────────────
        elif sub_len > self.LENGTH_THRESHOLD:
            self._maybe_emit(("long", domain[:30]), ts, "WARNING",
                f"Unusually long DNS subdomain ({sub_len} chars): "
                f"{domain}  src={src}",
                ["DNS Tunneling"], ["long_subdomain"])

        # ── High query rate from single host ──────────────────
        cutoff = ts - timedelta(minutes=1)
        rate   = sum(1 for t in self._query_rate[src] if t >= cutoff)
        if rate > self.RATE_THRESHOLD:
            self._maybe_emit(("rate", src), ts, "WARNING",
                f"High DNS query rate from {src}: {rate} queries/min",
                ["DNS Tunneling"], ["high_dns_rate", f"src:{src}"])

        # ── NXDOMAIN storm (DGA domain cycling) ───────────────
        nx_rate = sum(1 for t in self._nxdomain_rate.get(domain, [])
                      if t >= cutoff)
        if is_nxdomain and nx_rate > self.NXDOMAIN_THRESHOLD:
            self._maybe_emit(("nxdomain", src), ts, "WARNING",
                f"NXDOMAIN storm from {src}: {nx_rate} failures/min "
                f"(possible DGA cycling)",
                ["DNS Tunneling"], ["nxdomain_storm"])

    def _maybe_emit(self, key: tuple, ts: datetime, level: str,
                    msg: str, rules: List[str], tags: List[str]):
        last = self._alerted.get(key, datetime.min)
        if ts - last < timedelta(minutes=5):
            return
        self._alerted[key] = ts
        entry = LogEntry(
            timestamp     = ts,
            source        = "dns-monitor",
            level         = level,
            message       = msg,
            platform      = self._platform,
            raw           = msg,
            matched_rules = rules,
            tags          = tags,
            is_anomaly    = True,
            anomaly_score = 0.8 if level == "WARNING" else 0.95,
            category      = "network",
            protocol      = "DNS",
        )
        self._on_entry(entry)
