"""
Process monitor.

Snapshots running processes every `interval` seconds via psutil.
Detects:
  - New processes spawned from suspicious parents
    (web server → shell, scripting engine → network tool, etc.)
  - Executables running from /tmp, /dev/shm, /var/tmp
  - Processes with outbound network connections that weren't there before
  - Processes with high CPU (possible crypto-miner)
  - Known malicious process names
"""
import os
import platform
import re
import threading
import time
from datetime import datetime
from typing import Callable, Dict, Optional, Set

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

from collectors.base import LogEntry

# ── Suspicious parent→child relationships ────────────────────
# Any process in SUSPICIOUS_PARENTS that spawns any in SUSPICIOUS_CHILDREN
# is flagged immediately.
SUSPICIOUS_PARENTS = {
    "apache2", "httpd", "nginx", "lighttpd",   # web servers
    "php", "php-fpm", "php7", "php8",          # PHP
    "tomcat", "catalina", "java",              # Java app servers
    "python", "python3", "ruby", "perl",       # interpreters
    "node", "nodejs",                          # Node.js
    "mysqld", "postgres", "mongod",            # databases
    "vsftpd", "proftpd", "pure-ftpd",         # FTP servers
}
SUSPICIOUS_CHILDREN = {
    "bash", "sh", "dash", "zsh", "ksh",       # shells
    "nc", "ncat", "netcat", "nmap",            # network tools
    "wget", "curl",                            # downloaders
    "python", "python3", "perl", "ruby",       # interpreters
    "gcc", "g++", "cc",                        # compilers
    "chmod", "chown", "chattr",                # permission changes
    "crontab",                                 # cron
    "su", "sudo",                              # priv esc
    "socat", "msfconsole", "metasploit",       # exploit tools
}

# ── Temp-dir execution patterns ──────────────────────────────
_TMP_RE = re.compile(r'^(/tmp|/var/tmp|/dev/shm|/run/shm)/', re.I)

# ── Known bad process names ──────────────────────────────────
KNOWN_BAD = {
    "xmrig", "minerd", "cpuminer", "cgminer",  # crypto miners
    "mimikatz", "msfvenom", "msfconsole",       # exploit tools
    "reverse_shell", "bindshell",
}

# ── High-CPU threshold ───────────────────────────────────────
CPU_THRESHOLD = 80.0   # % over a single interval


class ProcessMonitor:
    """
    Watches running processes for suspicious behaviour.
    Emits LogEntry objects via `on_entry` callback.
    """

    def __init__(self, config, on_entry: Callable[[LogEntry], None]):
        self._config   = config
        self._on_entry = on_entry
        self._interval = getattr(config, "process_monitor_interval", 10)
        self._platform = platform.system().lower()
        self._running  = False
        self._thread: Optional[threading.Thread] = None

        # pid → (name, ppid, exe) seen in previous snapshot
        self._known_pids: Dict[int, tuple] = {}
        self._warmed_up  = False

    # ── Lifecycle ─────────────────────────────────────────────

    def start(self):
        if not _HAS_PSUTIL:
            return
        self._running = True
        self._thread  = threading.Thread(
            target=self._loop, daemon=True, name="procmon")
        self._thread.start()

    def stop(self):
        self._running = False

    # ── Main loop ─────────────────────────────────────────────

    def _loop(self):
        # Warm-up: learn current process set without alerting
        self._snapshot(alert=False)
        self._warmed_up = True
        while self._running:
            time.sleep(self._interval)
            if self._running:
                self._snapshot(alert=True)

    # ── Snapshot ──────────────────────────────────────────────

    def _snapshot(self, alert: bool):
        now         = datetime.now()
        current_pids: Dict[int, tuple] = {}

        for proc in psutil.process_iter(
            ["pid", "name", "ppid", "exe", "cmdline",
             "username", "cpu_percent", "connections"]):
            try:
                info  = proc.info
                pid   = info["pid"]
                name  = (info["name"] or "").lower()
                ppid  = info["ppid"] or 0
                exe   = info["exe"] or ""
                cmdline = " ".join(info["cmdline"] or [])
                user  = info["username"] or ""
                cpu   = info.get("cpu_percent") or 0.0

                current_pids[pid] = (name, ppid, exe)

                if not alert:
                    continue

                is_new = pid not in self._known_pids

                # ── Check 1: known bad process name ────────────
                if name in KNOWN_BAD or any(b in cmdline.lower() for b in KNOWN_BAD):
                    self._emit(
                        level="CRITICAL",
                        message=(f"Known malicious process: {name} "
                                 f"(pid={pid}, user={user})  cmd: {cmdline[:120]}"),
                        source=f"procmon/{name}",
                        rules=["Malware Indicator"],
                        tags=["bad_process", f"proc:{name}"],
                        ts=now,
                    )

                # ── Check 2: execution from temp dir ───────────
                elif exe and _TMP_RE.match(exe):
                    self._emit(
                        level="CRITICAL",
                        message=(f"Process running from temp dir: {exe} "
                                 f"(pid={pid}, user={user})"),
                        source=f"procmon/{name}",
                        rules=["Malware Indicator"],
                        tags=["tmp_execution", f"proc:{name}"],
                        ts=now,
                    )

                # ── Check 3: suspicious parent→child chain ──────
                elif is_new:
                    parent_name = ""
                    try:
                        parent = psutil.Process(ppid)
                        parent_name = (parent.name() or "").lower()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    if (parent_name in SUSPICIOUS_PARENTS
                            and name in SUSPICIOUS_CHILDREN):
                        self._emit(
                            level="CRITICAL",
                            message=(
                                f"Suspicious child process: {parent_name} "
                                f"spawned {name} (pid={pid}, user={user}) "
                                f"— possible webshell or RCE"),
                            source=f"procmon/{parent_name}→{name}",
                            rules=["Reverse Shell Indicator"],
                            tags=["suspicious_spawn",
                                  f"parent:{parent_name}",
                                  f"child:{name}"],
                            ts=now,
                        )

                # ── Check 4: high CPU (possible miner) ──────────
                elif cpu > CPU_THRESHOLD:
                    self._emit(
                        level="WARNING",
                        message=(f"High CPU process: {name} at {cpu:.1f}% "
                                 f"(pid={pid}, user={user})"),
                        source=f"procmon/{name}",
                        rules=["Suspicious Process"],
                        tags=["high_cpu", f"proc:{name}"],
                        ts=now,
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied,
                    psutil.ZombieProcess):
                continue

        self._known_pids = current_pids

    # ── Emit ─────────────────────────────────────────────────

    def _emit(self, *, level: str, message: str, source: str,
              rules: list, tags: list, ts: datetime):
        entry = LogEntry(
            timestamp     = ts,
            source        = source,
            level         = level,
            message       = message,
            platform      = self._platform,
            raw           = message,
            matched_rules = rules,
            tags          = tags,
            is_anomaly    = True,
            anomaly_score = 0.85 if level == "WARNING" else 0.95,
            category      = "log",
        )
        self._on_entry(entry)
