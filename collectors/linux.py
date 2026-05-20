"""
Linux log collector.
Reads from journald (preferred) and /var/log/* syslog-format files.
"""
import json
import os
import re
import subprocess
from datetime import datetime
from typing import Dict, List, Optional

from .base import BaseCollector, LogEntry

# Oct 15 10:30:00 hostname process[pid]: message
_SYSLOG_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(\S+?)(?:\[\d+\])?:\s*(.*)",
    re.MULTILINE,
)

_PRIORITY = {"0": "CRITICAL", "1": "CRITICAL", "2": "CRITICAL",
             "3": "ERROR", "4": "WARNING", "5": "INFO",
             "6": "INFO", "7": "DEBUG"}


class LinuxCollector(BaseCollector):
    def __init__(self, config):
        super().__init__(config)
        self.platform = "linux"
        self._file_positions: Dict[str, int] = {}

    # ── public API ─────────────────────────────────────────────

    def get_log_files(self) -> List[str]:
        return [s.path for s in self.config.linux_sources
                if s.enabled and os.path.exists(s.path)]

    def collect(self) -> List[LogEntry]:
        entries = self._collect_journald()
        if not entries:
            for src in self.config.linux_sources:
                if src.enabled and os.path.exists(src.path):
                    entries.extend(self._parse_file(src.path, src.name, initial=True))
        return entries

    # ── journald ───────────────────────────────────────────────

    def _collect_journald(self) -> List[LogEntry]:
        try:
            result = subprocess.run(
                ["journalctl", "-n", "500", "--no-pager",
                 "-o", "json", "--since", "5 minutes ago"],
                capture_output=True, text=True, timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        entries = []
        if result.returncode != 0:
            return entries

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                e = self._parse_journald(obj)
                if e:
                    entries.append(e)
            except json.JSONDecodeError:
                pass
        return entries

    def _parse_journald(self, obj: dict) -> Optional[LogEntry]:
        try:
            level = _PRIORITY.get(str(obj.get("PRIORITY", "6")), "INFO")
            ts_us = int(obj.get("__REALTIME_TIMESTAMP", 0))
            ts = datetime.fromtimestamp(ts_us / 1_000_000) if ts_us else datetime.now()
            msg = obj.get("MESSAGE", "")
            if isinstance(msg, list):
                msg = " ".join(str(c) for c in msg)
            source = obj.get("SYSLOG_IDENTIFIER") or obj.get("_COMM") or "journald"
            unit = obj.get("_SYSTEMD_UNIT", "")
            if unit:
                source = f"{source}({unit})"
            return LogEntry(timestamp=ts, source=source, level=level,
                            message=str(msg)[:1000], platform="linux", raw=str(obj)[:500])
        except Exception:
            return None

    # ── syslog files ───────────────────────────────────────────

    def _parse_file(self, path: str, name: str, initial: bool = False) -> List[LogEntry]:
        entries = []
        year = datetime.now().year
        try:
            size = os.path.getsize(path)
            pos = self._file_positions.get(path, 0)
            if initial:
                # Read last N lines on startup
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()[-self.config.max_initial_lines:]
                self._file_positions[path] = size
                for line in lines:
                    e = self._parse_syslog_line(line.strip(), name, year)
                    if e:
                        entries.append(e)
            else:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(pos)
                    content = f.read()
                    self._file_positions[path] = f.tell()
                for line in content.splitlines():
                    e = self._parse_syslog_line(line.strip(), name, year)
                    if e:
                        entries.append(e)
        except (PermissionError, FileNotFoundError, OSError):
            pass
        return entries

    def _parse_syslog_line(self, line: str, name: str, year: int) -> Optional[LogEntry]:
        if not line:
            return None
        m = _SYSLOG_RE.match(line)
        if m:
            ts_str, process, message = m.groups()
            try:
                ts = datetime.strptime(f"{year} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
            except ValueError:
                ts = datetime.now()
            return LogEntry(timestamp=ts, source=f"{name}/{process}",
                            level=self.parse_level(message), message=message,
                            platform="linux", raw=line)
        return LogEntry(timestamp=datetime.now(), source=name,
                        level=self.parse_level(line), message=line,
                        platform="linux", raw=line)
