"""
macOS log collector.
Uses the Unified Logging System (`log show`) and /var/log/* files.
"""
import json
import os
import re
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from .base import BaseCollector, LogEntry

_SYSLOG_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(\S+?)(?:\[\d+\])?:\s*(.*)",
)
_UL_LEVEL = {
    "Default": "INFO", "Info": "INFO", "Debug": "DEBUG",
    "Error": "ERROR", "Fault": "CRITICAL",
}


class MacOSCollector(BaseCollector):
    def __init__(self, config):
        super().__init__(config)
        self.platform = "darwin"
        self._file_positions: Dict[str, int] = {}

    def get_log_files(self) -> List[str]:
        return [s.path for s in self.config.macos_sources
                if s.enabled and os.path.exists(s.path)]

    def collect(self) -> List[LogEntry]:
        entries = self._collect_unified_log()
        for src in self.config.macos_sources:
            if src.enabled and os.path.exists(src.path):
                entries.extend(self._parse_file(src.path, src.name))
        return entries

    # ── Unified Log ────────────────────────────────────────────

    def _collect_unified_log(self) -> List[LogEntry]:
        since = (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
        try:
            res = subprocess.run(
                ["log", "show", "--start", since, "--style", "json", "--last", "5m"],
                capture_output=True, text=True, timeout=20,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        if not res.stdout:
            return []
        entries = []
        try:
            logs = json.loads(res.stdout)
            for item in (logs if isinstance(logs, list) else [])[:500]:
                e = self._parse_ul_entry(item)
                if e:
                    entries.append(e)
        except (json.JSONDecodeError, TypeError):
            pass
        return entries

    def _parse_ul_entry(self, obj: dict) -> Optional[LogEntry]:
        try:
            level = _UL_LEVEL.get(obj.get("messageType", "Default"), "INFO")
            ts_str = obj.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(
                    ts_str.replace("Z", "+00:00").replace("+0000", "+00:00"))
            except (ValueError, AttributeError):
                ts = datetime.now()
            process = obj.get("process", "unknown")
            subsystem = obj.get("subsystem", "")
            source = f"{process}/{subsystem}" if subsystem else process
            msg = str(obj.get("eventMessage", ""))[:800]
            return LogEntry(timestamp=ts, source=source, level=level,
                            message=msg, platform="darwin", raw=str(obj)[:400])
        except Exception:
            return None

    # ── syslog files ───────────────────────────────────────────

    def _parse_file(self, path: str, name: str) -> List[LogEntry]:
        entries = []
        year = datetime.now().year
        try:
            size = os.path.getsize(path)
            pos = self._file_positions.get(path, max(0, size - 65536))
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(pos)
                content = f.read()
                self._file_positions[path] = f.tell()
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                m = _SYSLOG_RE.match(line)
                if m:
                    ts_str, process, msg = m.groups()
                    try:
                        ts = datetime.strptime(f"{year} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
                    except ValueError:
                        ts = datetime.now()
                    entries.append(LogEntry(
                        timestamp=ts, source=f"{name}/{process}",
                        level=self.parse_level(msg), message=msg,
                        platform="darwin", raw=line))
                else:
                    entries.append(LogEntry(
                        timestamp=datetime.now(), source=name,
                        level=self.parse_level(line), message=line,
                        platform="darwin", raw=line))
        except (PermissionError, FileNotFoundError, OSError):
            pass
        return entries
