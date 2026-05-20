"""
Windows Event Log collector.
Uses pywin32 if available, otherwise falls back to wevtutil.exe.
"""
import subprocess
from datetime import datetime
from typing import Dict, List, Optional

from .base import BaseCollector, LogEntry

_WEVT_LEVEL = {
    "information": "INFO", "verbose": "DEBUG",
    "warning": "WARNING", "error": "ERROR", "critical": "CRITICAL",
}


class WindowsCollector(BaseCollector):
    def __init__(self, config):
        super().__init__(config)
        self.platform = "windows"

    def get_log_files(self) -> List[str]:
        return []   # Windows uses event channels, not plain files

    def collect(self) -> List[LogEntry]:
        entries: List[LogEntry] = []
        try:
            import win32evtlog  # type: ignore
            for ch in self.config.windows_channels:
                entries.extend(self._collect_win32(ch))
        except ImportError:
            for ch in self.config.windows_channels:
                entries.extend(self._collect_wevtutil(ch))
        return entries

    # ── pywin32 path ───────────────────────────────────────────

    def _collect_win32(self, channel: str) -> List[LogEntry]:
        import win32evtlog, win32evtlogutil  # type: ignore
        entries: List[LogEntry] = []
        _type_map = {
            1: "ERROR", 2: "WARNING", 4: "INFO",
            8: "INFO",  16: "WARNING",
        }
        try:
            hand = win32evtlog.OpenEventLog(None, channel)
            flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                     win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            events = win32evtlog.ReadEventLog(hand, flags, 0) or []
            for ev in events[:300]:
                try:
                    level = _type_map.get(ev.EventType, "INFO")
                    msg = (win32evtlogutil.SafeFormatMessage(ev, channel) or "")[:500]
                    ts_tuple = ev.TimeGenerated.timetuple()[:6]
                    entries.append(LogEntry(
                        timestamp=datetime(*ts_tuple),
                        source=f"{channel}/{ev.SourceName}",
                        level=level, message=msg,
                        platform="windows",
                        raw=f"EventID={ev.EventID} Src={ev.SourceName}",
                    ))
                except Exception:
                    continue
            win32evtlog.CloseEventLog(hand)
        except Exception:
            pass
        return entries

    # ── wevtutil fallback ──────────────────────────────────────

    def _collect_wevtutil(self, channel: str) -> List[LogEntry]:
        try:
            res = subprocess.run(
                ["wevtutil", "qe", channel, "/c:100", "/rd:true", "/f:text"],
                capture_output=True, text=True, timeout=15,
                encoding="utf-8", errors="replace",
            )
            if res.returncode == 0:
                return self._parse_wevtutil(res.stdout, channel)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return []

    def _parse_wevtutil(self, output: str, channel: str) -> List[LogEntry]:
        entries: List[LogEntry] = []
        current: Dict[str, str] = {}

        def flush():
            if not current:
                return
            ts_str = current.get("Date", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                ts = datetime.now()
            level = _WEVT_LEVEL.get(current.get("Level", "").lower(), "INFO")
            source = current.get("Provider", channel)
            msg = current.get("Description", current.get("Message", ""))[:500]
            entries.append(LogEntry(
                timestamp=ts, source=f"{channel}/{source}",
                level=level, message=msg,
                platform="windows", raw=str(current)[:300],
            ))

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Event["):
                flush(); current = {}
            elif ":" in line:
                k, _, v = line.partition(":")
                current[k.strip()] = v.strip()

        flush()
        return entries
