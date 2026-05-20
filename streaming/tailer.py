"""
Real-time log tailer.
Uses watchdog for inotify-based file watching on Linux/macOS,
and falls back to polling on Windows or when no files are available.
"""
import os
import platform
import re
import threading
import time
from datetime import datetime
from typing import Callable, Dict, List

from collectors.base import BaseCollector, LogEntry

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent
    _HAS_WATCHDOG = True
except ImportError:
    _HAS_WATCHDOG = False

_SYSLOG_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(\S+?)(?:\[\d+\])?:\s*(.*)"
)


def _make_collector(config):
    sys_platform = platform.system().lower()
    if sys_platform == "linux":
        from collectors.linux import LinuxCollector
        return LinuxCollector(config)
    elif sys_platform == "windows":
        from collectors.windows import WindowsCollector
        return WindowsCollector(config)
    elif sys_platform == "darwin":
        from collectors.macos import MacOSCollector
        return MacOSCollector(config)
    else:
        from collectors.linux import LinuxCollector
        return LinuxCollector(config)


class LogTailer:
    """
    Watches log files in real-time and calls `on_new_entry` for every new line.
    Falls back to periodic polling when watchdog is unavailable or no files exist.
    """

    def __init__(self, config, on_new_entry: Callable[[LogEntry], None]):
        self.config = config
        self.on_new_entry = on_new_entry
        self._collector = _make_collector(config)
        self._observers: List = []
        self._running = False

    def start(self):
        self._running = True
        log_files = self._collector.get_log_files()

        if _HAS_WATCHDOG and log_files:
            self._start_watchdog(log_files)
        else:
            self._start_polling()

    def stop(self):
        self._running = False
        for obs in self._observers:
            obs.stop()
            obs.join()
        self._observers.clear()

    # ── watchdog ───────────────────────────────────────────────

    def _start_watchdog(self, log_files: List[str]):
        observer = Observer()
        watched_dirs: Dict[str, bool] = {}
        for path in log_files:
            if not os.path.exists(path):
                continue
            handler = _FileHandler(path, self.on_new_entry)
            directory = os.path.dirname(os.path.abspath(path))
            if directory not in watched_dirs:
                observer.schedule(handler, directory, recursive=False)
                watched_dirs[directory] = True
            else:
                observer.schedule(handler, directory, recursive=False)
        observer.start()
        self._observers.append(observer)

    # ── polling fallback ───────────────────────────────────────

    def _start_polling(self):
        def _poll():
            while self._running:
                try:
                    entries = self._collector.collect()
                    for entry in entries:
                        self.on_new_entry(entry)
                except Exception:
                    pass
                time.sleep(self.config.collect_interval)

        thread = threading.Thread(target=_poll, daemon=True, name="logagg-poll")
        thread.start()


if _HAS_WATCHDOG:
    class _FileHandler(FileSystemEventHandler):
        """Handles inotify file modification events for a single log file."""

        def __init__(self, path: str, callback: Callable[[LogEntry], None]):
            self._path = os.path.abspath(path)
            self._callback = callback
            self._position = os.path.getsize(path) if os.path.exists(path) else 0
            self._lock = threading.Lock()
            self._platform = platform.system().lower()
            self._name = os.path.basename(path).replace(".log", "")

        def on_modified(self, event):
            if not isinstance(event, FileModifiedEvent):
                return
            if os.path.abspath(event.src_path) != self._path:
                return
            with self._lock:
                self._drain()

        def _drain(self):
            try:
                with open(self._path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(self._position)
                    new_data = f.read()
                    self._position = f.tell()
                if not new_data:
                    return
                year = datetime.now().year
                for line in new_data.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    entry = self._parse_line(line, year)
                    self._callback(entry)
            except (OSError, PermissionError):
                pass

        def _parse_line(self, line: str, year: int) -> LogEntry:
            m = _SYSLOG_RE.match(line)
            if m:
                ts_str, process, message = m.groups()
                try:
                    ts = datetime.strptime(f"{year} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
                except ValueError:
                    ts = datetime.now()
                level = BaseCollector.parse_level(message)
                return LogEntry(timestamp=ts, source=f"{self._name}/{process}",
                                level=level, message=message,
                                platform=self._platform, raw=line)
            return LogEntry(timestamp=datetime.now(), source=self._name,
                            level=BaseCollector.parse_level(line), message=line,
                            platform=self._platform, raw=line)
