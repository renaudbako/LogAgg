"""
File Integrity Monitor (FIM).

Maintains a SHA-256 baseline of critical system files.
Change detection via:
  1. watchdog inotify/kqueue events (immediate on Linux/macOS)
  2. Periodic full-rescan fallback (every `rescan_interval` seconds)

Emits LogEntry objects with category="fim" on any:
  - Modification  (hash changed)
  - Deletion      (file disappeared)
  - Creation      (new file in watched directory)
  - Permission change (st_mode changed)
"""
import hashlib
import os
import platform
import stat
import threading
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set, Tuple

from collectors.base import LogEntry

try:
    from watchdog.observers import Observer
    from watchdog.events import (FileSystemEventHandler,
                                 FileModifiedEvent, FileDeletedEvent,
                                 FileCreatedEvent, FileMovedEvent)
    _HAS_WATCHDOG = True
except ImportError:
    _HAS_WATCHDOG = False


def _sha256(path: str) -> Optional[str]:
    """Return hex SHA-256 of file, or None on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _file_meta(path: str) -> Optional[Tuple[str, int, int]]:
    """Return (sha256, size, st_mode) or None."""
    try:
        st = os.stat(path)
        digest = _sha256(path)
        if digest is None:
            return None
        return digest, st.st_size, stat.S_IMODE(st.st_mode)
    except OSError:
        return None


class FileIntegrityMonitor:
    """
    Monitors a list of files and directories for changes.
    Baseline is persisted to the database so changes during downtime
    are detected on the next restart without false-positive storms.
    """

    def __init__(self, config, on_entry: Callable[[LogEntry], None],
                 db=None):
        self._config = config
        self._on_entry = on_entry
        self._db = db                    # optional Database instance for persistence
        self._platform = platform.system().lower()
        self._rescan_interval = getattr(config, "fim_rescan_interval", 60)

        self._baseline: Dict[str, Tuple[str, int, int]] = {}
        self._lock = threading.Lock()
        self._running = False
        self._observer: Optional["Observer"] = None
        self._rescan_thread: Optional[threading.Thread] = None

        self._watch_dirs: Set[str] = set()
        self._watch_files: Set[str] = set()

        self._load_watch_list()

    # ── Config loading ─────────────────────────────────────────

    def _load_watch_list(self):
        paths: List[str] = getattr(self._config, "fim_paths", [])
        for p in paths:
            p = os.path.expanduser(p)
            if os.path.isdir(p):
                self._watch_dirs.add(p)
            elif os.path.exists(p):
                self._watch_files.add(p)
                self._watch_dirs.add(os.path.dirname(p))
            else:
                # Non-existent yet — watch parent dir
                parent = os.path.dirname(p)
                if os.path.isdir(parent):
                    self._watch_dirs.add(parent)

    # ── Lifecycle ──────────────────────────────────────────────

    def start(self):
        self._running = True
        # Load persisted baseline first (avoids false positives on restart)
        if self._db:
            try:
                persisted = self._db.load_fim_baseline()
                if persisted:
                    with self._lock:
                        self._baseline = persisted
            except Exception:
                pass
        # Then build/refresh the live baseline
        self._build_baseline()

        if _HAS_WATCHDOG and self._watch_dirs:
            self._start_watchdog()

        self._rescan_thread = threading.Thread(
            target=self._rescan_loop, daemon=True, name="fim-rescan")
        self._rescan_thread.start()

    def stop(self):
        self._running = False
        if self._observer:
            self._observer.stop()
            self._observer.join()

    # ── Baseline ───────────────────────────────────────────────

    def _build_baseline(self):
        with self._lock:
            for path in self._all_watched_files():
                meta = _file_meta(path)
                if meta:
                    self._baseline[path] = meta

    def _all_watched_files(self) -> List[str]:
        """Walk watch directories + individual files."""
        seen: Set[str] = set()
        result = []

        for f in self._watch_files:
            if f not in seen and os.path.isfile(f):
                seen.add(f)
                result.append(f)

        for d in self._watch_dirs:
            try:
                for entry in os.scandir(d):
                    if entry.is_file(follow_symlinks=False):
                        if entry.path not in seen:
                            seen.add(entry.path)
                            result.append(entry.path)
            except (PermissionError, OSError):
                pass

        return result

    # ── Watchdog integration ───────────────────────────────────

    def _start_watchdog(self):
        self._observer = Observer()
        for d in self._watch_dirs:
            if os.path.isdir(d):
                handler = _FIMHandler(self)
                self._observer.schedule(handler, d, recursive=False)
        self._observer.start()

    def handle_event(self, event_type: str, path: str):
        """Called by _FIMHandler for watchdog events."""
        path = os.path.abspath(path)
        if not self._is_watched(path):
            return

        if event_type in ("modified", "created"):
            self._check_file(path, event_type)
        elif event_type == "deleted":
            self._handle_deletion(path)
        elif event_type == "moved":
            self._handle_deletion(path)

    def _is_watched(self, path: str) -> bool:
        if path in self._watch_files:
            return True
        parent = os.path.dirname(path)
        return parent in self._watch_dirs

    # ── Rescan loop ────────────────────────────────────────────

    def _rescan_loop(self):
        while self._running:
            time.sleep(self._rescan_interval)
            if not self._running:
                break
            try:
                self._full_rescan()
            except Exception:
                pass

    def _full_rescan(self):
        current_files = set(self._all_watched_files())
        with self._lock:
            baseline_files = set(self._baseline.keys())

        for path in current_files:
            self._check_file(path, "rescan")

        for path in baseline_files - current_files:
            self._handle_deletion(path)

        # Persist updated baseline to DB
        if self._db:
            try:
                with self._lock:
                    snapshot = dict(self._baseline)
                self._db.save_fim_baseline(snapshot)
            except Exception:
                pass

    # ── File checking ──────────────────────────────────────────

    def _check_file(self, path: str, trigger: str):
        meta = _file_meta(path)
        if meta is None:
            return

        new_hash, new_size, new_mode = meta

        with self._lock:
            baseline = self._baseline.get(path)
            if baseline is None:
                # New file
                self._baseline[path] = meta
                if trigger != "rescan":
                    self._emit_event("created", path, "", new_hash,
                                     new_mode, new_size)
                return

            old_hash, old_size, old_mode = baseline

            if new_hash != old_hash:
                self._baseline[path] = meta
                self._emit_event("modified", path, old_hash, new_hash,
                                 new_mode, new_size)
            elif new_mode != old_mode:
                self._baseline[path] = meta
                self._emit_event("permission_changed", path, old_hash, new_hash,
                                 new_mode, new_size,
                                 extra=f"mode {oct(old_mode)}→{oct(new_mode)}")

    def _handle_deletion(self, path: str):
        with self._lock:
            if path not in self._baseline:
                return
            old_hash, _, _ = self._baseline.pop(path)
        self._emit_event("deleted", path, old_hash, "", 0, 0)

    # ── Emit ───────────────────────────────────────────────────

    def _emit_event(self, event_type: str, path: str,
                    old_hash: str, new_hash: str,
                    mode: int, size: int, extra: str = ""):
        fname = os.path.basename(path)
        level_map = {
            "modified":          "CRITICAL",
            "deleted":           "CRITICAL",
            "created":           "WARNING",
            "permission_changed":"WARNING",
        }
        level = level_map.get(event_type, "WARNING")

        details = extra or (
            f"new_hash={new_hash[:12]}…" if new_hash else f"old_hash={old_hash[:12]}…"
        )
        msg = f"FIM [{event_type.upper()}] {path} — {details}"

        entry = LogEntry(
            timestamp=datetime.now(),
            source=f"fim/{fname}",
            level=level,
            message=msg,
            platform=self._platform,
            raw=msg,
            matched_rules=["File Integrity Violation"],
            tags=["fim", event_type, f"file:{fname}"],
            is_anomaly=True,
            anomaly_score=0.9 if level == "CRITICAL" else 0.6,
            category="fim",
            filepath=path,
            file_hash=new_hash or old_hash,
        )
        self._on_entry(entry)

    @property
    def baseline_count(self) -> int:
        return len(self._baseline)

    def get_baseline_snapshot(self, limit: int = 500) -> List[Dict]:
        with self._lock:
            items = list(self._baseline.items())
        return [
            {"path": p, "hash": meta[0][:16] + "…", "size": meta[1],
             "mode": oct(meta[2])}
            for p, meta in items[:limit]
        ]


# ── Watchdog handler ───────────────────────────────────────────
if _HAS_WATCHDOG:
    class _FIMHandler(FileSystemEventHandler):
        def __init__(self, fim: "FileIntegrityMonitor"):
            self._fim = fim

        def on_modified(self, event):
            if not event.is_directory:
                self._fim.handle_event("modified", event.src_path)

        def on_created(self, event):
            if not event.is_directory:
                self._fim.handle_event("created", event.src_path)

        def on_deleted(self, event):
            if not event.is_directory:
                self._fim.handle_event("deleted", event.src_path)

        def on_moved(self, event):
            if not event.is_directory:
                self._fim.handle_event("moved", event.src_path)
