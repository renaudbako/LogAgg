"""
Alert manager: deduplicates, rate-limits, and stores alerts.
Also provides the SocketIO push hook for real-time delivery.
"""
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Callable, Dict, Optional

from collectors.base import LogEntry
from storage.database import Database


class AlertManager:
    """
    Receives annotated LogEntry objects, decides whether to fire an alert,
    persists to DB, and calls the optional `on_alert` callback (e.g. SocketIO emit).
    """

    # Don't re-fire the same rule for the same source more than once per window
    _DEDUP_WINDOW_SECONDS = 120

    def __init__(self, db: Database,
                 on_alert: Optional[Callable[[Dict], None]] = None):
        self._db = db
        self._on_alert = on_alert
        self._lock = threading.Lock()
        # key: (rule_name, source) → last fired time
        self._last_fired: Dict[tuple, datetime] = defaultdict(
            lambda: datetime.min)
        # counters for dashboard stats
        self._total_fired = 0

    # ── Public API ─────────────────────────────────────────────

    def process(self, entry: LogEntry):
        """Call this for every annotated entry. Fires alerts as needed."""
        if entry.matched_rules:
            self._fire_rule_alerts(entry)
        if entry.is_anomaly and not entry.matched_rules:
            self._fire_anomaly_alert(entry)

    # ── Internal ───────────────────────────────────────────────

    def _fire_rule_alerts(self, entry: LogEntry):
        for rule in entry.matched_rules:
            key = (rule, entry.source)
            with self._lock:
                last = self._last_fired[key]
                if datetime.now() - last < timedelta(seconds=self._DEDUP_WINDOW_SECONDS):
                    continue
                self._last_fired[key] = datetime.now()

            level = self._rule_level(rule, entry)
            self._emit_and_store(rule, level, entry)

    def _fire_anomaly_alert(self, entry: LogEntry):
        key = ("__anomaly__", entry.source)
        with self._lock:
            last = self._last_fired[key]
            if datetime.now() - last < timedelta(seconds=self._DEDUP_WINDOW_SECONDS):
                return
            self._last_fired[key] = datetime.now()

        self._emit_and_store(
            "Anomaly Detected",
            "warning",
            entry,
            override_msg=f"Statistical anomaly from {entry.source} "
                         f"(score={entry.anomaly_score:.3f}): {entry.message[:100]}",
        )

    def _emit_and_store(self, rule_name: str, level: str,
                        entry: LogEntry, override_msg: Optional[str] = None):
        msg = override_msg or entry.message[:300]
        self._db.insert_alert(rule_name, level, msg, entry.source, entry.id)
        self._total_fired += 1

        if self._on_alert:
            try:
                self._on_alert({
                    "rule": rule_name,
                    "level": level,
                    "message": msg,
                    "source": entry.source,
                    "timestamp": entry.timestamp.isoformat(),
                    "log_id": entry.id,
                })
            except Exception:
                pass

    @staticmethod
    def _rule_level(rule_name: str, entry: LogEntry) -> str:
        """Derive level from entry's own level if it's elevated."""
        if entry.level == "CRITICAL":
            return "critical"
        if entry.level in ("ERROR", "WARNING"):
            return "warning"
        return "info"

    # ── Stats ──────────────────────────────────────────────────

    @property
    def total_fired(self) -> int:
        return self._total_fired
