"""
Two-layer anomaly detection:
  1. Statistical  – z-score on per-source event frequency (fast, always on)
  2. ML           – Isolation Forest on message features (optional, needs scikit-learn)
"""
import hashlib
import math
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import numpy as np

from collectors.base import LogEntry

try:
    from sklearn.ensemble import IsolationForest
    _HAS_SKLEARN = True
except ImportError:
    _HAS_SKLEARN = False

_LEVEL_SCORE = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}


def _featurize(entry: LogEntry) -> List[float]:
    """Convert a LogEntry to a fixed-size numeric feature vector."""
    hour = entry.timestamp.hour
    msg = entry.message.lower()
    return [
        _LEVEL_SCORE.get(entry.level, 1),
        math.log1p(len(entry.message)),
        hour / 23.0,
        int(entry.timestamp.weekday() >= 5),   # weekend
        int("error" in msg or "fail" in msg),
        int("warn" in msg),
        int("sudo" in msg or "root" in msg),
        int("ssh" in msg or "login" in msg),
        int("wget" in msg or "curl" in msg),
        # simple lexical hash bucket (0–1)
        int(hashlib.md5(entry.source.encode()).hexdigest(), 16) % 100 / 100.0,
    ]


class AnomalyDetector:
    """
    Thread-safe anomaly detector. Call `score(entry)` for every new entry;
    it returns (is_anomaly: bool, score: float).
    """

    def __init__(self, config):
        self._cfg = config
        self._lock = threading.Lock()

        # Statistical layer: sliding window of (timestamp, source) pairs
        self._window: deque = deque()
        self._window_seconds = 60
        self._source_counts: Dict[str, deque] = defaultdict(lambda: deque())

        # ML layer
        self._ml_enabled = config.ml_enabled and _HAS_SKLEARN
        self._train_size = config.ml_train_size
        self._contamination = config.ml_contamination
        self._threshold = config.anomaly_threshold
        self._model: Optional["IsolationForest"] = None
        self._buffer: List[List[float]] = []
        self._trained = False

    # ── Public API ─────────────────────────────────────────────

    def score(self, entry: LogEntry):
        """
        Annotates entry.is_anomaly and entry.anomaly_score in-place.
        Returns (is_anomaly, score).
        """
        with self._lock:
            stat_anomaly, stat_score = self._statistical_score(entry)
            ml_anomaly, ml_score = self._ml_score(entry)

        # Combine: either layer can flag
        combined = max(stat_score, ml_score)
        is_anom = stat_anomaly or ml_anomaly

        entry.anomaly_score = round(combined, 4)
        entry.is_anomaly = is_anom
        return is_anom, combined

    # ── Statistical ────────────────────────────────────────────

    def _statistical_score(self, entry: LogEntry):
        now = entry.timestamp
        cutoff = now - timedelta(seconds=self._window_seconds)

        # Prune global window
        while self._window and self._window[0] < cutoff:
            self._window.popleft()
        self._window.append(now)

        # Per-source rate
        src_q = self._source_counts[entry.source]
        while src_q and src_q[0] < cutoff:
            src_q.popleft()
        src_q.append(now)

        rate = len(src_q)           # events from this source in last 60 s
        global_rate = len(self._window)

        # Critical/Error always gets a boost
        level_boost = 0.3 if entry.level in ("ERROR", "CRITICAL") else 0.0

        # Z-score proxy: flag if source rate > 3× global average per source
        n_sources = max(len(self._source_counts), 1)
        avg_per_source = global_rate / n_sources
        if avg_per_source > 0 and rate > 3 * avg_per_source:
            return True, min(0.9 + level_boost, 1.0)

        if entry.level in ("ERROR", "CRITICAL"):
            return False, level_boost

        return False, 0.0

    # ── ML (Isolation Forest) ──────────────────────────────────

    def _ml_score(self, entry: LogEntry):
        if not self._ml_enabled:
            return False, 0.0

        vec = _featurize(entry)
        self._buffer.append(vec)

        if not self._trained:
            if len(self._buffer) >= self._train_size:
                self._fit()
            return False, 0.0

        X = np.array([vec])
        raw_score = float(self._model.score_samples(X)[0])
        # Isolation Forest: more negative = more anomalous
        # Normalise to [0, 1] where 1 = most anomalous
        normalised = max(0.0, -raw_score)
        is_anom = raw_score < self._threshold
        return is_anom, min(normalised, 1.0)

    def _fit(self):
        try:
            X = np.array(self._buffer[-self._train_size:])
            self._model = IsolationForest(
                n_estimators=100,
                contamination=self._contamination,
                random_state=42,
                n_jobs=1,
            )
            self._model.fit(X)
            self._trained = True
            # Keep a rolling buffer of last 2× train_size
            self._buffer = self._buffer[-self._train_size * 2:]
        except Exception:
            pass

    def retrain(self):
        """Trigger a manual retrain with latest buffered data."""
        with self._lock:
            if len(self._buffer) >= 100:
                self._fit()

    @property
    def model_ready(self) -> bool:
        return self._trained

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)
