"""
Two-layer anomaly detection:
  1. Statistical  – z-score on per-source event frequency (always on)
  2. ML           – Isolation Forest (optional, needs scikit-learn)

The trained model is persisted with joblib so it survives restarts.
"""
import hashlib
import math
import os
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import numpy as np

from collectors.base import LogEntry

try:
    from sklearn.ensemble import IsolationForest
    import joblib
    _HAS_SKLEARN = True
except ImportError:
    _HAS_SKLEARN = False

_LEVEL_SCORE = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}


def _featurize(entry: LogEntry) -> List[float]:
    hour = entry.timestamp.hour
    msg  = entry.message.lower()
    return [
        _LEVEL_SCORE.get(entry.level, 1),
        math.log1p(len(entry.message)),
        hour / 23.0,
        int(entry.timestamp.weekday() >= 5),
        int("error" in msg or "fail" in msg),
        int("warn" in msg),
        int("sudo" in msg or "root" in msg),
        int("ssh" in msg or "login" in msg),
        int("wget" in msg or "curl" in msg),
        int(hashlib.md5(entry.source.encode()).hexdigest(), 16) % 100 / 100.0,
    ]


class AnomalyDetector:
    def __init__(self, config):
        self._cfg            = config
        self._lock           = threading.Lock()
        self._model_path     = getattr(config, "ml_model_path", "logagg_iforest.pkl")
        self._metadata_path  = self._model_path + ".meta"
        self._window: deque  = deque()
        self._window_secs    = 60
        self._source_counts: Dict[str, deque] = defaultdict(lambda: deque())
        self._ml_enabled     = config.ml_enabled and _HAS_SKLEARN
        self._train_size     = config.ml_train_size
        self._contamination  = config.ml_contamination
        self._threshold      = config.anomaly_threshold
        self._model: Optional["IsolationForest"] = None
        self._buffer: List[List[float]] = []
        self._trained        = False
        self._trained_at: Optional[datetime] = None
        if self._ml_enabled:
            self._load_model()

    def score(self, entry: LogEntry):
        with self._lock:
            stat_anom, stat_score = self._statistical_score(entry)
            ml_anom,   ml_score   = self._ml_score(entry)
        combined = max(stat_score, ml_score)
        entry.anomaly_score = round(combined, 4)
        entry.is_anomaly    = stat_anom or ml_anom
        return entry.is_anomaly, combined

    def _statistical_score(self, entry: LogEntry):
        now    = entry.timestamp
        cutoff = now - timedelta(seconds=self._window_secs)
        while self._window and self._window[0] < cutoff:
            self._window.popleft()
        self._window.append(now)
        src_q = self._source_counts[entry.source]
        while src_q and src_q[0] < cutoff:
            src_q.popleft()
        src_q.append(now)
        rate        = len(src_q)
        global_rate = len(self._window)
        boost       = 0.3 if entry.level in ("ERROR", "CRITICAL") else 0.0
        avg         = global_rate / max(len(self._source_counts), 1)
        if avg > 0 and rate > 3 * avg:
            return True, min(0.9 + boost, 1.0)
        if entry.level in ("ERROR", "CRITICAL"):
            return False, boost
        return False, 0.0

    def _ml_score(self, entry: LogEntry):
        if not self._ml_enabled:
            return False, 0.0
        vec = _featurize(entry)
        self._buffer.append(vec)
        if not self._trained:
            if len(self._buffer) >= self._train_size:
                self._fit()
            return False, 0.0
        X    = np.array([vec])
        raw  = float(self._model.score_samples(X)[0])
        norm = max(0.0, -raw)
        return raw < self._threshold, min(norm, 1.0)

    def _fit(self):
        try:
            X = np.array(self._buffer[-self._train_size:])
            m = IsolationForest(n_estimators=100, contamination=self._contamination,
                                random_state=42, n_jobs=1)
            m.fit(X)
            self._model      = m
            self._trained    = True
            self._trained_at = datetime.now()
            self._buffer     = self._buffer[-self._train_size * 2:]
            self._save_model()
        except Exception as exc:
            print(f"[AnomalyDetector] fit failed: {exc}")

    def _save_model(self):
        try:
            joblib.dump(self._model, self._model_path)
            with open(self._metadata_path, "w") as f:
                f.write(f"{self._trained_at.isoformat() if self._trained_at else ''}\n"
                        f"{self._train_size}\n{self._contamination}\n")
        except Exception as exc:
            print(f"[AnomalyDetector] save failed: {exc}")

    def _load_model(self):
        if not os.path.exists(self._model_path):
            return
        try:
            self._model   = joblib.load(self._model_path)
            self._trained = True
            if os.path.exists(self._metadata_path):
                lines = open(self._metadata_path).read().splitlines()
                if lines and lines[0]:
                    self._trained_at = datetime.fromisoformat(lines[0])
            print(f"[AnomalyDetector] model loaded (trained {self._trained_at})")
        except Exception as exc:
            print(f"[AnomalyDetector] load failed ({exc}), will retrain")
            self._model = None; self._trained = False

    def retrain(self):
        with self._lock:
            if len(self._buffer) >= 100:
                self._fit()

    @property
    def model_ready(self) -> bool:  return self._trained
    @property
    def buffer_size(self) -> int:   return len(self._buffer)
    @property
    def trained_at(self) -> Optional[str]:
        return self._trained_at.isoformat() if self._trained_at else None
