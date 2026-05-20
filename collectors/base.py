"""
Base collector: shared LogEntry model and abstract interface.
"""
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class LogEntry:
    timestamp: datetime
    source: str
    level: str          # DEBUG | INFO | WARNING | ERROR | CRITICAL
    message: str
    platform: str       # linux | windows | darwin
    raw: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    is_anomaly: bool = False
    anomaly_score: float = 0.0
    matched_rules: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # ── MITRE ATT&CK ───────────────────────────────────────────
    mitre_tactic: str = ""           # e.g. "Discovery"
    mitre_tactic_id: str = ""        # e.g. "TA0007"
    mitre_technique: str = ""        # e.g. "Network Service Discovery"
    mitre_technique_id: str = ""     # e.g. "T1046"
    mitre_subtechnique_id: str = ""  # e.g. "T1046.001" (optional)

    # ── Network / FIM metadata ─────────────────────────────────
    category: str = "log"            # log | network | fim | portscan
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""
    filepath: str = ""               # FIM: affected file
    file_hash: str = ""              # FIM: new SHA-256

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "level": self.level,
            "message": self.message,
            "platform": self.platform,
            "raw": self.raw,
            "is_anomaly": self.is_anomaly,
            "anomaly_score": round(self.anomaly_score, 4),
            "matched_rules": self.matched_rules,
            "tags": self.tags,
            # MITRE
            "mitre_tactic": self.mitre_tactic,
            "mitre_tactic_id": self.mitre_tactic_id,
            "mitre_technique": self.mitre_technique,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_subtechnique_id": self.mitre_subtechnique_id,
            # Network / FIM
            "category": self.category,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "filepath": self.filepath,
            "file_hash": self.file_hash,
        }


class BaseCollector(ABC):
    def __init__(self, config):
        self.config = config
        self.platform = "unknown"

    @abstractmethod
    def collect(self) -> List[LogEntry]:
        """Snapshot-collect logs from this platform."""

    @abstractmethod
    def get_log_files(self) -> List[str]:
        """Return list of file paths suitable for real-time tailing."""

    # ── helpers ────────────────────────────────────────────────

    @staticmethod
    def parse_level(message: str) -> str:
        m = message.lower()
        if any(w in m for w in ("crit", "critical", "fatal", "emerg", "alert", "panic")):
            return "CRITICAL"
        if any(w in m for w in ("err", "error")):
            return "ERROR"
        if any(w in m for w in ("warn", "warning")):
            return "WARNING"
        if "debug" in m:
            return "DEBUG"
        return "INFO"
