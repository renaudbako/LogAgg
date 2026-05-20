"""
SQLite storage layer using SQLAlchemy core (no ORM overhead).
Handles log persistence, querying, and alert storage.
"""
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Column, Float, Integer, String, Boolean, Text, DateTime,
    create_engine, inspect, text
)
from sqlalchemy.pool import StaticPool

from collectors.base import LogEntry


_DDL = """
CREATE TABLE IF NOT EXISTS log_entries (
    id                    TEXT PRIMARY KEY,
    timestamp             TEXT NOT NULL,
    source                TEXT NOT NULL,
    level                 TEXT NOT NULL,
    message               TEXT NOT NULL,
    platform              TEXT NOT NULL,
    raw                   TEXT,
    is_anomaly            INTEGER DEFAULT 0,
    anomaly_score         REAL    DEFAULT 0.0,
    matched_rules         TEXT    DEFAULT '[]',
    tags                  TEXT    DEFAULT '[]',
    mitre_tactic          TEXT    DEFAULT '',
    mitre_tactic_id       TEXT    DEFAULT '',
    mitre_technique       TEXT    DEFAULT '',
    mitre_technique_id    TEXT    DEFAULT '',
    mitre_subtechnique_id TEXT    DEFAULT '',
    category              TEXT    DEFAULT 'log',
    src_ip                TEXT    DEFAULT '',
    dst_ip                TEXT    DEFAULT '',
    dst_port              INTEGER DEFAULT 0,
    protocol              TEXT    DEFAULT '',
    filepath              TEXT    DEFAULT '',
    file_hash             TEXT    DEFAULT '',
    created_at            TEXT    DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_timestamp  ON log_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_level      ON log_entries(level);
CREATE INDEX IF NOT EXISTS idx_source     ON log_entries(source);
CREATE INDEX IF NOT EXISTS idx_anomaly    ON log_entries(is_anomaly);
CREATE INDEX IF NOT EXISTS idx_category   ON log_entries(category);
CREATE INDEX IF NOT EXISTS idx_mitre_tac  ON log_entries(mitre_tactic);
CREATE INDEX IF NOT EXISTS idx_mitre_tech ON log_entries(mitre_technique_id);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name   TEXT NOT NULL,
    level       TEXT NOT NULL,
    message     TEXT NOT NULL,
    source      TEXT NOT NULL,
    log_id      TEXT,
    timestamp   TEXT NOT NULL,
    acknowledged INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_alert_ts   ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alert_rule ON alerts(rule_name);

CREATE TABLE IF NOT EXISTS stats (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class Database:
    def __init__(self, db_path: str = "logagg.db"):
        url = f"sqlite:///{db_path}" if db_path != ":memory:" else "sqlite://"
        self._engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool if db_path == ":memory:" else None,
        )
        self._init_schema()

    # ── Schema ─────────────────────────────────────────────────

    def _init_schema(self):
        with self._engine.begin() as conn:
            for stmt in _DDL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))

    # ── Write ──────────────────────────────────────────────────

    def insert_entry(self, entry: LogEntry) -> bool:
        try:
            with self._engine.begin() as conn:
                conn.execute(text("""
                    INSERT OR IGNORE INTO log_entries
                        (id, timestamp, source, level, message, platform,
                         raw, is_anomaly, anomaly_score, matched_rules, tags,
                         mitre_tactic, mitre_tactic_id, mitre_technique,
                         mitre_technique_id, mitre_subtechnique_id,
                         category, src_ip, dst_ip, dst_port,
                         protocol, filepath, file_hash)
                    VALUES
                        (:id, :ts, :src, :lvl, :msg, :plt,
                         :raw, :anom, :score, :rules, :tags,
                         :mt, :mt_id, :mtech, :mtech_id, :msub,
                         :cat, :sip, :dip, :dport,
                         :proto, :fpath, :fhash)
                """), {
                    "id":      entry.id,
                    "ts":      entry.timestamp.isoformat(),
                    "src":     entry.source,
                    "lvl":     entry.level,
                    "msg":     entry.message,
                    "plt":     entry.platform,
                    "raw":     entry.raw,
                    "anom":    int(entry.is_anomaly),
                    "score":   entry.anomaly_score,
                    "rules":   json.dumps(entry.matched_rules),
                    "tags":    json.dumps(entry.tags),
                    "mt":      entry.mitre_tactic,
                    "mt_id":   entry.mitre_tactic_id,
                    "mtech":   entry.mitre_technique,
                    "mtech_id":entry.mitre_technique_id,
                    "msub":    entry.mitre_subtechnique_id,
                    "cat":     entry.category,
                    "sip":     entry.src_ip,
                    "dip":     entry.dst_ip,
                    "dport":   entry.dst_port,
                    "proto":   entry.protocol,
                    "fpath":   entry.filepath,
                    "fhash":   entry.file_hash,
                })
            return True
        except Exception:
            return False

    def insert_many(self, entries: List[LogEntry]) -> int:
        inserted = 0
        for e in entries:
            if self.insert_entry(e):
                inserted += 1
        return inserted

    def update_anomaly(self, entry_id: str, is_anomaly: bool, score: float):
        with self._engine.begin() as conn:
            conn.execute(text("""
                UPDATE log_entries SET is_anomaly=:a, anomaly_score=:s WHERE id=:id
            """), {"a": int(is_anomaly), "s": score, "id": entry_id})

    def insert_alert(self, rule_name: str, level: str, message: str,
                     source: str, log_id: Optional[str] = None):
        with self._engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO alerts (rule_name, level, message, source, log_id, timestamp)
                VALUES (:rn, :lvl, :msg, :src, :lid, :ts)
            """), {
                "rn": rule_name, "lvl": level, "msg": message,
                "src": source, "lid": log_id,
                "ts": datetime.now().isoformat(),
            })

    def acknowledge_alert(self, alert_id: int):
        with self._engine.begin() as conn:
            conn.execute(text(
                "UPDATE alerts SET acknowledged=1 WHERE id=:id"), {"id": alert_id})

    # ── Read ───────────────────────────────────────────────────

    def get_entries(
        self,
        limit: int = 200,
        offset: int = 0,
        level: Optional[str] = None,
        source: Optional[str] = None,
        search: Optional[str] = None,
        anomaly_only: bool = False,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        category: Optional[str] = None,
        mitre_tactic: Optional[str] = None,
        mitre_technique_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        clauses = []
        params: Dict[str, Any] = {"limit": limit, "offset": offset}

        if level:
            clauses.append("level = :level")
            params["level"] = level.upper()
        if source:
            clauses.append("source LIKE :source")
            params["source"] = f"%{source}%"
        if search:
            clauses.append("message LIKE :search")
            params["search"] = f"%{search}%"
        if anomaly_only:
            clauses.append("is_anomaly = 1")
        if since:
            clauses.append("timestamp >= :since")
            params["since"] = since.isoformat()
        if until:
            clauses.append("timestamp <= :until")
            params["until"] = until.isoformat()
        if category:
            clauses.append("category = :category")
            params["category"] = category
        if mitre_tactic:
            clauses.append("mitre_tactic = :mitre_tactic")
            params["mitre_tactic"] = mitre_tactic
        if mitre_technique_id:
            clauses.append("mitre_technique_id = :mitre_tech")
            params["mitre_tech"] = mitre_technique_id

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"""
            SELECT id, timestamp, source, level, message, platform,
                   is_anomaly, anomaly_score, matched_rules, tags,
                   mitre_tactic, mitre_tactic_id, mitre_technique,
                   mitre_technique_id, mitre_subtechnique_id,
                   category, src_ip, dst_ip, dst_port,
                   protocol, filepath, file_hash
            FROM log_entries {where}
            ORDER BY timestamp DESC
            LIMIT :limit OFFSET :offset
        """
        with self._engine.connect() as conn:
            rows = conn.execute(text(sql), params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_alerts(self, limit: int = 100, unacknowledged_only: bool = False) -> List[Dict]:
        where = "WHERE acknowledged=0" if unacknowledged_only else ""
        with self._engine.connect() as conn:
            rows = conn.execute(text(f"""
                SELECT id, rule_name, level, message, source, log_id, timestamp, acknowledged
                FROM alerts {where}
                ORDER BY timestamp DESC LIMIT :limit
            """), {"limit": limit}).fetchall()
        return [dict(r._mapping) for r in rows]

    def get_stats(self) -> Dict[str, Any]:
        with self._engine.connect() as conn:
            total = conn.execute(text("SELECT COUNT(*) FROM log_entries")).scalar()
            anomalies = conn.execute(
                text("SELECT COUNT(*) FROM log_entries WHERE is_anomaly=1")).scalar()
            unacked = conn.execute(
                text("SELECT COUNT(*) FROM alerts WHERE acknowledged=0")).scalar()
            by_level = conn.execute(text("""
                SELECT level, COUNT(*) as cnt FROM log_entries GROUP BY level
            """)).fetchall()
            recent_rate = conn.execute(text("""
                SELECT COUNT(*) FROM log_entries
                WHERE timestamp >= :since
            """), {"since": (datetime.now() - timedelta(minutes=5)).isoformat()}).scalar()
        return {
            "total_entries": total,
            "anomaly_count": anomalies,
            "unacked_alerts": unacked,
            "by_level": {r[0]: r[1] for r in by_level},
            "recent_rate": recent_rate,
        }

    def get_timeline(self, minutes: int = 60) -> List[Dict]:
        since = (datetime.now() - timedelta(minutes=minutes)).isoformat()
        with self._engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT strftime('%Y-%m-%dT%H:%M:00', timestamp) as minute,
                       level, COUNT(*) as cnt
                FROM log_entries
                WHERE timestamp >= :since
                GROUP BY minute, level
                ORDER BY minute
            """), {"since": since}).fetchall()
        return [{"minute": r[0], "level": r[1], "count": r[2]} for r in rows]

    def get_mitre_heatmap(self, since_hours: int = 24) -> List[Dict]:
        """Return tactic/technique hit counts for ATT&CK heatmap."""
        since = (datetime.now() - timedelta(hours=since_hours)).isoformat()
        with self._engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT mitre_tactic, mitre_tactic_id,
                       mitre_technique, mitre_technique_id,
                       mitre_subtechnique_id,
                       COUNT(*) as cnt
                FROM log_entries
                WHERE mitre_tactic != ''
                  AND timestamp >= :since
                GROUP BY mitre_technique_id
                ORDER BY cnt DESC
            """), {"since": since}).fetchall()
        return [dict(r._mapping) for r in rows]

    def get_tactic_counts(self, since_hours: int = 24) -> Dict[str, int]:
        since = (datetime.now() - timedelta(hours=since_hours)).isoformat()
        with self._engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT mitre_tactic, COUNT(*) as cnt
                FROM log_entries
                WHERE mitre_tactic != '' AND timestamp >= :since
                GROUP BY mitre_tactic
            """), {"since": since}).fetchall()
        return {r[0]: r[1] for r in rows}

    def get_category_counts(self, since_hours: int = 24) -> Dict[str, int]:
        since = (datetime.now() - timedelta(hours=since_hours)).isoformat()
        with self._engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT category, COUNT(*) as cnt
                FROM log_entries
                WHERE timestamp >= :since
                GROUP BY category
            """), {"since": since}).fetchall()
        return {r[0]: r[1] for r in rows}

    def get_top_scanners(self, limit: int = 10) -> List[Dict]:
        with self._engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT src_ip, COUNT(*) as cnt
                FROM log_entries
                WHERE category = 'portscan' AND src_ip != ''
                GROUP BY src_ip ORDER BY cnt DESC LIMIT :limit
            """), {"limit": limit}).fetchall()
        return [{"ip": r[0], "count": r[1]} for r in rows]

    def get_fim_events(self, limit: int = 100) -> List[Dict]:
        with self._engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT id, timestamp, message, level, filepath, file_hash,
                       mitre_tactic, mitre_technique_id
                FROM log_entries
                WHERE category = 'fim'
                ORDER BY timestamp DESC LIMIT :limit
            """), {"limit": limit}).fetchall()
        return [dict(r._mapping) for r in rows]

    def get_network_events(self, limit: int = 200) -> List[Dict]:
        with self._engine.connect() as conn:
            rows = conn.execute(text("""
                SELECT id, timestamp, message, level, src_ip, dst_ip,
                       dst_port, protocol, matched_rules, mitre_tactic,
                       mitre_technique_id
                FROM log_entries
                WHERE category IN ('network', 'portscan')
                ORDER BY timestamp DESC LIMIT :limit
            """), {"limit": limit}).fetchall()
        result = []
        for r in rows:
            d = dict(r._mapping)
            try:
                d["matched_rules"] = json.loads(d.get("matched_rules") or "[]")
            except Exception:
                d["matched_rules"] = []
            result.append(d)
        return result

    def prune_old(self, days: int = 7):
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with self._engine.begin() as conn:
            conn.execute(text(
                "DELETE FROM log_entries WHERE timestamp < :c"), {"c": cutoff})
            conn.execute(text(
                "DELETE FROM alerts WHERE timestamp < :c AND acknowledged=1"), {"c": cutoff})

    # ── Helpers ────────────────────────────────────────────────

    @staticmethod
    def _row_to_dict(row) -> Dict[str, Any]:
        d = dict(row._mapping)
        for key in ("matched_rules", "tags"):
            try:
                d[key] = json.loads(d.get(key) or "[]")
            except (json.JSONDecodeError, TypeError):
                d[key] = []
        d["is_anomaly"] = bool(d.get("is_anomaly"))
        # Ensure new fields have defaults for old rows
        for field in ("mitre_tactic","mitre_tactic_id","mitre_technique",
                      "mitre_technique_id","mitre_subtechnique_id",
                      "category","src_ip","dst_ip","protocol",
                      "filepath","file_hash"):
            d.setdefault(field, "")
        d.setdefault("dst_port", 0)
        return d
