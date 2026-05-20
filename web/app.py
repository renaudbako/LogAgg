"""
Flask + Flask-SocketIO web application.
Server-side event batching prevents WS flooding at high ingest rates.
Alerts carry full context (MITRE, excerpt, description) for rich UI.
"""
import threading
import time
from datetime import datetime
from typing import List, Optional

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit

from alerts.alert_manager import AlertManager
from detection.anomaly_detector import AnomalyDetector
from detection.pattern_matcher import PatternMatcher
from detection.mitre_mapper import MitreMapper
from detection.port_scan_detector import PortScanDetector
from storage.database import Database
from collectors.base import LogEntry
from streaming.tailer import LogTailer
from collectors.network_monitor import NetworkMonitor
from collectors.fim import FileIntegrityMonitor

# ── MITRE technique descriptions (subset) ─────────────────────
_TECH_DESC = {
    "T1110": "Adversary attempting to gain access by guessing passwords.",
    "T1046": "Adversary scanning to discover services on remote hosts.",
    "T1059": "Adversary abusing command-line interfaces to execute commands.",
    "T1053": "Adversary abusing task scheduling to execute programs at system startup.",
    "T1070": "Adversary deleting or altering artifacts to remove evidence.",
    "T1562": "Adversary disabling security tools or logging to evade detection.",
    "T1548": "Adversary circumventing mechanisms to gain higher-level permissions.",
    "T1078": "Adversary using compromised credentials for authentication.",
    "T1098": "Adversary manipulating accounts to maintain access.",
    "T1071": "Adversary using standard protocols to blend C2 traffic.",
    "T1572": "Adversary tunneling data inside application-layer protocols.",
    "T1003": "Adversary attempting to dump credentials from the operating system.",
    "T1222": "Adversary modifying file permissions on sensitive files.",
    "T1021": "Adversary using valid accounts to log into remote services.",
    "T1091": "Adversary spreading using removable media.",
    "T1543": "Adversary installing malicious services for persistence.",
    "T1105": "Adversary transferring tools or files from external system.",
    "T1041": "Adversary exfiltrating data over the C2 channel.",
    "T1048": "Adversary exfiltrating data using protocols other than C2.",
    "T1499": "Adversary performing DoS to degrade or block service.",
    "T1574": "Adversary hijacking execution flow to run malicious code.",
    "T1036": "Adversary masquerading malicious items as benign.",
    "T1566": "Adversary sending phishing messages to gain access.",
    "T1595": "Adversary actively scanning the infrastructure.",
    "T1018": "Adversary discovering remote systems on the network.",
}


class _EventBatcher:
    """
    Collects LogEntry dicts and emits them as batches via SocketIO.
    Batches flush after `interval` seconds OR when `max_size` is reached,
    whichever comes first. Prevents per-event WS overhead at high ingest.
    """
    def __init__(self, socketio, interval: float = 0.25, max_size: int = 40):
        self._sio      = socketio
        self._interval = interval
        self._max_size = max_size
        self._lock     = threading.Lock()
        self._buf: List[dict]            = []
        self._net_buf: List[dict]        = []
        self._fim_buf: List[dict]        = []
        self._timer: Optional[threading.Timer] = None

    def add(self, entry_dict: dict, channel: str = "log"):
        with self._lock:
            if channel == "network":
                self._net_buf.append(entry_dict)
            elif channel == "fim":
                self._fim_buf.append(entry_dict)
            else:
                self._buf.append(entry_dict)
            if (len(self._buf) + len(self._net_buf) + len(self._fim_buf)) >= self._max_size:
                self._flush_locked()
            elif self._timer is None:
                self._timer = threading.Timer(self._interval, self._flush)
                self._timer.daemon = True
                self._timer.start()

    def _flush(self):
        with self._lock:
            self._flush_locked()

    def _flush_locked(self):
        if self._timer:
            self._timer.cancel()
            self._timer = None
        if self._buf:
            self._sio.emit("log_batch", self._buf[:], namespace="/logs")
            self._buf.clear()
        if self._net_buf:
            self._sio.emit("net_batch", self._net_buf[:], namespace="/logs")
            self._net_buf.clear()
        if self._fim_buf:
            self._sio.emit("fim_batch", self._fim_buf[:], namespace="/logs")
            self._fim_buf.clear()


def create_app(config=None):
    if config is None:
        from config import default_config
        config = default_config

    app = Flask(__name__, template_folder="templates", static_folder="static")
    CORS(app)
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading",
                        ping_timeout=60, ping_interval=25,
                        max_http_buffer_size=5 * 1024 * 1024)

    db       = Database(config.db_path)
    matcher  = PatternMatcher(config)
    detector = AnomalyDetector(config)
    mitre    = MitreMapper()
    batcher  = _EventBatcher(socketio)

    def _enrich_alert(entry: LogEntry, rule_name: str) -> dict:
        """Build a rich alert payload for the frontend."""
        tech_id = entry.mitre_technique_id
        return {
            "rule":            rule_name,
            "level":           entry.level.lower(),
            "message":         entry.message[:300],
            "source":          entry.source,
            "timestamp":       entry.timestamp.isoformat(),
            "log_id":          entry.id,
            "mitre_tactic":    entry.mitre_tactic,
            "mitre_tactic_id": entry.mitre_tactic_id,
            "mitre_technique": entry.mitre_technique,
            "mitre_technique_id": tech_id,
            "mitre_sub_id":    entry.mitre_subtechnique_id,
            "tech_description": _TECH_DESC.get(tech_id.split(".")[0], ""),
            "category":        entry.category,
            "src_ip":          entry.src_ip,
            "dst_ip":          entry.dst_ip,
            "dst_port":        entry.dst_port,
            "filepath":        entry.filepath,
            "is_anomaly":      entry.is_anomaly,
            "anomaly_score":   entry.anomaly_score,
            "matched_rules":   entry.matched_rules,
        }

    def _on_alert(alert_dict: dict):
        socketio.emit("alert", alert_dict, namespace="/logs")

    alert_mgr = AlertManager(db, on_alert=_on_alert)
    # Patch alert_mgr to pass enriched data
    _orig_emit = alert_mgr._emit_and_store
    def _enriched_emit(rule_name, level, entry_or_str, *args, **kwargs):
        # Call original
        _orig_emit(rule_name, level, *args, **kwargs)
    # Use the hook via on_alert callback which receives the dict from insert_alert
    # Override: patch AlertManager to emit rich payload when we have entry context
    alert_mgr._enrich_fn = _enrich_alert

    def _on_scan(entry: LogEntry):
        mitre.annotate(entry)
        db.insert_entry(entry)
        alert_mgr.process(entry)
        batcher.add(entry.to_dict(), "network")

    pscan = PortScanDetector(
        config, on_scan=_on_scan,
        unique_port_threshold=getattr(config, "port_scan_threshold", 12),
        window_seconds=getattr(config, "port_scan_window", 60),
    )

    def _pipeline(entry: LogEntry):
        matcher.annotate(entry)
        detector.score(entry)
        mitre.annotate(entry)

        # Log-based port scan extraction
        if entry.category == "log":
            scan_alert = pscan.process_log_entry(entry)
            if scan_alert:
                mitre.annotate(scan_alert)
                db.insert_entry(scan_alert)
                alert_mgr.process(scan_alert)
                batcher.add(scan_alert.to_dict(), "network")

        db.insert_entry(entry)
        alert_mgr.process(entry)

        if entry.category in ("network", "portscan"):
            batcher.add(entry.to_dict(), "network")
        elif entry.category == "fim":
            batcher.add(entry.to_dict(), "fim")
        else:
            batcher.add(entry.to_dict(), "log")

    net_monitor = None
    if getattr(config, "network_monitor_enabled", True):
        def _on_net_entry(entry: LogEntry):
            if entry.src_ip and entry.dst_port:
                pscan.process_connection(entry.src_ip, entry.dst_port, entry.timestamp)
            _pipeline(entry)
        net_monitor = NetworkMonitor(config, on_entry=_on_net_entry)

    fim = None
    if getattr(config, "fim_enabled", True):
        fim = FileIntegrityMonitor(config, on_entry=_pipeline)

    tailer = LogTailer(config, on_new_entry=_pipeline)

    # ── REST ──────────────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/logs")
    def api_logs():
        entries = db.get_entries(
            limit=min(int(request.args.get("limit", 200)), 1000),
            offset=int(request.args.get("offset", 0)),
            level=request.args.get("level"),
            source=request.args.get("source"),
            search=request.args.get("search"),
            anomaly_only=request.args.get("anomaly_only","").lower()=="true",
            category=request.args.get("category"),
            mitre_tactic=request.args.get("mitre_tactic"),
            mitre_technique_id=request.args.get("mitre_technique_id"),
        )
        return jsonify(entries)

    @app.route("/api/alerts")
    def api_alerts():
        unacked = request.args.get("unacknowledged","").lower()=="true"
        limit   = int(request.args.get("limit", 100))
        alerts  = db.get_alerts(limit=limit, unacknowledged_only=unacked)
        # Enrich alerts with MITRE descriptions
        for a in alerts:
            tid = (a.get("mitre_technique_id") or "").split(".")[0]
            a["tech_description"] = _TECH_DESC.get(tid, "")
        return jsonify(alerts)

    @app.route("/api/alerts/history")
    def api_alerts_history():
        alerts = db.get_alerts(limit=500, unacknowledged_only=False)
        for a in alerts:
            tid = (a.get("mitre_technique_id") or "").split(".")[0]
            a["tech_description"] = _TECH_DESC.get(tid, "")
        return jsonify(alerts)

    @app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
    def api_ack_alert(alert_id):
        db.acknowledge_alert(alert_id)
        socketio.emit("alert_acked", {"id": alert_id}, namespace="/logs")
        return jsonify({"ok": True})

    @app.route("/api/alerts/acknowledge_all", methods=["POST"])
    def api_ack_all():
        with db._engine.begin() as conn:
            from sqlalchemy import text
            conn.execute(text("UPDATE alerts SET acknowledged=1 WHERE acknowledged=0"))
        socketio.emit("alerts_cleared", {}, namespace="/logs")
        return jsonify({"ok": True})

    @app.route("/api/stats")
    def api_stats():
        s = db.get_stats()
        s["ml_ready"]      = detector.model_ready
        s["ml_buffer"]     = detector.buffer_size
        s["ml_train_size"] = config.ml_train_size
        s["alerts_fired"]  = alert_mgr.total_fired
        s["categories"]    = db.get_category_counts()
        s["fim_baseline"]  = fim.baseline_count if fim else 0
        s["top_scanners"]  = pscan.get_top_scanners(5)
        s["tactic_counts"] = db.get_tactic_counts(since_hours=24)
        return jsonify(s)

    @app.route("/api/timeline")
    def api_timeline():
        return jsonify(db.get_timeline(minutes=int(request.args.get("minutes", 60))))

    @app.route("/api/mitre/heatmap")
    def api_mitre_heatmap():
        return jsonify(db.get_mitre_heatmap(since_hours=int(request.args.get("hours", 24))))

    @app.route("/api/mitre/tactics")
    def api_mitre_tactics():
        return jsonify(db.get_tactic_counts(since_hours=int(request.args.get("hours", 24))))

    @app.route("/api/network/events")
    def api_network_events():
        return jsonify(db.get_network_events(limit=int(request.args.get("limit", 200))))

    @app.route("/api/network/connections")
    def api_network_connections():
        return jsonify(net_monitor.get_active_connections() if net_monitor else [])

    @app.route("/api/network/scanners")
    def api_network_scanners():
        # Merge live in-memory state with persisted DB counts
        live    = {s["ip"]: s for s in pscan.get_top_scanners(20)}
        db_rows = {r["ip"]: r["count"] for r in db.get_top_scanners(20)}
        merged  = {}
        for ip, s in live.items():
            merged[ip] = {"ip": ip,
                          "unique_ports": s["unique_ports"],
                          "count": max(s["count"], db_rows.get(ip, 0))}
        for ip, cnt in db_rows.items():
            if ip not in merged:
                merged[ip] = {"ip": ip, "unique_ports": 0, "count": cnt}
        result = sorted(merged.values(), key=lambda x: -(x["unique_ports"] or x["count"]))
        return jsonify(result[:20])

    @app.route("/api/fim/events")
    def api_fim_events():
        return jsonify(db.get_fim_events(limit=int(request.args.get("limit", 100))))

    @app.route("/api/fim/baseline")
    def api_fim_baseline():
        return jsonify(fim.get_baseline_snapshot() if fim else [])

    @app.route("/api/retrain", methods=["POST"])
    def api_retrain():
        detector.retrain()
        return jsonify({"ok": True, "model_ready": detector.model_ready})

    @socketio.on("connect", namespace="/logs")
    def on_connect():
        emit("connected", {"status": "ok",
                           "server_time": datetime.now().isoformat()})

    @socketio.on("ping_stats", namespace="/logs")
    def on_ping_stats():
        """Lightweight stats push on client request."""
        s = db.get_stats()
        emit("stats_update", {
            "total": s["total_entries"],
            "anomalies": s["anomaly_count"],
            "unacked": s["unacked_alerts"],
            "rate": s["recent_rate"],
        })

    def _start_all():
        pscan.start()          # /proc/net/tcp polling thread (1s interval)
        tailer.start()
        if net_monitor: net_monitor.start()
        if fim:         fim.start()

    threading.Thread(target=_start_all, daemon=True, name="logagg-start").start()
    app._tailer = tailer; app._db = db
    return app, socketio
