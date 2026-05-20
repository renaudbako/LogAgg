"""
Flask + Flask-SocketIO web application.
Wires: LogTailer · NetworkMonitor · FIM · ProcessMonitor · DNSMonitor
       PortScanDetector · PatternMatcher · AnomalyDetector · MitreMapper
       CorrelationEngine · AlertManager · WebhookDispatcher · AuthMiddleware
"""
import threading
from datetime import datetime
from typing import Optional

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit

from alerts.alert_manager import AlertManager
from alerts.webhook_dispatcher import WebhookDispatcher
from detection.anomaly_detector import AnomalyDetector
from detection.pattern_matcher import PatternMatcher
from detection.mitre_mapper import MitreMapper
from detection.port_scan_detector import PortScanDetector
from detection.correlation_engine import CorrelationEngine, CHAINS
from storage.database import Database
from collectors.base import LogEntry
from streaming.tailer import LogTailer
from collectors.network_monitor import NetworkMonitor
from collectors.fim import FileIntegrityMonitor
from collectors.process_monitor import ProcessMonitor
from collectors.dns_monitor import DNSMonitor
from middleware.auth import make_auth

# Technique descriptions for alert enrichment
_TECH_DESC = {
    "T1110":"Adversary attempting to gain access by guessing passwords.",
    "T1046":"Adversary scanning to discover services on remote hosts.",
    "T1059":"Adversary abusing command-line interfaces to execute commands.",
    "T1053":"Adversary abusing task scheduling for persistent execution.",
    "T1070":"Adversary deleting or altering artifacts to remove evidence.",
    "T1562":"Adversary disabling security tools or logging.",
    "T1548":"Adversary circumventing elevation controls for higher permissions.",
    "T1078":"Adversary using compromised credentials for authentication.",
    "T1098":"Adversary manipulating accounts to maintain access.",
    "T1071":"Adversary using standard protocols to blend C2 traffic.",
    "T1572":"Adversary tunneling data inside application-layer protocols.",
    "T1003":"Adversary attempting to dump credentials from the OS.",
    "T1222":"Adversary modifying file permissions on sensitive files.",
    "T1021":"Adversary using valid accounts to log into remote services.",
    "T1091":"Adversary spreading using removable media.",
    "T1543":"Adversary installing malicious services for persistence.",
    "T1105":"Adversary transferring tools from external system.",
    "T1499":"Adversary performing DoS to degrade or block service.",
}


class _EventBatcher:
    """Buffer events and emit in batches (250 ms or 40 entries)."""
    def __init__(self, socketio, interval=0.25, max_size=40):
        self._sio   = socketio
        self._iv    = interval
        self._max   = max_size
        self._lock  = threading.Lock()
        self._log:  list = []
        self._net:  list = []
        self._fim:  list = []
        self._timer = None

    def add(self, d: dict, ch: str = "log"):
        with self._lock:
            if   ch == "network": self._net.append(d)
            elif ch == "fim":     self._fim.append(d)
            else:                 self._log.append(d)
            total = len(self._log) + len(self._net) + len(self._fim)
            if total >= self._max:
                self._flush_locked()
            elif self._timer is None:
                self._timer = threading.Timer(self._iv, self._flush)
                self._timer.daemon = True
                self._timer.start()

    def _flush(self):
        with self._lock: self._flush_locked()

    def _flush_locked(self):
        if self._timer: self._timer.cancel(); self._timer = None
        if self._log: self._sio.emit("log_batch", self._log[:], namespace="/logs"); self._log.clear()
        if self._net: self._sio.emit("net_batch", self._net[:], namespace="/logs"); self._net.clear()
        if self._fim: self._sio.emit("fim_batch", self._fim[:], namespace="/logs"); self._fim.clear()


def create_app(config=None):
    if config is None:
        from config import default_config
        config = default_config

    app = Flask(__name__, template_folder="templates", static_folder="static")
    CORS(app)
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading",
                        ping_timeout=60, ping_interval=25,
                        max_http_buffer_size=5*1024*1024)

    # ── Auth ──────────────────────────────────────────────────
    auth = make_auth(config)
    auth.init_app(app)

    # ── Core components ───────────────────────────────────────
    db      = Database(config.db_path)
    matcher = PatternMatcher(config)
    detect  = AnomalyDetector(config)
    mitre   = MitreMapper()
    batcher = _EventBatcher(socketio)
    webhook = WebhookDispatcher(config)

    def _on_alert(alert_dict: dict):
        socketio.emit("alert", alert_dict, namespace="/logs")
        webhook.dispatch(alert_dict)

    alert_mgr = AlertManager(db, on_alert=_on_alert)

    # ── Correlation engine ────────────────────────────────────
    def _on_correlated(entry: LogEntry, chain, summary: str):
        db.insert_entry(entry)
        alert_mgr.process(entry)
        batcher.add(entry.to_dict(), "log")
        socketio.emit("correlation", {
            "chain":    chain.name,
            "severity": chain.severity,
            "summary":  summary,
            "description": chain.description,
            "tactics":  list(chain.tactics),
            "timestamp": entry.timestamp.isoformat(),
        }, namespace="/logs")

    correlation = CorrelationEngine(on_correlated=_on_correlated)

    # ── Port scan ─────────────────────────────────────────────
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

    # ── Main pipeline ─────────────────────────────────────────
    def _pipeline(entry: LogEntry):
        matcher.annotate(entry)
        detect.score(entry)
        mitre.annotate(entry)
        correlation.observe(entry)

        if entry.category == "log":
            scan_alert = pscan.process_log_entry(entry)
            if scan_alert:
                mitre.annotate(scan_alert)
                db.insert_entry(scan_alert)
                alert_mgr.process(scan_alert)
                batcher.add(scan_alert.to_dict(), "network")

        db.insert_entry(entry)
        alert_mgr.process(entry)

        ch = "network" if entry.category in ("network","portscan") else \
             "fim"     if entry.category == "fim" else "log"
        batcher.add(entry.to_dict(), ch)

    # ── Optional collectors ───────────────────────────────────
    net_monitor = None
    if getattr(config, "network_monitor_enabled", True):
        def _on_net(entry: LogEntry):
            if entry.src_ip and entry.dst_port:
                pscan.process_connection(entry.src_ip, entry.dst_port, entry.timestamp)
            _pipeline(entry)
        net_monitor = NetworkMonitor(config, on_entry=_on_net)

    fim = None
    if getattr(config, "fim_enabled", True):
        fim = FileIntegrityMonitor(config, on_entry=_pipeline, db=db)

    proc_monitor = None
    if getattr(config, "process_monitor_enabled", True):
        proc_monitor = ProcessMonitor(config, on_entry=_pipeline)

    dns_monitor = None
    if getattr(config, "dns_monitor_enabled", True):
        def _on_dns_entry(entry: LogEntry):
            _pipeline(entry)
        dns_monitor = DNSMonitor(config, on_entry=_on_dns_entry)

    tailer = LogTailer(config, on_new_entry=_pipeline)

    # Also feed log entries into DNS monitor for passive detection
    _orig_pipeline = _pipeline
    def _pipeline_with_dns(entry: LogEntry):
        if dns_monitor and entry.category == "log":
            dns_monitor.process_log_entry(entry)
        _orig_pipeline(entry)
    tailer_pipeline = _pipeline_with_dns

    # ── REST ──────────────────────────────────────────────────

    @app.route("/api/health")
    def api_health():
        return jsonify({"status": "ok", "ts": datetime.now().isoformat()})

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
            since=_parse_dt(request.args.get("since")),
            until=_parse_dt(request.args.get("until")),
        )
        return jsonify(entries)

    @app.route("/api/alerts")
    def api_alerts():
        return jsonify(db.get_alerts(
            limit=int(request.args.get("limit", 100)),
            unacknowledged_only=request.args.get("unacknowledged","").lower()=="true"))

    @app.route("/api/alerts/history")
    def api_alerts_history():
        alerts = db.get_alerts(limit=500, unacknowledged_only=False)
        for a in alerts:
            tid = (a.get("mitre_technique_id") or "").split(".")[0]
            a["tech_description"] = _TECH_DESC.get(tid, "")
        return jsonify(alerts)

    @app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
    def api_ack(alert_id):
        db.acknowledge_alert(alert_id)
        socketio.emit("alert_acked", {"id": alert_id}, namespace="/logs")
        return jsonify({"ok": True})

    @app.route("/api/alerts/acknowledge_all", methods=["POST"])
    def api_ack_all():
        from sqlalchemy import text as _t
        with db._engine.begin() as conn:
            conn.execute(_t("UPDATE alerts SET acknowledged=1 WHERE acknowledged=0"))
        socketio.emit("alerts_cleared", {}, namespace="/logs")
        return jsonify({"ok": True})

    @app.route("/api/stats")
    def api_stats():
        s = db.get_stats()
        s.update({
            "ml_ready":        detect.model_ready,
            "ml_buffer":       detect.buffer_size,
            "ml_train_size":   config.ml_train_size,
            "ml_trained_at":   detect.trained_at,
            "alerts_fired":    alert_mgr.total_fired,
            "categories":      db.get_category_counts(),
            "fim_baseline":    fim.baseline_count if fim else 0,
            "top_scanners":    pscan.get_top_scanners(5),
            "tactic_counts":   db.get_tactic_counts(since_hours=24),
            "correlation":     correlation.get_stats(),
            "webhook":         webhook.stats,
        })
        return jsonify(s)

    @app.route("/api/timeline")
    def api_timeline():
        return jsonify(db.get_timeline(minutes=int(request.args.get("minutes",60))))

    @app.route("/api/mitre/heatmap")
    def api_mitre_heatmap():
        return jsonify(db.get_mitre_heatmap(since_hours=int(request.args.get("hours",24))))

    @app.route("/api/mitre/tactics")
    def api_mitre_tactics():
        return jsonify(db.get_tactic_counts(since_hours=int(request.args.get("hours",24))))

    @app.route("/api/network/events")
    def api_network_events():
        return jsonify(db.get_network_events(limit=int(request.args.get("limit",200))))

    @app.route("/api/network/connections")
    def api_network_connections():
        return jsonify(net_monitor.get_active_connections() if net_monitor else [])

    @app.route("/api/network/scanners")
    def api_network_scanners():
        live    = {s["ip"]: s for s in pscan.get_top_scanners(20)}
        db_rows = {r["ip"]: r["count"] for r in db.get_top_scanners(20)}
        merged  = {}
        for ip, s in live.items():
            merged[ip] = {"ip": ip, "unique_ports": s["unique_ports"],
                          "count": max(s["count"], db_rows.get(ip,0))}
        for ip, cnt in db_rows.items():
            if ip not in merged:
                merged[ip] = {"ip": ip, "unique_ports": 0, "count": cnt}
        return jsonify(sorted(merged.values(), key=lambda x:-(x["unique_ports"] or x["count"]))[:20])

    @app.route("/api/fim/events")
    def api_fim_events():
        return jsonify(db.get_fim_events(limit=int(request.args.get("limit",100))))

    @app.route("/api/fim/baseline")
    def api_fim_baseline():
        return jsonify(fim.get_baseline_snapshot() if fim else [])

    @app.route("/api/correlation/chains")
    def api_chains():
        return jsonify([{
            "name": c.name, "tactics": list(c.tactics),
            "window_minutes": c.window_minutes, "severity": c.severity,
            "description": c.description,
        } for c in CHAINS])

    @app.route("/api/correlation/stats")
    def api_corr_stats():
        return jsonify(correlation.get_stats())

    @app.route("/api/retrain", methods=["POST"])
    def api_retrain():
        detect.retrain()
        return jsonify({"ok": True, "model_ready": detect.model_ready,
                        "trained_at": detect.trained_at})

    @app.route("/api/prune", methods=["POST"])
    def api_prune():
        db.prune_old(retention=getattr(config, "retention_days", None))
        return jsonify({"ok": True})

    # ── SocketIO ──────────────────────────────────────────────
    @socketio.on("connect", namespace="/logs")
    def on_connect():
        emit("connected", {"status": "ok",
                           "server_time": datetime.now().isoformat(),
                           "auth_enabled": config.auth_enabled})

    @socketio.on("ping_stats", namespace="/logs")
    def on_ping_stats():
        s = db.get_stats()
        emit("stats_update", {"total": s["total_entries"],
                               "anomalies": s["anomaly_count"],
                               "unacked": s["unacked_alerts"],
                               "rate": s["recent_rate"]})

    # ── Startup ───────────────────────────────────────────────
    def _start_all():
        pscan.start()
        tailer.start()
        if net_monitor:   net_monitor.start()
        if fim:           fim.start()
        if proc_monitor:  proc_monitor.start()
        if dns_monitor:   dns_monitor.start()

    threading.Thread(target=_start_all, daemon=True, name="logagg-start").start()
    app._db = db; app._tailer = tailer
    return app, socketio


def _parse_dt(s):
    if not s: return None
    try: return datetime.fromisoformat(s)
    except ValueError: return None
