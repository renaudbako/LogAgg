# LogAgg — Real-Time Threat Intelligence Platform

A self-hosted, cross-platform log aggregation and threat detection system with a live web dashboard.

## Features

| Capability | Detail |
|---|---|
| **Log Collection** | Linux journald + syslog, macOS Unified Logging, Windows Event Log |
| **Real-time Tailing** | inotify/kqueue via watchdog; polling fallback |
| **Port Scan Detection** | Sliding-window per-IP unique-port counter; configurable threshold |
| **Network Monitor** | psutil live connection snapshots; suspicious port detection; beaconing analysis |
| **File Integrity (FIM)** | SHA-256 baseline of 25+ critical paths; inotify + periodic rescan |
| **Rule-based Detection** | 15+ regex rules covering SSH brute-force, reverse shells, log tampering, etc. |
| **Statistical Anomaly** | Per-source z-score rate analysis, always active |
| **ML Anomaly** | Isolation Forest (scikit-learn); auto-trains after N entries |
| **MITRE ATT&CK** | 50+ technique mappings; heatmap view; per-entry tactic/technique tags |
| **Alerts** | Deduplication, rate-limiting, rich context cards, acknowledge workflow |
| **Dashboard** | 5-tab SPA; virtual-scrolled log stream; batched WS (no flooding) |
| **SQLite Storage** | Queryable history; MITRE + network + FIM columns; auto-prune |

## Quick Start

```bash
pip install -r requirements.txt
python main.py
# → http://localhost:5000
```

**Options:**
```
--host  0.0.0.0    Bind address
--port  5000       HTTP port
--db    logagg.db  SQLite file
--debug            Verbose output
```

## Dashboard Tabs

| Tab | Contents |
|---|---|
| **Logs** | Virtual-scrolled live stream; inline expandable row detail; MITRE dot per row |
| **Alerts** | Rich alert cards: severity, rule, source, MITRE chip, log excerpt, ack button |
| **Network** | Active connections table; top scanners; event log with IP/port/process/MITRE |
| **File Integrity** | Event summary stats; baseline browser; events with before/after hash |
| **MITRE ATT&CK** | Kill-chain heatmap; technique cards with hit counts; click to filter logs |

## Architecture

```
log_aggregator/
├── main.py                      CLI entry point
├── config.py                    All settings (sources, FIM paths, ML, rules)
│
├── collectors/
│   ├── base.py                  LogEntry dataclass (MITRE + network + FIM fields)
│   ├── linux.py                 journald JSON + syslog files
│   ├── macos.py                 Unified Logging + /var/log
│   ├── windows.py               Win32 Event Log / wevtutil
│   ├── network_monitor.py       psutil connection snapshots + beaconing
│   └── fim.py                   SHA-256 baseline + watchdog + rescan
│
├── streaming/
│   └── tailer.py                watchdog file watcher + polling fallback
│
├── detection/
│   ├── pattern_matcher.py       Regex rule engine → level upgrade + matched_rules
│   ├── anomaly_detector.py      Z-score rate + Isolation Forest
│   ├── mitre_mapper.py          50+ ATT&CK technique mappings (rules, FIM, network, patterns)
│   └── port_scan_detector.py    Sliding-window unique-port counter per source IP
│
├── alerts/
│   └── alert_manager.py         Dedup (2-min window), rate-limit, persist, WS push
│
├── storage/
│   └── database.py              SQLAlchemy/SQLite; MITRE heatmap; FIM/network queries
│
└── web/
    ├── app.py                   Flask + SocketIO; _EventBatcher (batch WS emit)
    └── templates/index.html     1500-line SPA dashboard
```

## REST API

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/logs` | Query entries (level, source, search, category, mitre_tactic, anomaly_only) |
| GET | `/api/alerts` | Unacknowledged alerts with MITRE context |
| GET | `/api/alerts/history` | Full alert history (500 max) |
| POST | `/api/alerts/:id/acknowledge` | Acknowledge single alert |
| POST | `/api/alerts/acknowledge_all` | Acknowledge all pending alerts |
| GET | `/api/stats` | Counts, ML status, category breakdown, tactic counts |
| GET | `/api/timeline` | Per-minute level counts for chart |
| GET | `/api/mitre/heatmap` | Technique hit counts for ATT&CK heatmap |
| GET | `/api/mitre/tactics` | Tactic-level counts |
| GET | `/api/network/events` | Stored network events |
| GET | `/api/network/connections` | Live psutil snapshot |
| GET | `/api/network/scanners` | Top source IPs by scan event count |
| GET | `/api/fim/events` | File integrity events |
| GET | `/api/fim/baseline` | Current SHA-256 baseline |
| POST | `/api/retrain` | Trigger Isolation Forest retrain |

## WebSocket Events (`/logs` namespace)

| Event | Direction | Payload |
|---|---|---|
| `log_batch` | server → client | `LogEntry[]` (batched every 250ms or 40 entries) |
| `net_batch` | server → client | `LogEntry[]` (network category) |
| `fim_batch` | server → client | `LogEntry[]` (fim category) |
| `alert` | server → client | Rich alert dict with MITRE context |
| `alert_acked` | server → client | `{id}` |
| `alerts_cleared` | server → client | `{}` |
| `stats_update` | server → client | Lightweight stats push |
| `ping_stats` | client → server | Request stats push |

## Performance Notes

- **WS batching**: events buffered 250ms server-side → 10–40× fewer WS messages at high ingest
- **Virtual DOM**: log stream capped at 600 DOM nodes; 5000-entry in-memory ring buffer
- **Deduplication**: same rule+source deduped within 2-minute window
- **Debounced renders**: level bars and filter counts re-render max every 2s
- **Ingest rate**: ~2600 entries/sec on single core (full pipeline: match + detect + MITRE + DB)

## Configuration

Edit `config.py` to tune:

```python
# FIM paths (watched for SHA-256 changes)
fim_paths = ["/etc/passwd", "/etc/sudoers", ...]
fim_rescan_interval = 60   # seconds

# Network monitor
network_interval   = 15    # snapshot every N seconds
port_scan_threshold = 15   # unique ports before alert
port_scan_window    = 60   # sliding window (seconds)

# ML
ml_train_size    = 800
ml_contamination = 0.05
anomaly_threshold = -0.10

# Alert dedup
# AlertManager._DEDUP_WINDOW_SECONDS = 120
```

## Requirements

- Python 3.9+
- Linux/macOS/Windows
- Optional: `pywin32` for Windows native Event Log
- Optional: scikit-learn for ML anomaly detection (gracefully disabled if absent)
