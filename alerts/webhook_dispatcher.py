"""
Webhook dispatcher.

Sends alert notifications to Slack, Discord, or a generic HTTP endpoint.
Operates asynchronously — a background thread drains a queue so it never
blocks the main pipeline.

Configure in config.py:
    webhook_url      = "https://hooks.slack.com/..."   # or Discord / generic
    webhook_type     = "slack"   # "slack" | "discord" | "generic"
    webhook_min_level = "WARNING"  # minimum severity to send
    webhook_enabled  = True
"""
import json
import queue
import threading
from datetime import datetime
from typing import Any, Dict, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

_LEVEL_EMOJI = {
    "DEBUG":    "🔵",
    "INFO":     "🟢",
    "WARNING":  "🟡",
    "ERROR":    "🟠",
    "CRITICAL": "🔴",
}
_LEVEL_COLOUR = {           # hex for Slack/Discord attachments
    "DEBUG":    "#607080",
    "INFO":     "#00d4ff",
    "WARNING":  "#ffd740",
    "ERROR":    "#ff7043",
    "CRITICAL": "#ff1744",
}
_LEVEL_ORDER = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}


class WebhookDispatcher:
    """
    Queue-backed webhook sender.
    Call `dispatch(alert_dict)` — returns immediately; delivery is async.
    """

    def __init__(self, config):
        self._url       = getattr(config, "webhook_url",       "")
        self._type      = getattr(config, "webhook_type",      "generic").lower()
        self._enabled   = getattr(config, "webhook_enabled",   False) and bool(self._url)
        self._min_level = getattr(config, "webhook_min_level", "WARNING").upper()
        self._timeout   = getattr(config, "webhook_timeout",   8)
        self._queue: queue.Queue = queue.Queue(maxsize=500)
        self._sent      = 0
        self._failed    = 0

        if self._enabled:
            thread = threading.Thread(
                target=self._worker, daemon=True, name="webhook")
            thread.start()

    # ── Public API ────────────────────────────────────────────

    def dispatch(self, alert: Dict[str, Any]):
        """Non-blocking. Drops silently if queue is full."""
        if not self._enabled:
            return
        level = (alert.get("level") or "INFO").upper()
        if _LEVEL_ORDER.get(level, 0) < _LEVEL_ORDER.get(self._min_level, 2):
            return
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            pass

    @property
    def stats(self) -> Dict:
        return {
            "enabled": self._enabled,
            "sent":    self._sent,
            "failed":  self._failed,
            "queued":  self._queue.qsize(),
            "url":     self._url[:40] + "…" if len(self._url) > 40 else self._url,
        }

    # ── Worker ────────────────────────────────────────────────

    def _worker(self):
        while True:
            alert = self._queue.get()
            try:
                self._send(alert)
                self._sent += 1
            except Exception:
                self._failed += 1
            finally:
                self._queue.task_done()

    def _send(self, alert: Dict):
        if self._type == "slack":
            payload = self._slack_payload(alert)
        elif self._type == "discord":
            payload = self._discord_payload(alert)
        else:
            payload = self._generic_payload(alert)

        data    = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "LogAgg/1.0"}
        req     = Request(self._url, data=data, headers=headers, method="POST")

        with urlopen(req, timeout=self._timeout) as resp:
            if resp.status not in (200, 204):
                raise RuntimeError(f"HTTP {resp.status}")

    # ── Payload builders ──────────────────────────────────────

    def _slack_payload(self, a: Dict) -> Dict:
        level  = (a.get("level") or "INFO").upper()
        emoji  = _LEVEL_EMOJI.get(level, "⚪")
        colour = _LEVEL_COLOUR.get(level, "#607080")
        ts_str = _fmt_ts(a.get("timestamp"))
        mitre  = ""
        if a.get("mitre_tactic"):
            mitre = (f"\n*MITRE:* {a.get('mitre_tactic_id','')} "
                     f"{a.get('mitre_tactic','')} / "
                     f"{a.get('mitre_technique_id','')} "
                     f"{a.get('mitre_technique','').split(':')[0]}")

        return {
            "text": f"{emoji} *{level}* — {a.get('rule') or a.get('rule_name','')}",
            "attachments": [{
                "color":  colour,
                "fields": [
                    {"title": "Rule",    "value": a.get("rule") or a.get("rule_name",""), "short": True},
                    {"title": "Source",  "value": a.get("source",""),  "short": True},
                    {"title": "Time",    "value": ts_str,              "short": True},
                    {"title": "Message", "value": (a.get("message","") or "")[:300]},
                ],
                "footer": f"LogAgg{mitre}",
                "ts":     int(datetime.now().timestamp()),
            }],
        }

    def _discord_payload(self, a: Dict) -> Dict:
        level  = (a.get("level") or "INFO").upper()
        colour = int(_LEVEL_COLOUR.get(level, "#607080").lstrip("#"), 16)
        ts_str = _fmt_ts(a.get("timestamp"))
        fields = [
            {"name": "Source",  "value": a.get("source","") or "—",   "inline": True},
            {"name": "Level",   "value": level,                        "inline": True},
            {"name": "Time",    "value": ts_str,                       "inline": True},
            {"name": "Message", "value": (a.get("message","") or "")[:1024]},
        ]
        if a.get("mitre_tactic"):
            fields.append({
                "name": "MITRE",
                "value": (f"{a.get('mitre_tactic_id','')} {a.get('mitre_tactic','')} / "
                          f"{a.get('mitre_technique_id','')}"),
                "inline": False,
            })
        return {
            "embeds": [{
                "title":       a.get("rule") or a.get("rule_name","Unknown"),
                "description": (a.get("message","") or "")[:200],
                "color":       colour,
                "fields":      fields,
                "footer":      {"text": "LogAgg Threat Intelligence"},
            }]
        }

    @staticmethod
    def _generic_payload(a: Dict) -> Dict:
        return {
            "event":      "alert",
            "rule":       a.get("rule") or a.get("rule_name",""),
            "level":      (a.get("level") or "INFO").upper(),
            "source":     a.get("source",""),
            "message":    (a.get("message","") or "")[:500],
            "timestamp":  a.get("timestamp",""),
            "mitre":      {
                "tactic":       a.get("mitre_tactic",""),
                "tactic_id":    a.get("mitre_tactic_id",""),
                "technique":    a.get("mitre_technique",""),
                "technique_id": a.get("mitre_technique_id",""),
            },
        }


def _fmt_ts(ts_str: Optional[str]) -> str:
    if not ts_str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        return datetime.fromisoformat(ts_str).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ts_str
