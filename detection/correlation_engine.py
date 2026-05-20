"""
Correlation engine — multi-stage attack detection.

Each incoming LogEntry is fed to `observe(entry)`.  The engine maintains
a per-source-IP sliding window of observed MITRE tactics and fires a
correlated "multi-stage attack" alert when a defined chain is completed.

Chain example:
  Discovery → Credential Access → Privilege Escalation  within 60 min
  = "Reconnaissance-to-Compromise" campaign alert.

Design notes
-----------
* Chains are checked in order; the *first* match fires the alert.
* A chain fires at most once per source per `cooldown_minutes`.
* An entry with no MITRE tactic is silently ignored by the engine
  (it still flows through the normal pipeline).
* Thread-safe; safe to call from multiple pipeline threads.
"""
from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional, Set, Tuple

from collectors.base import LogEntry


# ── Chain definitions ─────────────────────────────────────────
@dataclass(frozen=True)
class Chain:
    name:            str
    tactics:         Tuple[str, ...]   # ordered — ALL must be present
    window_minutes:  int
    severity:        str               # CRITICAL | WARNING
    description:     str
    cooldown_minutes: int = 30         # suppress repeat for same source


CHAINS: List[Chain] = [
    Chain(
        name="Reconnaissance to Compromise",
        tactics=("Discovery", "Credential Access", "Privilege Escalation"),
        window_minutes=60,
        severity="CRITICAL",
        description=(
            "Full attack chain observed: network discovery followed by "
            "credential attack and privilege escalation from the same source."
        ),
    ),
    Chain(
        name="Initial Access to Persistence",
        tactics=("Initial Access", "Execution", "Persistence"),
        window_minutes=90,
        severity="CRITICAL",
        description=(
            "Attacker gained initial access, executed code, and established "
            "persistence mechanisms."
        ),
    ),
    Chain(
        name="Credential Theft to Lateral Movement",
        tactics=("Credential Access", "Lateral Movement"),
        window_minutes=45,
        severity="CRITICAL",
        description=(
            "Credential theft followed by lateral movement — possible "
            "pass-the-hash or stolen SSH key use."
        ),
    ),
    Chain(
        name="Defense Evasion Campaign",
        tactics=("Defense Evasion", "Privilege Escalation"),
        window_minutes=30,
        severity="CRITICAL",
        description=(
            "Security controls disabled or tampered with, combined with "
            "privilege escalation — active hands-on intrusion likely."
        ),
    ),
    Chain(
        name="Data Exfiltration Attempt",
        tactics=("Collection", "Exfiltration"),
        window_minutes=60,
        severity="CRITICAL",
        description=(
            "Data collection activity followed by exfiltration attempt."
        ),
    ),
    Chain(
        name="C2 Established",
        tactics=("Execution", "Command and Control"),
        window_minutes=30,
        severity="CRITICAL",
        description=(
            "Remote code execution followed by command-and-control "
            "communication — likely active backdoor."
        ),
    ),
    Chain(
        name="Port Scan to Brute Force",
        tactics=("Discovery", "Credential Access"),
        window_minutes=20,
        severity="WARNING",
        description=(
            "Port scan from source immediately followed by authentication "
            "attacks — automated attack tool likely."
        ),
    ),
    Chain(
        name="Log Tampering After Intrusion",
        tactics=("Privilege Escalation", "Defense Evasion"),
        window_minutes=30,
        severity="CRITICAL",
        description=(
            "Privilege escalation followed by log tampering or defence "
            "evasion — attacker covering tracks."
        ),
    ),
    Chain(
        name="Persistence to Exfiltration",
        tactics=("Persistence", "Collection", "Exfiltration"),
        window_minutes=120,
        severity="CRITICAL",
        description=(
            "Long-term access pattern: persistence established, data "
            "collected, then exfiltrated."
        ),
    ),
]


# ── Per-source state ──────────────────────────────────────────
@dataclass
class _SourceState:
    # tactic → list of event timestamps
    tactic_times: Dict[str, List[datetime]] = field(
        default_factory=lambda: defaultdict(list))
    # chain_name → last fired time
    fired: Dict[str, datetime] = field(default_factory=dict)


class CorrelationEngine:
    """
    Feed every annotated LogEntry through `observe(entry)`.
    Set `on_correlated` to receive chain-completion events.
    """

    def __init__(
        self,
        on_correlated: Optional[Callable[[LogEntry, Chain, str], None]] = None,
    ):
        self._on_correlated = on_correlated
        self._lock  = threading.Lock()
        self._state: Dict[str, _SourceState] = defaultdict(_SourceState)
        self._total_correlations = 0

    # ── Public API ────────────────────────────────────────────

    def observe(self, entry: LogEntry) -> Optional[Tuple[Chain, str]]:
        """
        Record the tactic from `entry`, check all chains.
        Returns (matched_chain, summary_message) or None.
        Also calls on_correlated callback.
        """
        tactic = entry.mitre_tactic
        if not tactic:
            return None

        # Derive a source key — prefer IP, fall back to process source
        src_key = entry.src_ip or entry.source.split("/")[0]

        now = entry.timestamp or datetime.now()

        with self._lock:
            state = self._state[src_key]

            # Record this tactic observation
            state.tactic_times[tactic].append(now)

            # Prune old events (keep max window across all chains)
            max_window = max(c.window_minutes for c in CHAINS)
            cutoff = now - timedelta(minutes=max_window)
            for t in list(state.tactic_times.keys()):
                state.tactic_times[t] = [
                    ts for ts in state.tactic_times[t] if ts >= cutoff
                ]

            # Check each chain
            for chain in CHAINS:
                result = self._check_chain(state, chain, src_key, now, entry)
                if result:
                    return result

        return None

    def get_stats(self) -> Dict:
        with self._lock:
            active_sources = len(self._state)
            chains_fired   = sum(
                len(s.fired) for s in self._state.values()
            )
        return {
            "total_correlations": self._total_correlations,
            "active_sources":     active_sources,
            "chains_defined":     len(CHAINS),
        }

    # ── Internal ─────────────────────────────────────────────

    def _check_chain(
        self,
        state: _SourceState,
        chain: Chain,
        src_key: str,
        now: datetime,
        trigger_entry: LogEntry,
    ) -> Optional[Tuple[Chain, str]]:
        # All tactics in chain must have at least one event
        for tactic in chain.tactics:
            if not state.tactic_times.get(tactic):
                return None

        # Find a time window that contains all tactics
        window = timedelta(minutes=chain.window_minutes)
        # Walk possible windows anchored on each observation of the last tactic
        last_tactic = chain.tactics[-1]
        for anchor in state.tactic_times[last_tactic]:
            window_start = anchor - window
            # Check every required tactic has an event in [window_start, anchor]
            if all(
                any(window_start <= ts <= anchor
                    for ts in state.tactic_times.get(t, []))
                for t in chain.tactics
            ):
                # Dedup: don't fire same chain for same source within cooldown
                last_fired = state.fired.get(chain.name, datetime.min)
                if now - last_fired < timedelta(minutes=chain.cooldown_minutes):
                    return None

                state.fired[chain.name] = now
                self._total_correlations += 1

                # Build timeline string for the alert message
                timeline = " → ".join(
                    f"{t} ({self._latest_ts(state, t, window_start, anchor)})"
                    for t in chain.tactics
                )
                summary = (
                    f"[CORRELATED] {chain.name} from {src_key}: "
                    f"{timeline}"
                )
                alert_entry = self._make_alert(
                    chain, src_key, summary, trigger_entry)

                if self._on_correlated:
                    self._on_correlated(alert_entry, chain, summary)

                return chain, summary

        return None

    @staticmethod
    def _latest_ts(
        state: _SourceState,
        tactic: str,
        start: datetime,
        end: datetime,
    ) -> str:
        times = [
            ts for ts in state.tactic_times.get(tactic, [])
            if start <= ts <= end
        ]
        if not times:
            return "?"
        return max(times).strftime("%H:%M:%S")

    @staticmethod
    def _make_alert(
        chain: Chain,
        src_key: str,
        summary: str,
        trigger: LogEntry,
    ) -> LogEntry:
        return LogEntry(
            timestamp     = datetime.now(),
            source        = f"correlation/{src_key}",
            level         = chain.severity,
            message       = summary,
            platform      = trigger.platform,
            raw           = summary,
            matched_rules = [chain.name],
            tags          = ["correlated", "multi-stage",
                             *[f"tactic:{t}" for t in chain.tactics]],
            is_anomaly    = True,
            anomaly_score = 0.99,
            category      = "log",
            src_ip        = trigger.src_ip or src_key,
            mitre_tactic  = chain.tactics[-1],
            mitre_tactic_id = "",
            mitre_technique  = chain.name,
            mitre_technique_id = "CORR",
        )
