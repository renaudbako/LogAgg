"""
Rule-based pattern matcher.
Applies AlertRule regexes from config against incoming LogEntry messages.
"""
import re
from typing import List, Tuple

from collectors.base import LogEntry


class PatternMatcher:
    """
    Compiles AlertRule patterns at startup for O(1) per-rule matching.
    Returns matched rule names and the highest matched severity level.
    """

    _LEVEL_ORDER = {"info": 0, "warning": 1, "critical": 2}

    def __init__(self, config):
        self._rules: List[Tuple[str, re.Pattern, str]] = []
        for rule in config.alert_rules:
            if not rule.enabled:
                continue
            try:
                pattern = re.compile(rule.pattern, re.IGNORECASE)
                self._rules.append((rule.name, pattern, rule.level))
            except re.error:
                pass  # skip malformed patterns

    def match(self, entry: LogEntry) -> Tuple[List[str], str]:
        """
        Returns (matched_rule_names, highest_level_string).
        highest_level_string is one of 'info' | 'warning' | 'critical',
        or empty string if no rules matched.
        """
        matched: List[str] = []
        best_level = ""
        text = entry.message + " " + entry.raw

        for name, pattern, level in self._rules:
            if pattern.search(text):
                matched.append(name)
                if self._LEVEL_ORDER.get(level, 0) > self._LEVEL_ORDER.get(best_level, -1):
                    best_level = level

        return matched, best_level

    def annotate(self, entry: LogEntry) -> LogEntry:
        """Mutates entry in-place: sets matched_rules and upgrades level."""
        matched, best_level = self.match(entry)
        if matched:
            entry.matched_rules = matched
            _upgrade_map = {"info": "INFO", "warning": "WARNING", "critical": "CRITICAL"}
            upgraded = _upgrade_map.get(best_level, "INFO")
            # Only upgrade, never downgrade
            _order = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
            if _order.get(upgraded, 0) > _order.get(entry.level, 0):
                entry.level = upgraded
        return entry
