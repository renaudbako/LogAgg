"""
MITRE ATT&CK Enterprise mapper.

Maps rule names, categories, and message patterns to ATT&CK
tactics and techniques. Each LogEntry gets annotated with:
  mitre_tactic / mitre_tactic_id
  mitre_technique / mitre_technique_id
  mitre_subtechnique_id  (optional)
"""
import re
from typing import Dict, List, NamedTuple, Optional, Tuple

from collectors.base import LogEntry


# ── ATT&CK Tactic registry ─────────────────────────────────────
TACTICS: Dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# Reverse map: name → id
TACTIC_IDS = {v: k for k, v in TACTICS.items()}


class Technique(NamedTuple):
    tactic: str
    tactic_id: str
    technique: str
    technique_id: str
    subtechnique_id: str = ""


# ── Rule-name → ATT&CK mapping ─────────────────────────────────
_RULE_MAP: Dict[str, Technique] = {
    # ── Credential Access ──────────────────────────────
    "SSH Brute Force": Technique(
        "Credential Access", "TA0006",
        "Brute Force: Password Spraying", "T1110", "T1110.003"),
    "Failed Login": Technique(
        "Credential Access", "TA0006",
        "Brute Force", "T1110", ""),
    "Kerberos Attack": Technique(
        "Credential Access", "TA0006",
        "Steal or Forge Kerberos Tickets", "T1558", ""),
    # ── Privilege Escalation ───────────────────────────
    "Sudo Escalation": Technique(
        "Privilege Escalation", "TA0004",
        "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "T1548", "T1548.003"),
    "Root Login": Technique(
        "Privilege Escalation", "TA0004",
        "Valid Accounts: Local Accounts", "T1078", "T1078.003"),
    "Privilege File Modified": Technique(
        "Privilege Escalation", "TA0004",
        "File and Directory Permissions Modification", "T1222", ""),
    "SUID Binary": Technique(
        "Privilege Escalation", "TA0004",
        "Abuse Elevation Control Mechanism: Setuid and Setgid", "T1548", "T1548.001"),
    # ── Defense Evasion ────────────────────────────────
    "Log Tampering": Technique(
        "Defense Evasion", "TA0005",
        "Indicator Removal: Clear Linux or Mac System Logs", "T1070", "T1070.002"),
    "Firewall Block": Technique(
        "Defense Evasion", "TA0005",
        "Impair Defenses: Disable or Modify System Firewall", "T1562", "T1562.004"),
    "File Integrity Violation": Technique(
        "Defense Evasion", "TA0005",
        "Indicator Removal on Host", "T1070", ""),
    "Timestomp": Technique(
        "Defense Evasion", "TA0005",
        "Indicator Removal: Timestomp", "T1070", "T1070.006"),
    # ── Execution ──────────────────────────────────────
    "Malware Indicator": Technique(
        "Execution", "TA0002",
        "Command and Scripting Interpreter: Unix Shell", "T1059", "T1059.004"),
    "Reverse Shell Indicator": Technique(
        "Execution", "TA0002",
        "Command and Scripting Interpreter: Unix Shell", "T1059", "T1059.004"),
    "Suspicious Cron": Technique(
        "Execution", "TA0002",
        "Scheduled Task/Job: Cron", "T1053", "T1053.003"),
    # ── Persistence ────────────────────────────────────
    "Cron Persistence": Technique(
        "Persistence", "TA0003",
        "Scheduled Task/Job: Cron", "T1053", "T1053.003"),
    "SSH Key Added": Technique(
        "Persistence", "TA0003",
        "Account Manipulation: SSH Authorized Keys", "T1098", "T1098.004"),
    "Startup Script": Technique(
        "Persistence", "TA0003",
        "Boot or Logon Initialization Scripts", "T1037", ""),
    # ── Discovery ──────────────────────────────────────
    "Port Scan": Technique(
        "Discovery", "TA0007",
        "Network Service Discovery", "T1046", ""),
    "Port Scan Detected": Technique(
        "Discovery", "TA0007",
        "Network Service Discovery", "T1046", ""),
    "Network Discovery": Technique(
        "Discovery", "TA0007",
        "Remote System Discovery", "T1018", ""),
    "Process Discovery": Technique(
        "Discovery", "TA0007",
        "Process Discovery", "T1057", ""),
    "File Discovery": Technique(
        "Discovery", "TA0007",
        "File and Directory Discovery", "T1083", ""),
    # ── Command and Control ────────────────────────────
    "Suspicious Outbound": Technique(
        "Command and Control", "TA0011",
        "Application Layer Protocol", "T1071", ""),
    "Beaconing Detected": Technique(
        "Command and Control", "TA0011",
        "Application Layer Protocol: Web Protocols", "T1071", "T1071.001"),
    "DNS Tunneling": Technique(
        "Command and Control", "TA0011",
        "Protocol Tunneling", "T1572", ""),
    "C2 Connection": Technique(
        "Command and Control", "TA0011",
        "Ingress Tool Transfer", "T1105", ""),
    "Suspicious Network Connection": Technique(
        "Command and Control", "TA0011",
        "Application Layer Protocol", "T1071", ""),
    # ── Lateral Movement ───────────────────────────────
    "Lateral SSH": Technique(
        "Lateral Movement", "TA0008",
        "Remote Services: SSH", "T1021", "T1021.004"),
    "Pass the Hash": Technique(
        "Lateral Movement", "TA0008",
        "Use Alternate Authentication Material: Pass the Hash", "T1550", "T1550.002"),
    # ── Initial Access ─────────────────────────────────
    "USB Device": Technique(
        "Initial Access", "TA0001",
        "Replication Through Removable Media", "T1091", ""),
    "Phishing": Technique(
        "Initial Access", "TA0001",
        "Phishing", "T1566", ""),
    # ── Impact ─────────────────────────────────────────
    "Process Crash": Technique(
        "Impact", "TA0040",
        "Endpoint Denial of Service", "T1499", ""),
    "OOM Killer": Technique(
        "Impact", "TA0040",
        "Endpoint Denial of Service: Service Exhaustion Flood", "T1499", "T1499.002"),
    "Kernel Error": Technique(
        "Impact", "TA0040",
        "Endpoint Denial of Service", "T1499", ""),
    # ── Collection ─────────────────────────────────────
    "Sensitive File Access": Technique(
        "Collection", "TA0009",
        "Data from Local System", "T1005", ""),
    "Clipboard Capture": Technique(
        "Collection", "TA0009",
        "Clipboard Data", "T1115", ""),
    # ── Exfiltration ───────────────────────────────────
    "Data Exfiltration": Technique(
        "Exfiltration", "TA0010",
        "Exfiltration Over C2 Channel", "T1041", ""),
    "Large Outbound Transfer": Technique(
        "Exfiltration", "TA0010",
        "Exfiltration Over Alternative Protocol", "T1048", ""),
    # ── Reconnaissance ─────────────────────────────────
    "Recon Activity": Technique(
        "Reconnaissance", "TA0043",
        "Active Scanning", "T1595", ""),
}

# ── Pattern-based fallback mapping ────────────────────────────
# (regex, Technique) — checked against message when no rule match
_PATTERN_MAP: List[Tuple[re.Pattern, Technique]] = [
    (re.compile(r"nmap|masscan|port.?scan|syn.?flood", re.I),
     Technique("Discovery", "TA0007", "Network Service Discovery", "T1046", "")),

    (re.compile(r"Failed password|Invalid user|authentication failure|pam.*fail", re.I),
     Technique("Credential Access", "TA0006", "Brute Force", "T1110", "")),

    (re.compile(r"sudo.*COMMAND|su -|runlevel", re.I),
     Technique("Privilege Escalation", "TA0004",
               "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "T1548", "T1548.003")),

    (re.compile(r"wget|curl.*http|base64 -d|/tmp/.*\.(sh|py|elf|pl)", re.I),
     Technique("Execution", "TA0002",
               "Command and Scripting Interpreter: Unix Shell", "T1059", "T1059.004")),

    (re.compile(r"/dev/tcp|mkfifo|nc -e|bash -i|ncat|netcat.*-e", re.I),
     Technique("Execution", "TA0002",
               "Command and Scripting Interpreter: Unix Shell", "T1059", "T1059.004")),

    (re.compile(r"CRON|crontab", re.I),
     Technique("Persistence", "TA0003", "Scheduled Task/Job: Cron", "T1053", "T1053.003")),

    (re.compile(r"rm.*\.log|shred.*log|truncate.*log|> /var/log", re.I),
     Technique("Defense Evasion", "TA0005",
               "Indicator Removal: Clear Linux or Mac System Logs", "T1070", "T1070.002")),

    (re.compile(r"UFW BLOCK|IPTABLES.*DROP|firewall.*DENY", re.I),
     Technique("Defense Evasion", "TA0005",
               "Impair Defenses: Disable or Modify System Firewall", "T1562", "T1562.004")),

    (re.compile(r"session opened for user root|ROOT LOGIN", re.I),
     Technique("Privilege Escalation", "TA0004",
               "Valid Accounts: Local Accounts", "T1078", "T1078.003")),

    (re.compile(r"segfault|core dump|killed process|signal 11", re.I),
     Technique("Impact", "TA0040", "Endpoint Denial of Service", "T1499", "")),

    (re.compile(r"usb.*attach|usb.*connect|new.*speed USB", re.I),
     Technique("Initial Access", "TA0001",
               "Replication Through Removable Media", "T1091", "")),

    (re.compile(r"Out of memory|oom.kill", re.I),
     Technique("Impact", "TA0040",
               "Endpoint Denial of Service: Service Exhaustion Flood", "T1499", "T1499.002")),

    (re.compile(r"chmod.*(?:passwd|shadow|sudoers)|chown.*(?:passwd|shadow)", re.I),
     Technique("Privilege Escalation", "TA0004",
               "File and Directory Permissions Modification", "T1222", "")),

    (re.compile(r"ssh.*accept|ssh.*session|sshd.*open", re.I),
     Technique("Lateral Movement", "TA0008",
               "Remote Services: SSH", "T1021", "T1021.004")),
]

# ── FIM file-path → technique mapping ────────────────────────
_FIM_PATH_MAP: List[Tuple[re.Pattern, Technique]] = [
    (re.compile(r"/etc/passwd|/etc/shadow|/etc/gshadow", re.I),
     Technique("Credential Access", "TA0006",
               "OS Credential Dumping: /etc/passwd and /etc/shadow", "T1003", "T1003.008")),
    (re.compile(r"/etc/sudoers|/etc/sudoers\.d", re.I),
     Technique("Privilege Escalation", "TA0004",
               "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "T1548", "T1548.003")),
    (re.compile(r"\.ssh/authorized_keys|\.ssh/id_", re.I),
     Technique("Persistence", "TA0003",
               "Account Manipulation: SSH Authorized Keys", "T1098", "T1098.004")),
    (re.compile(r"/etc/cron|/var/spool/cron", re.I),
     Technique("Persistence", "TA0003",
               "Scheduled Task/Job: Cron", "T1053", "T1053.003")),
    (re.compile(r"/etc/profile|/etc/bash|\.bashrc|\.profile|\.bash_profile", re.I),
     Technique("Persistence", "TA0003",
               "Boot or Logon Initialization Scripts: RC Scripts", "T1037", "T1037.004")),
    (re.compile(r"/etc/systemd|/lib/systemd|\.service$", re.I),
     Technique("Persistence", "TA0003",
               "Create or Modify System Process: Systemd Service", "T1543", "T1543.002")),
    (re.compile(r"/etc/ld\.so|/etc/hosts|/etc/resolv\.conf", re.I),
     Technique("Defense Evasion", "TA0005",
               "Hijack Execution Flow", "T1574", "")),
    (re.compile(r"/tmp/|/var/tmp/|/dev/shm/", re.I),
     Technique("Execution", "TA0002",
               "Command and Scripting Interpreter", "T1059", "")),
    (re.compile(r"/bin/|/sbin/|/usr/bin/|/usr/sbin/", re.I),
     Technique("Defense Evasion", "TA0005",
               "Masquerading: Invalid Code Signature", "T1036", "T1036.001")),
]

# ── Network-category → technique mapping ─────────────────────
_NET_PORT_MAP: Dict[int, Technique] = {
    22:   Technique("Lateral Movement",    "TA0008", "Remote Services: SSH", "T1021", "T1021.004"),
    23:   Technique("Lateral Movement",    "TA0008", "Remote Services", "T1021", ""),
    3389: Technique("Lateral Movement",    "TA0008", "Remote Services: Remote Desktop Protocol", "T1021", "T1021.001"),
    445:  Technique("Lateral Movement",    "TA0008", "Remote Services: SMB/Windows Admin Shares", "T1021", "T1021.002"),
    139:  Technique("Lateral Movement",    "TA0008", "Remote Services: SMB/Windows Admin Shares", "T1021", "T1021.002"),
    4444: Technique("Command and Control", "TA0011", "Application Layer Protocol", "T1071", ""),
    1337: Technique("Command and Control", "TA0011", "Application Layer Protocol", "T1071", ""),
    6666: Technique("Command and Control", "TA0011", "Application Layer Protocol", "T1071", ""),
    6667: Technique("Command and Control", "TA0011", "IRC", "T1071", ""),
    53:   Technique("Command and Control", "TA0011", "Protocol Tunneling", "T1572", ""),
    80:   Technique("Command and Control", "TA0011", "Application Layer Protocol: Web Protocols", "T1071", "T1071.001"),
    443:  Technique("Command and Control", "TA0011", "Application Layer Protocol: Web Protocols", "T1071", "T1071.001"),
    8080: Technique("Command and Control", "TA0011", "Application Layer Protocol: Web Protocols", "T1071", "T1071.001"),
    25:   Technique("Exfiltration",        "TA0010", "Exfiltration Over Alternative Protocol", "T1048", ""),
    587:  Technique("Exfiltration",        "TA0010", "Exfiltration Over Alternative Protocol", "T1048", ""),
}


class MitreMapper:
    """
    Annotates LogEntry objects with MITRE ATT&CK context.
    Call `annotate(entry)` — mutates in-place, returns entry.
    """

    def annotate(self, entry: LogEntry) -> LogEntry:
        tech = self._resolve(entry)
        if tech:
            entry.mitre_tactic       = tech.tactic
            entry.mitre_tactic_id    = tech.tactic_id
            entry.mitre_technique    = tech.technique
            entry.mitre_technique_id = tech.technique_id
            entry.mitre_subtechnique_id = tech.subtechnique_id
        return entry

    def _resolve(self, entry: LogEntry) -> Optional[Technique]:
        # 1. Exact rule-name lookup
        for rule in entry.matched_rules:
            if rule in _RULE_MAP:
                return _RULE_MAP[rule]

        # 2. FIM filepath lookup
        if entry.category == "fim" and entry.filepath:
            for pat, tech in _FIM_PATH_MAP:
                if pat.search(entry.filepath):
                    return tech

        # 3. Network port lookup
        if entry.category in ("network", "portscan") and entry.dst_port:
            if entry.dst_port in _NET_PORT_MAP:
                return _NET_PORT_MAP[entry.dst_port]

        # 4. Port scan category override
        if entry.category == "portscan":
            return _RULE_MAP["Port Scan Detected"]

        # 5. Pattern matching on message
        for pat, tech in _PATTERN_MAP:
            if pat.search(entry.message) or pat.search(entry.raw):
                return tech

        return None

    # ── Aggregation helpers for the dashboard ──────────────────

    @staticmethod
    def tactic_counts(entries: List[LogEntry]) -> Dict[str, int]:
        """Count entries per tactic, ordered by ATT&CK kill-chain."""
        counts: Dict[str, int] = {t: 0 for t in TACTICS.values()}
        for e in entries:
            if e.mitre_tactic:
                counts[e.mitre_tactic] = counts.get(e.mitre_tactic, 0) + 1
        return {k: v for k, v in counts.items() if v > 0}

    @staticmethod
    def technique_summary(entries: List[LogEntry]) -> List[Dict]:
        """Top techniques with counts for the ATT&CK heatmap."""
        summary: Dict[str, dict] = {}
        for e in entries:
            if not e.mitre_technique_id:
                continue
            key = e.mitre_technique_id
            if key not in summary:
                summary[key] = {
                    "technique_id": e.mitre_technique_id,
                    "technique":    e.mitre_technique,
                    "tactic":       e.mitre_tactic,
                    "tactic_id":    e.mitre_tactic_id,
                    "count": 0,
                }
            summary[key]["count"] += 1
        return sorted(summary.values(), key=lambda x: -x["count"])
