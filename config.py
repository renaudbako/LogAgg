"""
LogAgg Configuration
Centralized settings for all components.
"""
import platform
from dataclasses import dataclass, field
from typing import List

PLATFORM = platform.system().lower()  # 'linux', 'windows', 'darwin'


@dataclass
class LogSource:
    path: str
    name: str
    enabled: bool = True
    encoding: str = "utf-8"


@dataclass
class AlertRule:
    name: str
    pattern: str
    level: str          # 'info' | 'warning' | 'critical'
    description: str
    enabled: bool = True


@dataclass
class Config:
    # ── Storage ──────────────────────────────────────────────────
    db_path: str = "logagg.db"

    # ── Web server ───────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 5000
    debug: bool = False

    # ── Collection ───────────────────────────────────────────────
    collect_interval: int = 30          # seconds between periodic polls
    max_initial_lines: int = 2000       # lines read on first collection

    # ── Anomaly detection ────────────────────────────────────────
    ml_enabled: bool = True
    ml_train_size: int = 800            # entries before first model fit
    ml_contamination: float = 0.05
    anomaly_threshold: float = -0.10    # Isolation-Forest score cut-off

    # ── File Integrity Monitoring ────────────────────────────────
    fim_enabled: bool = True
    fim_rescan_interval: int = 60       # full re-hash every N seconds
    fim_paths: List[str] = field(default_factory=lambda: [
        # Auth & credentials
        "/etc/passwd",
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/group",
        # Privilege escalation targets
        "/etc/sudoers",
        "/etc/sudoers.d",
        # SSH
        "/etc/ssh/sshd_config",
        "/root/.ssh/authorized_keys",
        # Persistence vectors
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/environment",
        # Systemd services
        "/etc/systemd/system",
        "/lib/systemd/system",
        # Name resolution (hijacking)
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/nsswitch.conf",
        # Dynamic linker (hijack)
        "/etc/ld.so.conf",
        "/etc/ld.so.preload",
        # PAM (auth bypass)
        "/etc/pam.conf",
        "/etc/pam.d",
        # Binary paths (tampering)
        "/usr/bin/sudo",
        "/usr/bin/su",
        "/bin/login",
    ])

    # ── Network monitor ──────────────────────────────────────────
    network_monitor_enabled: bool = True
    network_interval: int = 15          # snapshot every N seconds
    port_scan_threshold: int = 12       # unique ports before alert
    port_scan_window: int = 60          # window in seconds

    # ── Linux log sources ────────────────────────────────────────
    linux_sources: List[LogSource] = field(default_factory=lambda: [
        LogSource("/var/log/syslog",           "syslog"),
        LogSource("/var/log/auth.log",         "auth"),
        LogSource("/var/log/kern.log",         "kernel"),
        LogSource("/var/log/messages",         "messages", enabled=False),
        LogSource("/var/log/secure",           "secure",   enabled=False),
        LogSource("/var/log/apache2/access.log","apache_access", enabled=False),
        LogSource("/var/log/apache2/error.log", "apache_error",  enabled=False),
        LogSource("/var/log/nginx/access.log",  "nginx_access",  enabled=False),
        LogSource("/var/log/nginx/error.log",   "nginx_error",   enabled=False),
    ])

    # ── macOS log sources ────────────────────────────────────────
    macos_sources: List[LogSource] = field(default_factory=lambda: [
        LogSource("/var/log/system.log",  "system"),
        LogSource("/var/log/install.log", "install", enabled=False),
    ])

    # ── Windows Event Log channels ───────────────────────────────
    windows_channels: List[str] = field(default_factory=lambda: [
        "System", "Application", "Security",
        "Microsoft-Windows-PowerShell/Operational",
    ])

    # ── Security detection rules ─────────────────────────────────
    alert_rules: List[AlertRule] = field(default_factory=lambda: [
        AlertRule("SSH Brute Force",
                  r"Failed password.*ssh|sshd.*Invalid user",
                  "critical", "Multiple SSH authentication failures"),
        AlertRule("Sudo Escalation",
                  r"sudo.*COMMAND|sudo.*authentication failure",
                  "warning", "Sudo command executed"),
        AlertRule("Failed Login",
                  r"authentication failure|Failed password|Invalid user|pam_unix.*failed",
                  "warning", "Failed login attempt"),
        AlertRule("Root Login",
                  r"session opened for user root|ROOT LOGIN|logged in as root",
                  "critical", "Root login detected"),
        AlertRule("Process Crash",
                  r"segfault|core dump(ed)?|killed process|signal 11",
                  "warning", "Process crash / segfault"),
        AlertRule("Firewall Block",
                  r"IPTABLES.*DROP|UFW BLOCK|firewall.*DENY|Blocked.*port",
                  "warning", "Firewall blocked connection"),
        AlertRule("Malware Indicator",
                  r"wget https?://|curl https?://|base64 -d|/tmp/\w+\.(sh|py|pl|elf)",
                  "critical", "Potential malware download / execution"),
        AlertRule("Log Tampering",
                  r"rm.*\.log|truncate.*log|> /var/log|shred.*log",
                  "critical", "Possible log tampering"),
        AlertRule("Port Scan",
                  r"nmap|masscan|port scan|SYN flood|too many connections",
                  "critical", "Port scanning / flood detected"),
        AlertRule("Kernel Error",
                  r"kernel:.*(?:ERROR|FATAL|BUG|panic|Oops)",
                  "warning", "Kernel error"),
        AlertRule("OOM Killer",
                  r"Out of memory.*Kill process|oom.kill",
                  "warning", "OOM killer triggered"),
        AlertRule("USB Device",
                  r"(?:usb|USB).*(?:attached|connected|new (?:full|high|low|super))",
                  "warning", "USB device connected"),
        AlertRule("Suspicious Cron",
                  r"crontab.*(?:root|nobody)|CRON.*(?:wget|curl|bash|python)",
                  "critical", "Suspicious cron job"),
        AlertRule("Reverse Shell Indicator",
                  r"(?:bash|sh|nc|ncat|netcat).*-[ei]|/dev/tcp/|mkfifo",
                  "critical", "Possible reverse-shell command"),
        AlertRule("Privilege File Modified",
                  r"(?:chmod|chown).*(?:/etc/passwd|/etc/shadow|/etc/sudoers)",
                  "critical", "Critical file permission change"),
    ])


# Singleton used by all modules unless overridden
default_config = Config()
