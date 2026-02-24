# 🐧 Ubuntu Log Collector & Parser

A lightweight Bash script that collects, parses, and summarizes system logs from Ubuntu/Debian systems into a single human-readable report.

Perfect for sysadmins, DevOps engineers, and anyone who needs a quick snapshot of system health without digging through dozens of log files manually.

---

## Features

- **One-command collection** — gathers logs from 10+ sources in seconds
- **Human-readable report** — structured, formatted output with severity labels and aligned columns
- **Executive summary** — quick health check (failed services, disk usage, memory, error counts, SSH failures)
- **Raw log backup** — keeps unmodified copies alongside the parsed report
- **Auto-compression** — outputs a `.tar.gz` archive ready to share or archive
- **Graceful degradation** — works with or without root, falls back to `journalctl` when traditional log files are missing
- **Zero dependencies** — uses only standard Ubuntu/Debian tools

## What It Collects

| Category | Source | Details |
|---|---|---|
| **System Info** | `/etc/os-release`, `lscpu`, `free`, `df`, `ip` | OS, CPU, memory, disk, network interfaces |
| **Syslog** | `/var/log/syslog` or `journalctl` | Parsed into timestamp, host, service, message |
| **Authentication** | `/var/log/auth.log` | Successful/failed logins, sudo command history |
| **Kernel** | `dmesg` | Messages classified as ERROR / WARN / INFO |
| **Journal Errors** | `journalctl -p err` | Emergency through error-level entries |
| **Services** | `systemctl` | Failed units, top 20 services by memory usage |
| **Packages** | `/var/log/apt/history.log` | Recent install/upgrade/remove operations |
| **Boot** | `journalctl --list-boots` | Last 3 boot times + current boot errors |
| **Cron** | syslog / `journalctl -u cron` | Recent cron activity + active crontab |
| **Network** | `ss`, `ufw`, `/etc/resolv.conf` | Active connections, listening ports, firewall rules, DNS |

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/eligof/ubuntu-log-collector.git
cd ubuntu-log-collector
```

### 2. Make the script executable

```bash
chmod +x log_collector.sh
```

### 3. Run it

```bash
# Basic run (some logs may be restricted)
./log_collector.sh

# Full access (recommended)
sudo ./log_collector.sh
```

## Output Structure

```
log_report_2025-02-24_14-30-00/
├── system_report.txt       # The full human-readable report
└── raw_logs/               # Unmodified log copies
    ├── syslog.log
    ├── auth.log
    ├── dmesg.log
    ├── journal_errors.log
    └── apt_history.log

log_report_2025-02-24_14-30-00.tar.gz   # Compressed archive
```

## Sample Report Output

```
================================================================================
  EXECUTIVE SUMMARY
  Collected: Mon Feb 24 14:30:00 UTC 2025
================================================================================

Quick Health Check:

  ✓ Services:      All services running normally
  ✓ Disk Usage:    All filesystems under 85%
  ✓ Memory:        42% used
  ℹ Errors:        17 error-level journal entries in last 3 days
  ℹ SSH Failures:  3 failed password attempts in auth.log

================================================================================
  AUTHENTICATION LOG (Login Attempts & sudo Usage)
================================================================================

--- Successful Logins ---
  Feb 24 10:15:03  | User: admin           | session opened for user admin
  Feb 24 12:42:18  | User: deploy           | Accepted publickey for deploy

--- Failed Login Attempts ---
  Feb 24 03:12:44  | sshd: Failed password for invalid user test from 192.168.1.50

--- Sudo Commands ---
  Feb 24 10:16:01  | Command: /usr/bin/apt update
```

## Configuration

Edit the variables at the top of `log_collector.sh` to customize behavior:

```bash
MAX_LINES=500       # Max recent lines to collect per log source
DAYS_BACK=3         # How far back to search journalctl entries
```

## Requirements

- **OS:** Ubuntu 16.04+ / Debian 9+ (or any systemd-based distro)
- **Shell:** Bash 4+
- **Tools:** All standard — `awk`, `grep`, `sed`, `tar`, `systemctl`, `journalctl`, `ss`
- **Permissions:** Runs without root (limited), full collection with `sudo`

## Use Cases

- **Incident response** — quickly gather logs after an issue for analysis or handoff
- **Routine health checks** — run periodically to monitor system state
- **Server audits** — capture a snapshot before/after changes
- **Remote troubleshooting** — generate a report and send the `.tar.gz` to your team
- **Onboarding** — get familiar with a new server's state in one command

## Automation

Run the collector on a schedule with cron:

```bash
# Weekly report every Sunday at 2 AM
0 2 * * 0 /path/to/log_collector.sh >> /var/log/log_collector_cron.log 2>&1
```

To keep only the last N reports:

```bash
# Clean up reports older than 30 days
find /path/to/reports/ -name "log_report_*.tar.gz" -mtime +30 -delete
```

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

> **Tip:** For best results, always run with `sudo` to ensure access to all log sources.
