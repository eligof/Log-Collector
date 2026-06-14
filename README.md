# Log Collector & Parser

A lightweight Bash script that collects, parses, and summarizes system and security logs from Ubuntu and Debian systems into a single human-readable report. Can also emit a machine-readable JSON summary for ingestion into a SIEM.

Built for sysadmins, DevOps, and security engineers who need a quick, structured snapshot of system health without digging through dozens of log files by hand.

---

## Features

- **One-command collection** gathers logs from 10+ sources in seconds
- **Human-readable report** structured output with severity labels and aligned columns
- **Executive summary** quick health check (failed services, disk usage, memory, error counts, SSH failures)
- **JSON summary** optional `--json` output for SIEM ingestion (Wazuh, Splunk, etc.)
- **Configurable via flags** set days, line counts, and output directory at runtime
- **Raw log backup** keeps unmodified copies alongside the parsed report
- **Auto-compression** outputs a `.tar.gz` archive ready to share or store
- **Graceful degradation** works with or without root, falls back to `journalctl` when traditional log files are missing
- **Zero dependencies** uses only standard Ubuntu/Debian tools

## What It Collects

| Category | Source | Details |
|---|---|---|
| **System Info** | `/etc/os-release`, `lscpu`, `free`, `df`, `ip` | OS, CPU, memory, disk, network interfaces |
| **Syslog** | `/var/log/syslog` or `journalctl` | Parsed into timestamp, host, service, message |
| **Authentication** | `/var/log/auth.log` | Successful and failed logins, sudo command history |
| **Kernel** | `dmesg` | Messages classified as ERROR / WARN / INFO |
| **Journal Errors** | `journalctl -p err` | Emergency through error-level entries |
| **Services** | `systemctl` | Failed units, top 20 services by memory usage |
| **Packages** | `/var/log/apt/history.log` | Recent install/upgrade/remove operations |
| **Boot** | `journalctl --list-boots` | Last boots and current boot errors |
| **Cron** | syslog / `journalctl -u cron` | Recent cron activity and active crontab |
| **Network** | `ss`, `ufw`, `/etc/resolv.conf` | Active connections, listening ports, firewall rules, DNS |

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/eligof/Log-Collector.git
cd Log-Collector

# 2. Make the script executable
chmod +x log_collector.sh

# 3. Run it (use sudo for full access to restricted logs)
sudo ./log_collector.sh
```

## Usage

```
Usage: ./log_collector.sh [options]

Options:
  -d, --days N      Days back to search journal logs (default: 3)
  -l, --lines N     Max recent lines per log source (default: 500)
  -o, --output DIR  Output directory (default: ./log_report_<timestamp>)
  -j, --json        Also write a machine-readable summary.json (SIEM friendly)
  -h, --help        Show this help and exit
```

Examples:

```bash
# Last 7 days, 1000 lines per source, with a JSON summary
sudo ./log_collector.sh --days 7 --lines 1000 --json

# Write the report to a specific directory
sudo ./log_collector.sh --output /var/tmp/audit_$(hostname)
```

## Output Structure

```
log_report_2026-06-14_14-30-00/
├── system_report.txt       # The full human-readable report
├── summary.json            # Machine-readable summary (only with --json)
└── raw_logs/               # Unmodified log copies
    ├── syslog.log
    ├── auth.log
    ├── dmesg.log
    ├── journal_errors.log
    └── apt_history.log

log_report_2026-06-14_14-30-00.tar.gz   # Compressed archive
```

## Sample Output

```
================================================================================
  EXECUTIVE SUMMARY
================================================================================

Quick Health Check:

  [ok] Services:      All services running normally
  [ok] Disk Usage:    All filesystems under 85%
  [ok] Memory:        42% used
  [i] Errors:        17 error-level journal entries in last 3 days
  [i] SSH Failures:  3 failed password attempts in auth.log
```

JSON summary (`--json`):

```json
{
  "hostname": "web-01",
  "collected_at": "2026-06-14T14:30:00+00:00",
  "kernel": "6.8.0-31-generic",
  "days_back": 3,
  "summary": {
    "failed_services": 0,
    "high_disk_filesystems": "",
    "memory_used_percent": 42,
    "journal_errors": 17,
    "ssh_failed_passwords": 3
  }
}
```

## Requirements

- **OS:** Ubuntu 16.04+ / Debian 9+ (or any systemd-based distro)
- **Shell:** Bash 4+
- **Tools:** Standard only (`awk`, `grep`, `sed`, `tar`, `systemctl`, `journalctl`, `ss`)
- **Permissions:** Runs without root (limited), full collection with `sudo`

## Use Cases

- **Incident response** quickly gather logs after an issue for analysis or handoff
- **Routine health checks** run periodically to monitor system state
- **Server audits** capture a snapshot before and after changes
- **Remote troubleshooting** generate a report and send the `.tar.gz` to your team
- **SIEM ingestion** feed the JSON summary into a centralized monitoring pipeline

## Automation

Run the collector on a schedule with cron:

```bash
# Weekly report every Sunday at 2 AM, with JSON output
0 2 * * 0 /path/to/log_collector.sh --json >> /var/log/log_collector_cron.log 2>&1
```

Keep only recent reports:

```bash
# Remove reports older than 30 days
find /path/to/reports/ -name "log_report_*.tar.gz" -mtime +30 -delete
```

## Security Note

The generated report and the `.tar.gz` archive contain sensitive system and authentication data, including usernames, SSH login attempts, sudo command history, IP addresses, and open ports. Store and transfer these files securely, and remove them when they are no longer needed.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
