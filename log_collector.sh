#!/usr/bin/env bash
# ============================================================================
# Ubuntu Log Collector & Parser
# Collects system logs and outputs a human-readable report.
# Optionally emits a machine-readable JSON summary for SIEM ingestion.
# ============================================================================

set -euo pipefail

VERSION="1.1.0"

# --- Defaults (overridable via flags) ---
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
MAX_LINES=500          # Max recent lines to grab per log
DAYS_BACK=3            # How many days back to look for journal logs
OUTPUT_DIR=""          # Defaults to ./log_report_<timestamp> if not set
JSON_OUTPUT=false      # Set true with --json

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'
DIM='\033[2m'

# --- Usage ---
usage() {
    cat <<EOF
Ubuntu Log Collector & Parser v${VERSION}

Collects and summarizes system and security logs into a single report.

Usage: $0 [options]

Options:
  -d, --days N      Days back to search journal logs (default: ${DAYS_BACK})
  -l, --lines N     Max recent lines per log source (default: ${MAX_LINES})
  -o, --output DIR  Output directory (default: ./log_report_<timestamp>)
  -j, --json        Also write a machine-readable summary.json (SIEM friendly)
  -h, --help        Show this help and exit

Run with sudo for full access to restricted logs.

Note: the generated report and archive contain sensitive system and
authentication data. Store and share them securely.
EOF
}

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--days)   DAYS_BACK="${2:?--days requires a value}"; shift 2 ;;
        -l|--lines)  MAX_LINES="${2:?--lines requires a value}"; shift 2 ;;
        -o|--output) OUTPUT_DIR="${2:?--output requires a value}"; shift 2 ;;
        -j|--json)   JSON_OUTPUT=true; shift ;;
        -h|--help)   usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

# Validate numeric inputs
[[ "$DAYS_BACK" =~ ^[0-9]+$ ]] || { echo "Error: --days must be a number" >&2; exit 1; }
[[ "$MAX_LINES" =~ ^[0-9]+$ ]] || { echo "Error: --lines must be a number" >&2; exit 1; }

# Derive paths after parsing
OUTPUT_DIR="${OUTPUT_DIR:-./log_report_${TIMESTAMP}}"
REPORT_FILE="${OUTPUT_DIR}/system_report.txt"
RAW_DIR="${OUTPUT_DIR}/raw_logs"
JSON_FILE="${OUTPUT_DIR}/summary.json"

# Health-check metrics (defaults; populated by compute_metrics)
M_FAILED=0; M_HIGH_DISK=""; M_MEM=0; M_ERRORS=0; M_SSH=0

# --- Progress Bar ---
TOTAL_STEPS=12
CURRENT_STEP=0
BAR_WIDTH=40
START_TIME=$(date +%s)

STEP_NAMES=(
    "System Information"
    "Syslog"
    "Authentication Logs"
    "Kernel Logs"
    "Journal Errors"
    "Service Status"
    "Package History"
    "Boot Logs"
    "Cron Logs"
    "Network Info"
    "Summary Report"
    "Compressing Archive"
)

format_elapsed() {
    local now elapsed mins secs
    now=$(date +%s)
    elapsed=$((now - START_TIME))
    mins=$((elapsed / 60))
    secs=$((elapsed % 60))
    printf "%dm %02ds" "$mins" "$secs"
}

draw_progress_bar() {
    local step=$1 total=$2 label=$3
    local percent filled empty bar=""
    percent=$((step * 100 / total))
    filled=$((step * BAR_WIDTH / total))
    empty=$((BAR_WIDTH - filled))

    if [[ $filled -gt 0 ]]; then
        bar=$(printf '#%.0s' $(seq 1 "$filled"))
    fi
    if [[ $empty -gt 0 ]]; then
        bar+=$(printf '.%.0s' $(seq 1 "$empty"))
    fi

    if [[ $step -gt 0 ]]; then
        echo -ne "\033[3A"
    fi

    echo -e "  ${CYAN}${bar}${NC}  ${BOLD}${percent}%${NC}  (${step}/${total})    "
    echo -e "  ${GREEN}>${NC} ${label}                                        "
    echo -e "  ${DIM}Elapsed: $(format_elapsed)${NC}                          "
}

advance_step() {
    local label="${STEP_NAMES[$CURRENT_STEP]}"
    draw_progress_bar "$((CURRENT_STEP + 1))" "$TOTAL_STEPS" "$label"
    CURRENT_STEP=$((CURRENT_STEP + 1))
}

# --- Helper Functions ---
print_header()  { echo -e "${CYAN}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error()   { echo -e "${RED}[x]${NC} $1"; }

separator() {
    printf '%0.s=' {1..80} >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

section_header() {
    echo "" >> "$REPORT_FILE"
    separator
    echo "  $1" >> "$REPORT_FILE"
    echo "  Collected: $(date)" >> "$REPORT_FILE"
    separator
    echo "" >> "$REPORT_FILE"
}

check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        print_warning "Not running as root. Some logs may be inaccessible."
        print_warning "For full collection, run with: sudo $0"
        echo ""
    fi
}

setup() {
    print_header "Setting up output directories..."
    mkdir -p "$OUTPUT_DIR" "$RAW_DIR"
    {
        echo "Ubuntu System Log Report"
        echo "Generated: $(date)"
        echo "Hostname:  $(hostname)"
        echo "User:      $(whoami)"
        echo "Kernel:    $(uname -r)"
        echo "Uptime:    $(uptime -p 2>/dev/null || uptime)"
    } > "$REPORT_FILE"
    separator
    print_success "Output directory: ${OUTPUT_DIR}"
}

# --- Collection Functions ---
collect_system_info() {
    section_header "SYSTEM INFORMATION"
    {
        echo "--- OS Release ---"
        cat /etc/os-release 2>/dev/null || echo "N/A"
        echo ""
        echo "--- CPU Info ---"
        lscpu 2>/dev/null | grep -E "Model name|CPU\(s\)|Thread|Core|Socket|MHz" || echo "N/A"
        echo ""
        echo "--- Memory ---"
        free -h 2>/dev/null || echo "N/A"
        echo ""
        echo "--- Disk Usage ---"
        df -h --total 2>/dev/null | grep -E "Filesystem|/dev/|total" || echo "N/A"
        echo ""
        echo "--- Network Interfaces ---"
        ip -br addr 2>/dev/null || ifconfig 2>/dev/null || echo "N/A"
    } >> "$REPORT_FILE"
}

collect_syslog() {
    section_header "SYSLOG (Recent Entries)"
    if [[ -f /var/log/syslog ]]; then
        tail -n "$MAX_LINES" /var/log/syslog > "${RAW_DIR}/syslog.log" 2>/dev/null || true
        echo "Last ${MAX_LINES} entries (parsed):" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        tail -n "$MAX_LINES" /var/log/syslog 2>/dev/null | while IFS= read -r line; do
            ts=$(echo "$line" | awk '{print $1, $2, $3}')
            host=$(echo "$line" | awk '{print $4}')
            rest=$(echo "$line" | cut -d' ' -f5-)
            service=$(echo "$rest" | cut -d':' -f1 | sed 's/\[.*//')
            message=$(echo "$rest" | cut -d':' -f2-)
            printf "  %-16s | %-12s | %-20s | %s\n" "$ts" "$host" "$service" "$message"
        done >> "$REPORT_FILE" 2>/dev/null || true
    else
        echo "  /var/log/syslog not found" >> "$REPORT_FILE"
        if command -v journalctl &>/dev/null; then
            journalctl --since "${DAYS_BACK} days ago" --no-pager -o short-iso 2>/dev/null \
                | tail -n "$MAX_LINES" >> "$REPORT_FILE" || true
        fi
    fi
}

collect_auth_log() {
    section_header "AUTHENTICATION LOG (Login Attempts & sudo Usage)"
    local auth_file="/var/log/auth.log"
    if [[ -f "$auth_file" ]]; then
        tail -n "$MAX_LINES" "$auth_file" > "${RAW_DIR}/auth.log" 2>/dev/null || true

        echo "--- Successful Logins ---" >> "$REPORT_FILE"
        grep -i "session opened\|accepted" "$auth_file" 2>/dev/null | tail -n 50 \
            | awk '{
                ts=$1" "$2" "$3; user="";
                for(i=1;i<=NF;i++){ if($i=="for" && $(i+1)=="user"){ user=$(i+2); break } if($i=="for"){ user=$(i+1); break } }
                gsub(/[^a-zA-Z0-9_.-]/, "", user);
                printf "  %-16s | User: %-15s | %s\n", ts, user, $0
            }' >> "$REPORT_FILE" 2>/dev/null || echo "  No successful logins found" >> "$REPORT_FILE"

        echo "" >> "$REPORT_FILE"
        echo "--- Failed Login Attempts ---" >> "$REPORT_FILE"
        grep -i "failed\|invalid\|error" "$auth_file" 2>/dev/null | tail -n 50 \
            | awk '{ ts=$1" "$2" "$3; printf "  %-16s | %s\n", ts, $0 }' >> "$REPORT_FILE" 2>/dev/null \
            || echo "  No failed logins found" >> "$REPORT_FILE"

        echo "" >> "$REPORT_FILE"
        echo "--- Sudo Commands ---" >> "$REPORT_FILE"
        grep -i "sudo" "$auth_file" 2>/dev/null | grep "COMMAND=" | tail -n 30 \
            | awk -F'COMMAND=' '{ split($1,a," "); ts=a[1]" "a[2]" "a[3]; printf "  %-16s | Command: %s\n", ts, $2 }' \
            >> "$REPORT_FILE" 2>/dev/null || echo "  No sudo commands found" >> "$REPORT_FILE"
    else
        echo "  /var/log/auth.log not found" >> "$REPORT_FILE"
        if command -v journalctl &>/dev/null; then
            echo "" >> "$REPORT_FILE"
            echo "--- Auth via journalctl ---" >> "$REPORT_FILE"
            journalctl _COMM=sshd --since "${DAYS_BACK} days ago" --no-pager -o short-iso 2>/dev/null \
                | tail -n "$MAX_LINES" >> "$REPORT_FILE" || true
        fi
    fi
}

collect_kernel_log() {
    section_header "KERNEL LOG (dmesg)"
    {
        echo "--- Recent Kernel Messages ---"
        echo ""
        dmesg --time-format=iso 2>/dev/null | tail -n "$MAX_LINES" | while IFS= read -r line; do
            severity="INFO"
            if echo "$line" | grep -qi "error\|fail\|critical\|panic"; then severity="ERROR"
            elif echo "$line" | grep -qi "warn"; then severity="WARN "; fi
            printf "  [%-5s] %s\n" "$severity" "$line"
        done || echo "  Could not read dmesg (try running as root)"
        echo ""
        echo "--- Kernel Errors Summary ---"
        echo ""
        dmesg 2>/dev/null | grep -ci "error\|fail" | xargs -I{} echo "  Total error/fail messages: {}" || true
        dmesg 2>/dev/null | grep -ci "warn" | xargs -I{} echo "  Total warning messages: {}" || true
    } >> "$REPORT_FILE"
    dmesg > "${RAW_DIR}/dmesg.log" 2>/dev/null || true
}

collect_journal_errors() {
    section_header "SYSTEMD JOURNAL - ERRORS & CRITICAL (Last ${DAYS_BACK} Days)"
    if command -v journalctl &>/dev/null; then
        {
            echo "--- Priority: Emergency, Alert, Critical, Error ---"
            echo ""
            journalctl -p err --since "${DAYS_BACK} days ago" --no-pager -o short-iso 2>/dev/null \
                | tail -n "$MAX_LINES" | while IFS= read -r line; do echo "  $line"; done \
                || echo "  No errors found in the last ${DAYS_BACK} days"
        } >> "$REPORT_FILE"
        journalctl -p err --since "${DAYS_BACK} days ago" --no-pager > "${RAW_DIR}/journal_errors.log" 2>/dev/null || true
    else
        echo "  journalctl not available" >> "$REPORT_FILE"
    fi
}

collect_service_status() {
    section_header "FAILED SYSTEMD SERVICES"
    if command -v systemctl &>/dev/null; then
        {
            echo "--- Currently Failed Units ---"
            echo ""
            failed=$(systemctl --failed --no-legend 2>/dev/null || true)
            if [[ -z "$failed" ]]; then echo "  No failed services"
            else echo "$failed" | while IFS= read -r line; do echo "  x $line"; done; fi
            echo ""
            echo "--- Top 20 Services by Memory Usage ---"
            echo ""
            systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}' \
                | while read -r svc; do
                    mem=$(systemctl show "$svc" --property=MemoryCurrent 2>/dev/null | cut -d= -f2)
                    if [[ "$mem" != "[not set]" && -n "$mem" && "$mem" != "infinity" ]]; then
                        mem_mb=$((mem / 1024 / 1024))
                        printf "  %-45s %6s MB\n" "$svc" "$mem_mb"
                    fi
                done 2>/dev/null | sort -t' ' -k2 -rn | head -20
        } >> "$REPORT_FILE"
    else
        echo "  systemctl not available" >> "$REPORT_FILE"
    fi
}

collect_package_log() {
    section_header "APT PACKAGE HISTORY (Recent Activity)"
    if [[ -f /var/log/apt/history.log ]]; then
        {
            echo "--- Recent Package Operations ---"
            echo ""
            tail -n 200 /var/log/apt/history.log 2>/dev/null \
                | grep -E "Start-Date|Commandline|Install|Upgrade|Remove|End-Date" | sed 's/^/  /' \
                || echo "  No recent apt activity"
        } >> "$REPORT_FILE"
        cp /var/log/apt/history.log "${RAW_DIR}/apt_history.log" 2>/dev/null || true
    else
        echo "  /var/log/apt/history.log not found" >> "$REPORT_FILE"
    fi
}

collect_boot_log() {
    section_header "BOOT LOG (Last 3 Boots)"
    if command -v journalctl &>/dev/null; then
        {
            echo "--- Boot Times ---"; echo ""
            journalctl --list-boots 2>/dev/null | tail -5 | sed 's/^/  /' || echo "  N/A"
            echo ""; echo "--- Current Boot Errors ---"; echo ""
            journalctl -b -p err --no-pager -o short-iso 2>/dev/null | tail -n 100 | sed 's/^/  /' \
                || echo "  No boot errors found"
        } >> "$REPORT_FILE"
    else
        echo "  journalctl not available" >> "$REPORT_FILE"
    fi
}

collect_cron_log() {
    section_header "CRON JOB LOG"
    {
        echo "--- Recent Cron Activity ---"; echo ""
        if [[ -f /var/log/syslog ]]; then
            grep -i "cron" /var/log/syslog 2>/dev/null | tail -n 50 \
                | awk '{ ts=$1" "$2" "$3; $1=$2=$3=$4=""; printf "  %-16s | %s\n", ts, $0 }' \
                || echo "  No cron entries found"
        elif command -v journalctl &>/dev/null; then
            journalctl -u cron --since "${DAYS_BACK} days ago" --no-pager -o short-iso 2>/dev/null \
                | tail -n 50 | sed 's/^/  /' || echo "  No cron entries found"
        else
            echo "  Cannot find cron logs"
        fi
        echo ""; echo "--- Active Crontab (Current User) ---"; echo ""
        crontab -l 2>/dev/null | sed 's/^/  /' || echo "  No crontab for current user"
    } >> "$REPORT_FILE"
}

collect_network_log() {
    section_header "NETWORK STATUS & LOGS"
    {
        echo "--- Active Connections (Top 20) ---"; echo ""
        ss -tunap 2>/dev/null | head -21 | sed 's/^/  /' \
            || netstat -tunap 2>/dev/null | head -21 | sed 's/^/  /' || echo "  N/A"
        echo ""; echo "--- Listening Ports ---"; echo ""
        ss -tlnp 2>/dev/null | sed 's/^/  /' || netstat -tlnp 2>/dev/null | sed 's/^/  /' || echo "  N/A"
        echo ""; echo "--- Firewall Rules (UFW) ---"; echo ""
        if command -v ufw &>/dev/null; then
            ufw status verbose 2>/dev/null | sed 's/^/  /' || echo "  UFW not active or insufficient permissions"
        else
            iptables -L -n 2>/dev/null | head -30 | sed 's/^/  /' || echo "  Cannot read firewall rules"
        fi
        echo ""; echo "--- DNS Configuration ---"; echo ""
        grep -v "^#" /etc/resolv.conf 2>/dev/null | sed 's/^/  /' || echo "  N/A"
    } >> "$REPORT_FILE"
}

# Compute the health-check metrics once, reused by text summary and JSON.
compute_metrics() {
    M_FAILED=$(systemctl --failed --no-legend 2>/dev/null | wc -l | tr -d ' ')
    [[ "$M_FAILED" =~ ^[0-9]+$ ]] || M_FAILED=0
    M_HIGH_DISK=$(df -h 2>/dev/null | awk 'NR>1 && (+$5) > 85 {print $6" ("$5")"}' | paste -sd ',' - || true)
    M_MEM=$(free 2>/dev/null | awk '/Mem:/ {printf "%.0f", $3/$2*100}')
    [[ -n "$M_MEM" ]] || M_MEM=0
    M_ERRORS=$(journalctl -p err --since "${DAYS_BACK} days ago" --no-pager 2>/dev/null | wc -l | tr -d ' ')
    [[ "$M_ERRORS" =~ ^[0-9]+$ ]] || M_ERRORS=0
    if [[ -f /var/log/auth.log ]]; then
        M_SSH=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || true)
    else
        M_SSH=0
    fi
    [[ "$M_SSH" =~ ^[0-9]+$ ]] || M_SSH=0
}

generate_summary() {
    section_header "EXECUTIVE SUMMARY"
    {
        echo "Quick Health Check:"; echo ""
        if [[ "$M_FAILED" -eq 0 ]]; then echo "  [ok] Services:      All services running normally"
        else echo "  [!] Services:      ${M_FAILED} failed service(s) detected"; fi
        if [[ -z "$M_HIGH_DISK" ]]; then echo "  [ok] Disk Usage:    All filesystems under 85%"
        else echo "  [!] Disk Usage:    High usage on: ${M_HIGH_DISK}"; fi
        if [[ "$M_MEM" -lt 85 ]]; then echo "  [ok] Memory:        ${M_MEM}% used"
        else echo "  [!] Memory:        ${M_MEM}% used (HIGH)"; fi
        echo "  [i] Errors:        ${M_ERRORS} error-level journal entries in last ${DAYS_BACK} days"
        echo "  [i] SSH Failures:  ${M_SSH} failed password attempts in auth.log"
        echo ""
        echo "Report contents: ${OUTPUT_DIR}/"
        echo "  - system_report.txt   (human-readable report)"
        echo "  - raw_logs/           (unmodified log copies)"
    } >> "$REPORT_FILE"
}

generate_json() {
    cat > "$JSON_FILE" <<EOF
{
  "hostname": "$(hostname)",
  "collected_at": "$(date -Iseconds)",
  "kernel": "$(uname -r)",
  "days_back": ${DAYS_BACK},
  "summary": {
    "failed_services": ${M_FAILED},
    "high_disk_filesystems": "${M_HIGH_DISK}",
    "memory_used_percent": ${M_MEM},
    "journal_errors": ${M_ERRORS},
    "ssh_failed_passwords": ${M_SSH}
  }
}
EOF
}

# --- Main ---
main() {
    echo ""
    echo -e "${CYAN}=== Ubuntu Log Collector & Parser v${VERSION} ===${NC}"
    echo ""

    check_privileges
    setup

    echo ""
    print_header "Starting log collection..."
    echo ""; echo ""; echo ""

    draw_progress_bar 0 "$TOTAL_STEPS" "Starting..."

    collect_system_info    >/dev/null 2>&1 || true; advance_step
    collect_syslog         >/dev/null 2>&1 || true; advance_step
    collect_auth_log       >/dev/null 2>&1 || true; advance_step
    collect_kernel_log     >/dev/null 2>&1 || true; advance_step
    collect_journal_errors >/dev/null 2>&1 || true; advance_step
    collect_service_status >/dev/null 2>&1 || true; advance_step
    collect_package_log    >/dev/null 2>&1 || true; advance_step
    collect_boot_log       >/dev/null 2>&1 || true; advance_step
    collect_cron_log       >/dev/null 2>&1 || true; advance_step
    collect_network_log    >/dev/null 2>&1 || true; advance_step
    compute_metrics        >/dev/null 2>&1 || true
    generate_summary       >/dev/null 2>&1 || true; advance_step
    if [[ "$JSON_OUTPUT" == true ]]; then generate_json >/dev/null 2>&1 || true; fi

    separator
    echo "END OF REPORT" >> "$REPORT_FILE"

    tar -czf "${OUTPUT_DIR}.tar.gz" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" 2>/dev/null || true
    advance_step

    echo -ne "\033[3A"
    echo -e "  $(printf '#%.0s' $(seq 1 "$BAR_WIDTH"))  ${BOLD}100%${NC}  (${TOTAL_STEPS}/${TOTAL_STEPS})    "
    echo -e "  ${GREEN}All steps completed${NC}                                "
    echo -e "  ${DIM}Total time: $(format_elapsed)${NC}                          "

    echo ""
    echo -e "${GREEN}=== Collection Complete ===${NC}"
    echo ""
    echo -e "  Report:   ${CYAN}${REPORT_FILE}${NC}"
    echo -e "  Raw logs: ${CYAN}${RAW_DIR}/${NC}"
    [[ "$JSON_OUTPUT" == true ]] && echo -e "  JSON:     ${CYAN}${JSON_FILE}${NC}"
    echo -e "  Archive:  ${CYAN}${OUTPUT_DIR}.tar.gz${NC}"
    echo ""
    echo -e "  View report: ${YELLOW}less ${REPORT_FILE}${NC}"
    echo ""
}

main "$@"
