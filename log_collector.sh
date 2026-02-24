#!/usr/bin/env bash
# ============================================================================
# Ubuntu Log Collector & Parser
# Collects system logs and outputs a human-readable report
# ============================================================================

set -euo pipefail

# --- Configuration ---
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
OUTPUT_DIR="./log_report_${TIMESTAMP}"
REPORT_FILE="${OUTPUT_DIR}/system_report.txt"
RAW_DIR="${OUTPUT_DIR}/raw_logs"
MAX_LINES=600000          # Max recent lines to grab per log
DAYS_BACK=365            # How many days back to look for journal logs

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Helper Functions ---

print_header() {
    echo -e "${CYAN}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

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

# Check if running as root (needed for some logs)
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        print_warning "Not running as root. Some logs may be inaccessible."
        print_warning "For full collection, run with: sudo $0"
        echo ""
        SUDO_AVAILABLE=false
    else
        SUDO_AVAILABLE=true
    fi
}

# --- Setup ---

setup() {
    print_header "Setting up output directories..."
    mkdir -p "$OUTPUT_DIR" "$RAW_DIR"
    echo "Ubuntu System Log Report" > "$REPORT_FILE"
    echo "Generated: $(date)" >> "$REPORT_FILE"
    echo "Hostname:  $(hostname)" >> "$REPORT_FILE"
    echo "User:      $(whoami)" >> "$REPORT_FILE"
    echo "Kernel:    $(uname -r)" >> "$REPORT_FILE"
    echo "Uptime:    $(uptime -p 2>/dev/null || uptime)" >> "$REPORT_FILE"
    separator
    print_success "Output directory: ${OUTPUT_DIR}"
}

# --- Collection Functions ---

collect_system_info() {
    print_header "Collecting system information..."
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

    print_success "System information collected"
}

collect_syslog() {
    print_header "Collecting syslog..."
    section_header "SYSLOG (Recent Entries)"

    if [[ -f /var/log/syslog ]]; then
        # Copy raw log
        tail -n "$MAX_LINES" /var/log/syslog > "${RAW_DIR}/syslog.log" 2>/dev/null || true

        # Parse: extract timestamp, hostname, service, message
        echo "Last ${MAX_LINES} entries (parsed):" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        tail -n "$MAX_LINES" /var/log/syslog 2>/dev/null | while IFS= read -r line; do
            # Syslog format: Mon DD HH:MM:SS hostname service[pid]: message
            ts=$(echo "$line" | awk '{print $1, $2, $3}')
            host=$(echo "$line" | awk '{print $4}')
            rest=$(echo "$line" | cut -d' ' -f5-)
            service=$(echo "$rest" | cut -d':' -f1 | sed 's/\[.*//') 
            message=$(echo "$rest" | cut -d':' -f2-)

            printf "  %-16s | %-12s | %-20s | %s\n" "$ts" "$host" "$service" "$message"
        done >> "$REPORT_FILE" 2>/dev/null

        print_success "Syslog collected"
    else
        echo "  /var/log/syslog not found" >> "$REPORT_FILE"
        print_warning "Syslog not found, trying journalctl..."

        # Fallback to journalctl
        if command -v journalctl &>/dev/null; then
            journalctl --since "${DAYS_BACK} days ago" --no-pager -o short-iso 2>/dev/null \
                | tail -n "$MAX_LINES" >> "$REPORT_FILE" || true
            print_success "Journal log collected as fallback"
        fi
    fi
}

collect_auth_log() {
    print_header "Collecting authentication logs..."
    section_header "AUTHENTICATION LOG (Login Attempts & sudo Usage)"

    local auth_file="/var/log/auth.log"
    if [[ -f "$auth_file" ]]; then
        tail -n "$MAX_LINES" "$auth_file" > "${RAW_DIR}/auth.log" 2>/dev/null || true

        # Successful logins
        echo "--- Successful Logins ---" >> "$REPORT_FILE"
        grep -i "session opened\|accepted" "$auth_file" 2>/dev/null \
            | tail -n 50 \
            | awk '{
                ts=$1" "$2" "$3;
                user="";
                for(i=1;i<=NF;i++) {
                    if($i=="for" && $(i+1)=="user") { user=$(i+2); break }
                    if($i=="for") { user=$(i+1); break }
                }
                gsub(/[^a-zA-Z0-9_.-]/, "", user);
                printf "  %-16s | User: %-15s | %s\n", ts, user, $0
            }' >> "$REPORT_FILE" 2>/dev/null || echo "  No successful logins found" >> "$REPORT_FILE"

        echo "" >> "$REPORT_FILE"

        # Failed logins
        echo "--- Failed Login Attempts ---" >> "$REPORT_FILE"
        grep -i "failed\|invalid\|error" "$auth_file" 2>/dev/null \
            | tail -n 50 \
            | awk '{
                ts=$1" "$2" "$3;
                printf "  %-16s | %s\n", ts, $0
            }' >> "$REPORT_FILE" 2>/dev/null || echo "  No failed logins found" >> "$REPORT_FILE"

        echo "" >> "$REPORT_FILE"

        # Sudo usage
        echo "--- Sudo Commands ---" >> "$REPORT_FILE"
        grep -i "sudo" "$auth_file" 2>/dev/null \
            | grep "COMMAND=" \
            | tail -n 30 \
            | awk -F'COMMAND=' '{
                split($1, a, " ");
                ts=a[1]" "a[2]" "a[3];
                cmd=$2;
                printf "  %-16s | Command: %s\n", ts, cmd
            }' >> "$REPORT_FILE" 2>/dev/null || echo "  No sudo commands found" >> "$REPORT_FILE"

        print_success "Auth log collected"
    else
        echo "  /var/log/auth.log not found" >> "$REPORT_FILE"
        print_warning "Auth log not found"

        if command -v journalctl &>/dev/null; then
            echo "" >> "$REPORT_FILE"
            echo "--- Auth via journalctl ---" >> "$REPORT_FILE"
            journalctl _COMM=sshd --since "${DAYS_BACK} days ago" --no-pager -o short-iso 2>/dev/null \
                | tail -n "$MAX_LINES" >> "$REPORT_FILE" || true
        fi
    fi
}

collect_kernel_log() {
    print_header "Collecting kernel logs..."
    section_header "KERNEL LOG (dmesg)"

    {
        echo "--- Recent Kernel Messages ---"
        echo ""
        dmesg --time-format=iso 2>/dev/null \
            | tail -n "$MAX_LINES" \
            | while IFS= read -r line; do
                # Classify severity
                severity="INFO"
                if echo "$line" | grep -qi "error\|fail\|critical\|panic"; then
                    severity="ERROR"
                elif echo "$line" | grep -qi "warn"; then
                    severity="WARN "
                fi
                printf "  [%-5s] %s\n" "$severity" "$line"
            done || echo "  Could not read dmesg (try running as root)"

        echo ""
        echo "--- Kernel Errors Summary ---"
        echo ""
        dmesg 2>/dev/null | grep -ci "error\|fail" | xargs -I{} echo "  Total error/fail messages: {}" || true
        dmesg 2>/dev/null | grep -ci "warn" | xargs -I{} echo "  Total warning messages: {}" || true
    } >> "$REPORT_FILE"

    dmesg > "${RAW_DIR}/dmesg.log" 2>/dev/null || true
    print_success "Kernel log collected"
}

collect_journal_errors() {
    print_header "Collecting systemd journal errors..."
    section_header "SYSTEMD JOURNAL - ERRORS & CRITICAL (Last ${DAYS_BACK} Days)"

    if command -v journalctl &>/dev/null; then
        {
            echo "--- Priority: Emergency, Alert, Critical, Error ---"
            echo ""
            journalctl -p err --since "${DAYS_BACK} days ago" --no-pager -o short-iso 2>/dev/null \
                | tail -n "$MAX_LINES" \
                | while IFS= read -r line; do
                    echo "  $line"
                done || echo "  No errors found in the last ${DAYS_BACK} days"
        } >> "$REPORT_FILE"

        journalctl -p err --since "${DAYS_BACK} days ago" --no-pager \
            > "${RAW_DIR}/journal_errors.log" 2>/dev/null || true

        print_success "Journal errors collected"
    else
        echo "  journalctl not available" >> "$REPORT_FILE"
        print_warning "journalctl not available"
    fi
}

collect_service_status() {
    print_header "Collecting service status..."
    section_header "FAILED SYSTEMD SERVICES"

    if command -v systemctl &>/dev/null; then
        {
            echo "--- Currently Failed Units ---"
            echo ""
            failed=$(systemctl --failed --no-legend 2>/dev/null)
            if [[ -z "$failed" ]]; then
                echo "  ✓ No failed services"
            else
                echo "$failed" | while IFS= read -r line; do
                    echo "  ✗ $line"
                done
            fi

            echo ""
            echo "--- Top 20 Services by Memory Usage ---"
            echo ""
            systemctl list-units --type=service --state=running --no-legend 2>/dev/null \
                | awk '{print $1}' \
                | while read -r svc; do
                    mem=$(systemctl show "$svc" --property=MemoryCurrent 2>/dev/null | cut -d= -f2)
                    if [[ "$mem" != "[not set]" && "$mem" != "" && "$mem" != "infinity" ]]; then
                        mem_mb=$((mem / 1024 / 1024))
                        printf "  %-45s %6s MB\n" "$svc" "$mem_mb"
                    fi
                done 2>/dev/null | sort -t' ' -k2 -rn | head -20
        } >> "$REPORT_FILE"

        print_success "Service status collected"
    else
        echo "  systemctl not available" >> "$REPORT_FILE"
        print_warning "systemctl not available"
    fi
}

collect_package_log() {
    print_header "Collecting package manager logs..."
    section_header "APT PACKAGE HISTORY (Recent Activity)"

    if [[ -f /var/log/apt/history.log ]]; then
        {
            echo "--- Recent Package Operations ---"
            echo ""
            tail -n 200 /var/log/apt/history.log 2>/dev/null \
                | grep -E "Start-Date|Commandline|Install|Upgrade|Remove|End-Date" \
                | sed 's/^/  /' || echo "  No recent apt activity"
        } >> "$REPORT_FILE"

        cp /var/log/apt/history.log "${RAW_DIR}/apt_history.log" 2>/dev/null || true
        print_success "APT log collected"
    else
        echo "  /var/log/apt/history.log not found" >> "$REPORT_FILE"
        print_warning "APT history log not found"
    fi
}

collect_boot_log() {
    print_header "Collecting boot logs..."
    section_header "BOOT LOG (Last 3 Boots)"

    if command -v journalctl &>/dev/null; then
        {
            echo "--- Boot Times ---"
            echo ""
            journalctl --list-boots 2>/dev/null | tail -5 | sed 's/^/  /' || echo "  N/A"
            echo ""
            echo "--- Current Boot Errors ---"
            echo ""
            journalctl -b -p err --no-pager -o short-iso 2>/dev/null \
                | tail -n 100 \
                | sed 's/^/  /' || echo "  No boot errors found"
        } >> "$REPORT_FILE"

        print_success "Boot log collected"
    else
        echo "  journalctl not available" >> "$REPORT_FILE"
        print_warning "journalctl not available"
    fi
}

collect_cron_log() {
    print_header "Collecting cron logs..."
    section_header "CRON JOB LOG"

    {
        echo "--- Recent Cron Activity ---"
        echo ""
        if [[ -f /var/log/syslog ]]; then
            grep -i "cron" /var/log/syslog 2>/dev/null \
                | tail -n 50 \
                | awk '{
                    ts=$1" "$2" "$3;
                    $1=$2=$3=$4="";
                    printf "  %-16s | %s\n", ts, $0
                }' || echo "  No cron entries found"
        elif command -v journalctl &>/dev/null; then
            journalctl -u cron --since "${DAYS_BACK} days ago" --no-pager -o short-iso 2>/dev/null \
                | tail -n 50 \
                | sed 's/^/  /' || echo "  No cron entries found"
        else
            echo "  Cannot find cron logs"
        fi

        echo ""
        echo "--- Active Crontab (Current User) ---"
        echo ""
        crontab -l 2>/dev/null | sed 's/^/  /' || echo "  No crontab for current user"
    } >> "$REPORT_FILE"

    print_success "Cron log collected"
}

collect_network_log() {
    print_header "Collecting network information..."
    section_header "NETWORK STATUS & LOGS"

    {
        echo "--- Active Connections (Top 20) ---"
        echo ""
        ss -tunap 2>/dev/null | head -21 | sed 's/^/  /' || \
            netstat -tunap 2>/dev/null | head -21 | sed 's/^/  /' || echo "  N/A"

        echo ""
        echo "--- Listening Ports ---"
        echo ""
        ss -tlnp 2>/dev/null | sed 's/^/  /' || \
            netstat -tlnp 2>/dev/null | sed 's/^/  /' || echo "  N/A"

        echo ""
        echo "--- Firewall Rules (UFW) ---"
        echo ""
        if command -v ufw &>/dev/null; then
            ufw status verbose 2>/dev/null | sed 's/^/  /' || echo "  UFW not active or insufficient permissions"
        else
            iptables -L -n 2>/dev/null | head -30 | sed 's/^/  /' || echo "  Cannot read firewall rules"
        fi

        echo ""
        echo "--- DNS Configuration ---"
        echo ""
        cat /etc/resolv.conf 2>/dev/null | grep -v "^#" | sed 's/^/  /' || echo "  N/A"
    } >> "$REPORT_FILE"

    print_success "Network info collected"
}

generate_summary() {
    print_header "Generating summary..."

    # Insert summary at the top area of the report
    section_header "EXECUTIVE SUMMARY"

    {
        echo "Quick Health Check:"
        echo ""

        # Failed services
        failed_count=$(systemctl --failed --no-legend 2>/dev/null | wc -l || echo "?")
        if [[ "$failed_count" -eq 0 ]]; then
            echo "  ✓ Services:      All services running normally"
        else
            echo "  ✗ Services:      ${failed_count} failed service(s) detected"
        fi

        # Disk usage
        high_disk=$(df -h 2>/dev/null | awk 'NR>1 && +$5 > 85 {print $6 " (" $5 ")"}')
        if [[ -z "$high_disk" ]]; then
            echo "  ✓ Disk Usage:    All filesystems under 85%"
        else
            echo "  ✗ Disk Usage:    High usage on: $high_disk"
        fi

        # Memory
        mem_pct=$(free 2>/dev/null | awk '/Mem:/ {printf "%.0f", $3/$2*100}')
        if [[ -n "$mem_pct" ]]; then
            if [[ "$mem_pct" -lt 85 ]]; then
                echo "  ✓ Memory:        ${mem_pct}% used"
            else
                echo "  ✗ Memory:        ${mem_pct}% used (HIGH)"
            fi
        fi

        # Recent errors
        err_count=$(journalctl -p err --since "${DAYS_BACK} days ago" --no-pager 2>/dev/null | wc -l || echo "?")
        echo "  ℹ Errors:        ${err_count} error-level journal entries in last ${DAYS_BACK} days"

        # Failed SSH
        if [[ -f /var/log/auth.log ]]; then
            fail_ssh=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo "0")
            echo "  ℹ SSH Failures:  ${fail_ssh} failed password attempts in auth.log"
        fi

        echo ""
        echo "Report contents: ${OUTPUT_DIR}/"
        echo "  - system_report.txt   (this file - human-readable report)"
        echo "  - raw_logs/           (unmodified log copies)"
    } >> "$REPORT_FILE"

    print_success "Summary generated"
}

# --- Main ---

main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     Ubuntu Log Collector & Parser v1.0       ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
    echo ""

    check_privileges
    setup

    echo ""
    print_header "Starting log collection..."
    echo ""

    collect_system_info
    collect_syslog
    collect_auth_log
    collect_kernel_log
    collect_journal_errors
    collect_service_status
    collect_package_log
    collect_boot_log
    collect_cron_log
    collect_network_log
    generate_summary

    echo ""
    separator >> "$REPORT_FILE"
    echo "END OF REPORT" >> "$REPORT_FILE"

    # Compress output
    print_header "Compressing report..."
    tar -czf "${OUTPUT_DIR}.tar.gz" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" 2>/dev/null
    print_success "Compressed archive: ${OUTPUT_DIR}.tar.gz"

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          Collection Complete!                ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Report:   ${CYAN}${REPORT_FILE}${NC}"
    echo -e "  Raw logs: ${CYAN}${RAW_DIR}/${NC}"
    echo -e "  Archive:  ${CYAN}${OUTPUT_DIR}.tar.gz${NC}"
    echo ""
    echo -e "  View report: ${YELLOW}less ${REPORT_FILE}${NC}"
    echo ""
}

main "$@"
