#!/bin/bash
set -uo pipefail

# ANSI Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color (Reset)

# checking for root
if [[ "$EUID" -ne 0 ]]; then
    echo "Please run as root" >&2
    echo "Try running: sudo $0" >&2
    exit 1
fi

audit_result () {
    if [[ "$1" == "FAIL" ]]; then
        echo -e "${RED}[WARNING] $2 ${NC}" # -e flag enables interpreation of \
    else
        echo -e "${GREEN}[OK] $2 ${NC}"
    fi
}

# '^' matches start of the line; '[[:space:]]' matches any whitespace character; and '*' matches the previous element 0 or more times
ROOT_FLAG=$(grep -i -E "^[[:space:]]*PermitRootLogin" /etc/ssh/sshd_config |  awk '{print tolower($2)}' | tail -n 1 || echo "not_found") 
PWD_AUTH=$(grep -i -E "^[[:space:]]*PasswordAuthentication" /etc/ssh/sshd_config |  awk '{print tolower($2)}' | tail -n 1 || echo "not_found") 
FIREWALL_FLAG=$(ufw status | grep "Status:" | awk '{print tolower($2)}')

# Find world-writable files starting from root (/).
# -xdev: Prevent scanning network mounts or special filesystems (stay on one disk).
# -type f: Look for files only (ignoring directories like /tmp).
# -perm -o=w: Check for files where "Others" have "Write" permission.
# 2>/dev/null: Discard permission denied errors.
WRITE_FLAG=$(find / -xdev -type f -perm -o=w 2>/dev/null | wc -l)

# Check for non-root users with UID 0
# Logic: Find users with UID 0 ($3 == 0) BUT exclude the specific user 'root' ($1 != "root")
UID0_ACCOUNTS=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
EMPTY_PWD=$(awk -F: '($2 == "" ) {print $1}' /etc/shadow)
IP_FORWARDING=$(sysctl net.ipv4.ip_forward | awk '{print $3}')
SUID_CHECK=$(find / -type f -perm -4000 2>/dev/null | wc -l)

[[ "$ROOT_FLAG" == "yes" ]] && audit_result "FAIL" "PermitRootLogin is set to YES" || audit_result "PASS" "PermitRootLogin is disabled"
[[ "$PWD_AUTH" == "yes" ]] && audit_result "FAIL" "PasswordAuthentication is set to YES" || audit_result "PASS" "PasswordAuthentication is disabled"
[[ "$FIREWALL_FLAG" == "inactive" ]] && audit_result "FAIL" "ufw firewall is set to inactive" || audit_result "PASS" "ufw firewall is active"
[[ "$WRITE_FLAG" -gt 0 ]] && audit_result "FAIL" "Found $WRITE_FLAG files writeable by other. Check with: find / -xdev -type f -perm -o=w" || audit_result "PASS" "Found no files writeable by other"
[[ -n "$UID0_ACCOUNTS" ]] && audit_result "FAIL" "Found non-root user(s) with UID 0: $UID0_ACCOUNTS" || audit_result "PASS" "No unauthorized UID 0 accounts found"
[[ -n "$EMPTY_PWD" ]] && audit_result "FAIL" "Found user(s) with empty passwords: $EMPTY_PWD" || audit_result "PASS" "Found no users with empty passwords"
[[ "$IP_FORWARDING" -eq 1 ]] && audit_result "FAIL" "IP Forwarding is enabled on machine" || audit_result "PASS" "IP Forwarding is disabled"
[[ "$SUID_CHECK" -gt 0 ]] && audit_result "FAIL" "Found $SUID_CHECK binaries. Check with: find / -type f -perm -4000 " || audit_result "PASS" "Found no SUID Binaries"

