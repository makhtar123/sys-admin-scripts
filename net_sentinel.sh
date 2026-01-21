#!/bin/bash

# STRICT MODE
set -euo pipefail

# --- CONFIGURATION & DEFAULTS ---
# ANSI Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TARGET=""
TARGET_IP=""
PORTS_STRING="80,443,22" 
OUTPUT_FILE=""

# --- FUNCTIONS ---
check_dependencies() {
    local dependencies=("nc" "dig" "ping" "ip" "openssl")
    for cmd in "${dependencies[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            echo -e "${RED}Error: Required command '$cmd' is not installed.${NC}"
            echo "Please install it via: sudo apt install dnsutils netcat openssl"
            exit 1
        fi
    done
}

initialize() {
    check_dependencies
    # 1. Check if Target is provided
    if [[ -z "$TARGET" ]]; then 
        echo -e "${RED}Error: Target (-t) is required.${NC}"
        echo "Usage: $0 -t <domain> [-p 80,443]"
        exit 1
    fi

    echo -e "${YELLOW}Initializing... resolving target: $TARGET ${NC}"

    # 2. Resolve IP (Needed for Ports and Ping)
    # Check if TARGET is already an IP 
    if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        TARGET_IP="$TARGET"
        echo "Target is an IP. Skipping DNS resolution."
    else
        # Try to resolve
        TARGET_IP=$(dig +short "$TARGET" | head -n 1)
        
        # Guard Clause: If resolution failed
        if [[ -z "$TARGET_IP" ]]; then
            echo -e "${RED}Error: Could not resolve domain '$TARGET'.${NC}"
            echo "Please check for typos or internet connectivity."
            exit 1
        fi
        echo "Target resolved to: $TARGET_IP"
    fi
}

connection_troubleshoot(){
    echo -e "\n--- Stage 1: Local Connectivity ---"
    
    # Dynamic Interface Detection
    local default_interface=$(ip route | grep "default" | awk -F"dev" '{print $2}' | awk '{print $1}' | head -n 1)
    
    # Check Link State
    local link_status=$(ip link show "$default_interface" 2>/dev/null | awk -F"state" '{print $2}' | awk '{print $1}')
    
    if [[ "$link_status" == "UP" ]]; then
        echo -e "${GREEN}✓ Interface $default_interface is physically UP ${NC}"
    else
        echo -e "${RED}X Interface $default_interface is DOWN or UNKNOWN ${NC}"
        # We exit here because if the cable is unplugged, nothing else will work.
        exit 1
    fi

    # Check IP
    local ip_addr=$(ip addr show "$default_interface" | grep -w "inet" | awk '{print $2}' | cut -d/ -f1)
    if [[ -z "$ip_addr" ]]; then
        echo -e "${RED}X Error: No IP address configured on interface ${NC}"
        exit 1
    fi
    
    # Check Gateway
    local default_gateway=$(ip route | grep "default" | awk -F"via" '{print $2}' | awk '{print $1}' | head -n 1)
    
    # If grep finds nothing, default to 100.
    local packet_loss=$( (ping -c 3 -W 2 -q "$default_gateway" || true) | grep -oP '\d+(?=% packet loss)' || echo 100 | head -n 1)
    
    if (( packet_loss == 0 )); then
        echo -e "${GREEN}✓ Default Gateway is reachable (0% loss)${NC}"
    elif (( packet_loss > 0 && packet_loss < 100 )); then
        echo -e "${YELLOW}? Unstable connection to Gateway: ($packet_loss% loss) ${NC}"
    else
        echo -e "${YELLOW}? Gateway silent, attempting upstream verification...${NC}"
        
        # If this fails, do NOT exit. We warn and proceed.
        if ping -c 3 -W 2 8.8.8.8 > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Internet reachable via ICMP. Diagnosis: Gateway is configured to drop ICMP ${NC}"
        else
            echo -e "${YELLOW}! Internet unreachable via ICMP.${NC}"
            echo -e "${YELLOW}  (This might be a firewall blocking Ping. Proceeding to DNS/TCP tests...)${NC}"
        fi
    fi
}   

dns_troubleshoot() {
    echo -e "\n--- Stage 2: DNS Health ---"
    
    # 1. Check Google (Sanity Check for System DNS)
    if [[ -z "$(dig +short google.com)" ]]; then
        # Local failed. Now test Upstream.
        if [[ -z "$(dig @8.8.8.8 +short google.com)" ]]; then
            echo -e "${RED}X Critical DNS Blockage (UDP 53). ${NC}"
            exit 1
        else
            echo -e "${YELLOW}! Local DNS Misconfigured (Upstream works). Check /etc/resolv.conf ${NC}"
        fi
    else
        echo -e "${GREEN}✓ System DNS is healthy.${NC}"
    fi

    # 2. Target Connectivity (Using the IP we found in initialize)
    echo "Testing connectivity to Target ($TARGET_IP)..."
    if ping -c 3 -W 1 "$TARGET_IP" > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Target is reachable via ICMP ${NC}"
        else
            echo -e "${RED}X Target is unreachable via ICMP (Might be firewalled) ${NC}"
            # We don't exit here, because Port Scan might still work
    fi
}

port_scanner() {
    echo -e "\n--- Stage 3: Port Scanning ---"
    echo "Scanning $TARGET_IP..."
    
    # Convert string "80,443" to array
    IFS=',' read -r -a PORT_LIST <<< "$PORTS_STRING"
    
    for port in "${PORT_LIST[@]}"; do
        # using nc -z (scan) -v (verbose) -w 1 (wait 1 sec)
        # Redirect stderr to stdout so we can grep it, or just rely on exit code
        if nc -z -w 1 "$TARGET_IP" "$port" 2>/dev/null; then
             echo -e "${GREEN}✓ Port $port ... OPEN${NC}"
        else
             echo -e "${RED}X Port $port ... CLOSED/FILTERED${NC}"
        fi
    done
}

ssl_validator() {
    echo -e "\n--- Stage 4: SSL Validator ---"
    
    # 1. Check if 443 is open first (Don't try SSL on a closed port)
    if ! nc -z -w 1 "$TARGET_IP" 443 2>/dev/null; then
        echo -e "${YELLOW}! Port 443 is closed. Skipping SSL check.${NC}"
        return
    fi

    echo "Checking SSL Certificate for $TARGET..."

    # 2. Fetch the Expiration Date
    # We use $TARGET (Domain) here, NOT the IP, for SNI support.
    local end_date_str=$(echo | openssl s_client -servername "$TARGET" -connect "$TARGET":443 2>/dev/null | openssl x509 -noout -enddate)

    # 3. Validation: Did we get a certificate?
    if [[ -z "$end_date_str" ]]; then
        echo -e "${RED}X Error: Could not retrieve certificate data.${NC}"
        return
    fi

    # Clean the output: "notAfter=Nov 13..." -> "Nov 13..."
    local clean_date=${end_date_str#*=}

    # 4. Convert to Epoch (Numbers)
    # Note: 'date -d' is GNU Linux standard. macOS requires 'date -j -f ...'
    local exp_epoch=$(date -d "$clean_date" +%s)
    local current_epoch=$(date +%s)

    # 5. Calculate Days Remaining
    local seconds_left=$(( exp_epoch - current_epoch ))
    local days_left=$(( seconds_left / 86400 ))

    # 6. The Verdict
    if (( days_left < 0 )); then
        echo -e "${RED}X Certificate EXPIRED $days_left days ago! ($clean_date)${NC}"
    elif (( days_left < 30 )); then
        echo -e "${YELLOW}! Warning: Certificate expires soon ($days_left days left).${NC}"
    else
        echo -e "${GREEN}✓ SSL Certificate is valid. Expires in $days_left days ($clean_date).${NC}"
    fi
}

# --- MAIN EXECUTION ---

# 1. Parse Arguments
while getopts "t:p:o:h" opt; do
  case ${opt} in
    t) TARGET="$OPTARG" ;;
    p) PORTS_STRING="$OPTARG" ;;
    o) OUTPUT_FILE="$OPTARG" ;;
    h)
      echo "Usage: $0 -t <domain/IP> [-p 80,443] [-o filename]"
      exit 0
      ;;
    \?)
      echo "Invalid Option: -$OPTARG" 1>&2
      exit 1
      ;;
    :)
      echo "Invalid Option: -$OPTARG requires an argument" 1>&2
      exit 1
      ;;
  esac
done

# Shift arguments so $1 is the first function name
shift $((OPTIND -1))

# 2. Initialize (Verify Target exists before running tests)
main_execution() {
    initialize

    # 3. Handle Default Behavior (If no functions specified, run all)
    if [[ $# -eq 0 ]]; then
        echo "No specific tests requested. Running full suite..."
        set -- "local" "dns" "ports" "ssl"
    fi

    # 4. Dispatcher Loop
    for command in "$@"; do
        case $command in
            local) connection_troubleshoot ;;
            dns)   dns_troubleshoot ;;
            ports) port_scanner ;;  # MATCHED NAME to function
            ssl)   ssl_validator ;;
            *)
                echo "Error: Unknown command '$command'"
                exit 1
                ;;
        esac
    done
}

if [[ -n "$OUTPUT_FILE" ]]; then
    # Create/Overwirte the file and show output on screen
    echo "Logging output to: $OUTPUT_FILE"
    
    # We pass "$@" to ensure the 'ports' or 'dns' args get passed to the function
    main_execution "$@" 2>&1 | tee "$OUTPUT_FILE"
    
else
    # Standard execution (Screen only)
    main_execution "$@"
fi
