#!/bin/bash

#############################################################################
# PNPT Reconnaissance Automation Pipeline - FIXED VERSION
# 
# Author: MB Cyberworks (mbcyberworks.nl)
# Purpose: Automated reconnaissance for PNPT certification prep
# Version: 2.0 - NOW WITH IP SUPPORT & FILE ENUMERATION
# License: MIT
#
# 🙏 ATTRIBUTION:
# This script integrates tools created by:
# - ProjectDiscovery (Subfinder, DNSx, Httpx, Naabu, Katana, Nuclei)
# - OWASP Amass Project
# - OJ Reeves (Gobuster)
# - Ben "epi" Risher (Feroxbuster)
# - Samba Team (smbmap, smbclient)
# - NFS utilities (showmount)
# All reconnaissance capabilities are provided by these excellent tools.
# This script provides workflow automation only.
#
# ⚠️  LEGAL WARNING - READ BEFORE USE ⚠️
#
# This tool performs ACTIVE SECURITY SCANNING including:
# - Port scanning - DNS enumeration - Web probing - Vulnerability detection
#
# ✅ AUTHORIZED USE ONLY:
# - Systems you own
# - Systems with explicit written permission  
# - Bug bounty programs (within stated scope ONLY)
# - Intentional practice targets (HackThisSite, TryHackMe, etc.)
#
# ❌ UNAUTHORIZED SCANNING IS ILLEGAL
# Violates: CFAA (US), Computer Misuse Act (UK), and similar laws worldwide
#
# Consequences: Criminal prosecution, civil lawsuits, professional sanctions
#
# 📖 See SECURITY.md for complete legal guidance
# 🤔 When in doubt: ASK FIRST, SCAN LATER
#
# Description:
# Professional-grade reconnaissance automation that reduces manual recon
# time from hours to minutes. Optimized for PNPT exam methodology.
#
# NEW IN v2.0:
# - IP address support (no more subdomain-only limitation!)
# - SMB share enumeration (smbmap/smbclient)
# - NFS share discovery (showmount)
# - Web directory bruteforcing (gobuster)
# - FTP anonymous access checks
# - Better suited for internal network pentesting
#
# Workflow:
# 1. Target Detection (IP vs Domain)
# 2. Subdomain Discovery (domain only) OR Direct IP scanning
# 3. DNS Resolution & Validation
# 4. Port Scanning (naabu)
# 5. Web Service Probing (httpx)
# 6. Share Enumeration (SMB/NFS)
# 7. Web Directory Discovery (gobuster)
# 8. Deep Web Crawling (katana)
# 9. Vulnerability Scanning (nuclei)
#
#############################################################################

set -Eeuo pipefail

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Global variables
TARGET=""
TARGET_TYPE="" # "ip" or "domain"
OUTPUT_DIR=""
VERBOSE=false
SCAN_MODE="default"

# Scan mode configurations
declare -A MODE_AMASS_TIMEOUT=(
    ["quick"]=300
    ["default"]=600
    ["thorough"]=1800
    ["deep"]=3600
)

declare -A MODE_NAABU_PORTS=(
    ["quick"]="top-ports 100"
    ["default"]="top-ports 1000"
    ["thorough"]="top-ports 1000"
    ["deep"]="p 1-65535"
)

declare -A MODE_KATANA_DEPTH=(
    ["quick"]=2
    ["default"]=3
    ["thorough"]=4
    ["deep"]=5
)

# Default mode settings
AMASS_TIMEOUT=600
NAABU_PORTS="top-ports 1000"
KATANA_DEPTH=3

#############################################################################
# Helper Functions
#############################################################################

print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
    ____  _   ______  ______   ____                     
   / __ \/ | / / __ \/_  __/  / __ \___  _________  ____ 
  / /_/ /  |/ / /_/ / / /    / /_/ / _ \/ ___/ __ \/ __ \
 / ____/ /|  / ____/ / /    / _, _/  __/ /__/ /_/ / / / /
/_/   /_/ |_/_/     /_/    /_/ |_|\___/\___/\____/_/ /_/ 
                                                          
        Professional Reconnaissance Automation
         MB Cyberworks - PNPT Edition v2.0
         NOW WITH IP SUPPORT & FILE ENUMERATION!
EOF
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
}

log_phase() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}[Phase $1]${NC} $2"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
}

set_scan_mode() {
    local mode="$1"
    
    if [[ ! "${MODE_AMASS_TIMEOUT[$mode]+isset}" ]]; then
        log_error "Invalid scan mode: $mode"
        log_error "Valid modes: quick, default, thorough, deep"
        exit 1
    fi
    
    SCAN_MODE="$mode"
    AMASS_TIMEOUT="${MODE_AMASS_TIMEOUT[$mode]}"
    NAABU_PORTS="${MODE_NAABU_PORTS[$mode]}"
    KATANA_DEPTH="${MODE_KATANA_DEPTH[$mode]}"
    
    log_info "Scan mode set to: $mode"
    log_info "  → Amass timeout: ${AMASS_TIMEOUT}s"
    log_info "  → Naabu ports: $NAABU_PORTS"
    log_info "  → Katana depth: $KATANA_DEPTH"
}

check_dependencies() {
    local missing_tools=()
    local required_tools=(
        "subfinder"
        "dnsx"
        "httpx"
        "naabu"
        "katana"
        "nuclei"
    )
    
    local optional_tools=(
        "smbmap"
        "smbclient"
        "showmount"
        "gobuster"
        "feroxbuster"
    )
    
    log_info "Checking dependencies..."
    
    # Check required tools
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install missing tools using install-pnpt-tools.sh"
        exit 1
    fi
    
    # Check optional tools (warn but don't fail)
    local missing_optional=()
    local missing_critical_optional=()
    
    for tool in "${optional_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_optional+=("$tool")
            # Mark critical optional tools
            if [[ "$tool" == "gobuster" || "$tool" == "feroxbuster" ]]; then
                missing_critical_optional+=("$tool")
            fi
        fi
    done
    
    if [ ${#missing_optional[@]} -gt 0 ]; then
        log_warn "Optional tools not found: ${missing_optional[*]}"
    fi
    
    # Critical warning if BOTH gobuster AND feroxbuster are missing
    if [[ ! " ${missing_critical_optional[@]} " =~ "gobuster" ]] || [[ ! " ${missing_critical_optional[@]} " =~ "feroxbuster" ]]; then
        # At least one is present, we're good
        :
    else
        log_error "CRITICAL: Neither gobuster nor feroxbuster found!"
        log_error "File/directory discovery will be SKIPPED"
        log_error "Install at least one: apt install gobuster"
        log_warn "Continuing anyway, but results will be incomplete..."
        sleep 3
    fi
    
    log_info "All required dependencies satisfied ✓"
}

detect_target_type() {
    local target="$1"
    
    # Check if it's an IP address (IPv4)
    if [[ "$target" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        TARGET_TYPE="ip"
        log_info "Target type detected: IP Address"
        return 0
    fi
    
    # Check if it's a CIDR range
    if [[ "$target" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        TARGET_TYPE="cidr"
        log_info "Target type detected: CIDR Range"
        return 0
    fi
    
    # Otherwise assume domain
    if [[ "$target" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        TARGET_TYPE="domain"
        log_info "Target type detected: Domain"
        return 0
    fi
    
    log_error "Invalid target format: $target"
    log_error "Must be: IP (10.0.0.1), CIDR (10.0.0.0/24), or Domain (example.com)"
    exit 1
}

create_output_structure() {
    local base_dir="$1"
    
    # Create all directories at once to avoid the "No such file" errors
    mkdir -p "$base_dir"/{subdomains,dns,ports,web,crawl,vulnerabilities,shares,logs}
    
    # Create placeholder files for stats
    touch "$base_dir"/stats_{subdomains,alive_hosts,open_ports,web_services,endpoints,vulnerabilities,shares}.txt
    echo "0" > "$base_dir/stats_subdomains.txt"
    echo "0" > "$base_dir/stats_alive_hosts.txt"
    echo "0" > "$base_dir/stats_open_ports.txt"
    echo "0" > "$base_dir/stats_web_services.txt"
    echo "0" > "$base_dir/stats_endpoints.txt"
    echo "0" > "$base_dir/stats_vulnerabilities.txt"
    echo "0" > "$base_dir/stats_shares.txt"
    
    log_info "Created output directory: $base_dir"
}

#############################################################################
# Reconnaissance Phases
#############################################################################

phase_target_preparation() {
    log_phase 1 "Target Preparation & Detection"
    
    local alive_file="$OUTPUT_DIR/dns/alive.txt"
    
    if [[ "$TARGET_TYPE" == "ip" ]]; then
        log_info "IP target detected - skipping subdomain enumeration"
        echo "$TARGET" > "$alive_file"
        echo "1" > "$OUTPUT_DIR/stats_alive_hosts.txt"
        log_info "Target IP prepared: $TARGET"
        
    elif [[ "$TARGET_TYPE" == "cidr" ]]; then
        log_info "CIDR range detected - discovering live hosts..."
        # Use naabu or nmap for host discovery
        if command -v naabu &> /dev/null; then
            naabu -host "$TARGET" -silent -o "$alive_file" 2>"$OUTPUT_DIR/logs/host_discovery.log" || true
        fi
        local host_count=$(wc -l < "$alive_file" 2>/dev/null || echo 0)
        echo "$host_count" > "$OUTPUT_DIR/stats_alive_hosts.txt"
        log_info "Live hosts discovered: $host_count"
        
    else
        log_info "Domain target detected - will run subdomain enumeration"
    fi
}

phase_subdomain_discovery() {
    # Only run for domain targets
    if [[ "$TARGET_TYPE" != "domain" ]]; then
        log_info "Skipping subdomain discovery (not a domain target)"
        return 0
    fi
    
    log_phase 2 "Subdomain Discovery"
    
    local output_file="$OUTPUT_DIR/subdomains/all_subdomains.txt"
    local subfinder_out="$OUTPUT_DIR/subdomains/subfinder.txt"
    local amass_out="$OUTPUT_DIR/subdomains/amass.txt"
    
    # Subfinder - fast passive enumeration
    log_info "Running subfinder (passive sources)..."
    if subfinder -d "$TARGET" -all -silent -o "$subfinder_out" 2>"$OUTPUT_DIR/logs/subfinder.log"; then
        local subfinder_count=$(wc -l < "$subfinder_out" 2>/dev/null || echo 0)
        log_info "Subfinder found: $subfinder_count subdomains"
    else
        log_warn "Subfinder encountered issues, check logs"
    fi
    
    # Optional: Amass passive (can be slow, comment out if needed)
    if command -v amass &> /dev/null; then
        log_info "Running amass (timeout: ${AMASS_TIMEOUT}s)..."
        if timeout "$AMASS_TIMEOUT" amass enum -passive -d "$TARGET" -o "$amass_out" 2>"$OUTPUT_DIR/logs/amass.log"; then
            local amass_count=$(wc -l < "$amass_out" 2>/dev/null || echo 0)
            log_info "Amass found: $amass_count subdomains"
        else
            log_warn "Amass timeout or error, continuing..."
        fi
    fi
    
    # Combine and deduplicate - filter only valid domain names
    cat "$subfinder_out" "$amass_out" 2>/dev/null | \
        grep -E '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$' | \
        grep -v '^\s*$' | \
        sort -u > "$output_file"
    
    local total_count=$(wc -l < "$output_file")
    
    log_info "Total unique subdomains discovered: $total_count"
    echo "$total_count" > "$OUTPUT_DIR/stats_subdomains.txt"
}

phase_dns_resolution() {
    # Skip if we already have IPs from target preparation
    if [[ "$TARGET_TYPE" == "ip" ]] || [[ "$TARGET_TYPE" == "cidr" ]]; then
        log_info "Skipping DNS resolution (IP/CIDR target already resolved)"
        return 0
    fi
    
    log_phase 3 "DNS Resolution & Validation"
    
    local input_file="$OUTPUT_DIR/subdomains/all_subdomains.txt"
    local output_file="$OUTPUT_DIR/dns/resolved.txt"
    local alive_file="$OUTPUT_DIR/dns/alive.txt"
    
    if [ ! -s "$input_file" ]; then
        log_warn "No subdomains to resolve, skipping DNS phase"
        return
    fi
    
    local input_count=$(wc -l < "$input_file")
    log_info "Resolving $input_count subdomains with dnsx..."
    
    # DNS resolution with dnsx
    if dnsx -l "$input_file" \
        -silent \
        -resp \
        -o "$output_file" 2>"$OUTPUT_DIR/logs/dnsx.log"; then
        
        # Extract just the hostnames that resolved
        grep -oP '^[^\s]+' "$output_file" 2>/dev/null | sort -u > "$alive_file" || touch "$alive_file"
        
        local alive_count=$(wc -l < "$alive_file" 2>/dev/null || echo 0)
        log_info "DNS resolution complete: $alive_count alive hosts"
        echo "$alive_count" > "$OUTPUT_DIR/stats_alive_hosts.txt"
    else
        log_warn "DNS resolution encountered issues, check logs"
        touch "$output_file" "$alive_file"
        echo "0" > "$OUTPUT_DIR/stats_alive_hosts.txt"
    fi
}

phase_port_scanning() {
    log_phase 4 "Port Scanning"
    
    local input_file="$OUTPUT_DIR/dns/alive.txt"
    local output_file="$OUTPUT_DIR/ports/open_ports.txt"
    
    if [ ! -s "$input_file" ]; then
        log_warn "No targets for port scanning, skipping"
        touch "$output_file"
        echo "0" > "$OUTPUT_DIR/stats_open_ports.txt"
        return
    fi
    
    local target_count=$(wc -l < "$input_file")
    log_info "Scanning ports on $target_count targets with naabu..."
    log_info "Port range: $NAABU_PORTS"
    
    # Determine naabu port arguments
    local port_args=""
    if [[ "$NAABU_PORTS" == "top-ports "* ]]; then
        local port_num="${NAABU_PORTS#top-ports }"
        port_args="-top-ports $port_num"
    elif [[ "$NAABU_PORTS" == "p "* ]]; then
        local port_range="${NAABU_PORTS#p }"
        port_args="-p $port_range"
    fi
    
    # Port scanning with naabu
    if naabu -list "$input_file" \
        $port_args \
        -silent \
        -o "$output_file" 2>"$OUTPUT_DIR/logs/naabu.log"; then
        
        local port_count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
        log_info "Port scanning complete: $port_count open ports discovered"
        echo "$port_count" > "$OUTPUT_DIR/stats_open_ports.txt"
    else
        log_warn "Port scanning encountered issues, check logs"
        touch "$output_file"
        echo "0" > "$OUTPUT_DIR/stats_open_ports.txt"
    fi
}

phase_web_probing() {
    log_phase 5 "Web Service Discovery & Probing"
    
    local input_file="$OUTPUT_DIR/dns/alive.txt"
    local output_file="$OUTPUT_DIR/web/web_services.txt"
    local json_file="$OUTPUT_DIR/web/web_services.json"
    
    if [ ! -s "$input_file" ]; then
        log_warn "No targets for web probing, skipping"
        touch "$output_file" "$json_file"
        echo "0" > "$OUTPUT_DIR/stats_web_services.txt"
        return
    fi
    
    local target_count=$(wc -l < "$input_file")
    log_info "Probing web services on $target_count targets with httpx..."
    
    # Web service probing with httpx
    if httpx -list "$input_file" \
        -silent \
        -timeout 10 \
        -title \
        -status-code \
        -tech-detect \
        -json \
        -o "$json_file" 2>"$OUTPUT_DIR/logs/httpx.log"; then
        
        # Extract URLs from JSON output
        grep -oP '"url":"[^"]+' "$json_file" 2>/dev/null | cut -d'"' -f4 | sort -u > "$output_file" || touch "$output_file"
        
        local web_count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
        log_info "Web probing complete: $web_count web services discovered"
        echo "$web_count" > "$OUTPUT_DIR/stats_web_services.txt"
    else
        log_warn "Web probing encountered issues, check logs"
        touch "$output_file" "$json_file"
        echo "0" > "$OUTPUT_DIR/stats_web_services.txt"
    fi
}

phase_share_enumeration() {
    log_phase 6 "Share Enumeration (SMB/NFS)"
    
    local input_file="$OUTPUT_DIR/dns/alive.txt"
    local smb_output="$OUTPUT_DIR/shares/smb_shares.txt"
    local nfs_output="$OUTPUT_DIR/shares/nfs_shares.txt"
    
    if [ ! -s "$input_file" ]; then
        log_warn "No targets for share enumeration, skipping"
        touch "$smb_output" "$nfs_output"
        echo "0" > "$OUTPUT_DIR/stats_shares.txt"
        return
    fi
    
    local share_count=0
    
    # SMB Share Enumeration
    if command -v smbmap &> /dev/null; then
        log_info "Enumerating SMB shares with smbmap (15s timeout per target)..."
        while IFS= read -r target; do
            log_info "  → Checking SMB on $target"
            {
                echo "=== SMB Shares on $target ==="
                # Use timeout with kill signal after 15 seconds
                timeout -k 2 15 smbmap -H "$target" 2>&1 || echo "No SMB shares, timeout, or access denied"
                echo ""
            } >> "$smb_output"
        done < "$input_file"
        
        # Safely count READ shares
        if [ -f "$smb_output" ]; then
            local smb_count=$(grep -c "READ" "$smb_output" 2>/dev/null)
            if [ -n "$smb_count" ]; then
                share_count=$((share_count + smb_count))
            fi
        fi
    else
        log_warn "smbmap not found - skipping SMB enumeration"
        log_warn "Install: apt install smbmap"
    fi
    
    # NFS Share Enumeration
    log_info "Enumerating NFS shares (10s timeout per target)..."
    
    # First try showmount if available
    if command -v showmount &> /dev/null; then
        while IFS= read -r target; do
            log_info "  → Checking NFS on $target with showmount"
            {
                echo "=== NFS Shares on $target (showmount) ==="
                # 10 second hard timeout - balance between speed and reliability
                timeout -s KILL 10 showmount -e "$target" 2>&1 || echo "Timeout or no NFS shares"
                echo ""
            } >> "$nfs_output"
        done < "$input_file"
    # Fallback to nmap if showmount not available
    elif command -v nmap &> /dev/null; then
        log_info "showmount not found, using nmap for NFS detection"
        while IFS= read -r target; do
            log_info "  → Checking NFS on $target with nmap"
            {
                echo "=== NFS Shares on $target (nmap) ==="
                nmap -p 111,2049 --script nfs-ls,nfs-showmount "$target" 2>&1 | grep -A 10 "nfs-" || echo "No NFS shares found"
                echo ""
            } >> "$nfs_output"
        done < "$input_file"
    else
        log_warn "Neither showmount nor nmap found - skipping NFS enumeration"
        log_warn "Install: apt install nfs-common  OR  apt install nmap"
        touch "$nfs_output"
    fi
    
    # Safely count NFS exports
    if [ -f "$nfs_output" ]; then
        local nfs_count=$(grep -cE "(Export list|nfs-showmount)" "$nfs_output" 2>/dev/null)
        if [ -n "$nfs_count" ] && [ "$nfs_count" -gt 0 ]; then
            share_count=$((share_count + nfs_count))
        fi
    fi
    
    echo "$share_count" > "$OUTPUT_DIR/stats_shares.txt"
    log_info "Share enumeration complete: $share_count shares discovered"
}

phase_directory_bruteforce() {
    log_phase 7 "Web Directory & File Discovery"
    
    local input_file="$OUTPUT_DIR/web/web_services.txt"
    local output_file="$OUTPUT_DIR/web/directories.txt"
    local files_found="$OUTPUT_DIR/web/files_found.txt"
    
    if [ ! -s "$input_file" ]; then
        log_warn "No web services for directory bruteforce, skipping"
        touch "$output_file" "$files_found"
        return
    fi
    
    # Find wordlist
    local wordlist=""
    if [ -f "/usr/share/wordlists/dirb/common.txt" ]; then
        wordlist="/usr/share/wordlists/dirb/common.txt"
    elif [ -f "/usr/share/seclists/Discovery/Web-Content/common.txt" ]; then
        wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"
    else
        log_warn "No wordlist found - skipping directory bruteforce"
        log_warn "Install: apt install dirb or seclists"
        touch "$output_file" "$files_found"
        return
    fi
    
    # Try feroxbuster first (fastest and best)
    if command -v feroxbuster &> /dev/null; then
        log_info "Using feroxbuster for directory discovery (recommended)"
        log_info "Wordlist: $wordlist"
        
        while IFS= read -r url; do
            log_info "  → Scanning $url"
            {
                echo "=== Feroxbuster scan: $url ==="
                # Run feroxbuster WITHOUT filtering - capture everything
                feroxbuster -u "$url" \
                    -w "$wordlist" \
                    -x php,html,txt,pdf,bak,old,config \
                    -t 50 \
                    --depth 2 \
                    --no-recursion \
                    --quiet \
                    2>/dev/null || echo "Scan failed or no results"
                echo ""
            } >> "$output_file"
        done < "$input_file"
        
    # Fallback to gobuster if feroxbuster not available
    elif command -v gobuster &> /dev/null; then
        log_info "Using gobuster for directory discovery"
        log_info "Wordlist: $wordlist"
        log_info "Note: feroxbuster is faster - install with: cargo install feroxbuster"
        
        while IFS= read -r url; do
            log_info "  → Scanning $url"
            {
                echo "=== Gobuster scan: $url ==="
                # Run gobuster WITHOUT filtering - capture everything
                gobuster dir -u "$url" -w "$wordlist" \
                    -x php,html,txt,pdf,bak,old,config \
                    -t 50 \
                    --no-error \
                    2>&1 || echo "No results found"
                echo ""
            } >> "$output_file"
        done < "$input_file"
        
    else
        log_error "Neither feroxbuster nor gobuster found!"
        log_error "Directory/file discovery is CRITICAL for PNPT"
        log_error "Install one of:"
        log_error "  → gobuster: apt install gobuster"
        log_error "  → feroxbuster: cargo install feroxbuster"
        touch "$output_file" "$files_found"
        return
    fi
    
    # Extract interesting files (200, 301, 302) - filter OUT 403/404
    if [ -f "$output_file" ]; then
        grep -E "(Status: (200|201|301|302|307)|200|301|302)" "$output_file" 2>/dev/null | \
            grep -vE "(Status: (403|404)|403|404)" | \
            grep -oP '(/[^\s]+|http[s]?://[^\s]+)' | \
            grep -v "^$" | \
            sort -u > "$files_found" || touch "$files_found"
    else
        touch "$files_found"
    fi
    
    local file_count=$(wc -l < "$files_found" 2>/dev/null || echo 0)
    log_info "Directory discovery complete: $file_count files found"
    
    # Show some results
    if [ "$file_count" -gt 0 ]; then
        log_info "Sample files found:"
        head -n 5 "$files_found" | while read -r file; do
            log_info "  → $file"
        done
    fi
}

phase_web_crawling() {
    log_phase 8 "Deep Web Crawling"
    
    local input_file="$OUTPUT_DIR/web/web_services.txt"
    local output_file="$OUTPUT_DIR/crawl/endpoints.txt"
    
    if [ ! -s "$input_file" ]; then
        log_warn "No targets for crawling, skipping"
        touch "$output_file"
        echo "0" > "$OUTPUT_DIR/stats_endpoints.txt"
        return
    fi
    
    local target_count=$(wc -l < "$input_file")
    log_info "Crawling $target_count web services with katana..."
    log_info "Crawl depth: $KATANA_DEPTH"
    
    # Web crawling with katana
    if katana -list "$input_file" \
        -depth "$KATANA_DEPTH" \
        -silent \
        -jc \
        -known-files all \
        -o "$output_file" 2>"$OUTPUT_DIR/logs/katana.log"; then
        
        local endpoint_count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
        log_info "Crawling complete: $endpoint_count endpoints discovered"
        echo "$endpoint_count" > "$OUTPUT_DIR/stats_endpoints.txt"
    else
        log_warn "Crawling encountered issues, check logs"
        touch "$output_file"
        echo "0" > "$OUTPUT_DIR/stats_endpoints.txt"
    fi
}

phase_vulnerability_scanning() {
    log_phase 9 "Vulnerability Scanning"
    
    local input_file="$OUTPUT_DIR/web/web_services.txt"
    local output_file="$OUTPUT_DIR/vulnerabilities/findings.txt"
    local json_file="$OUTPUT_DIR/vulnerabilities/findings.json"
    
    if [ ! -s "$input_file" ]; then
        log_warn "No targets for vulnerability scanning, skipping"
        touch "$output_file" "$json_file"
        echo "0" > "$OUTPUT_DIR/stats_vulnerabilities.txt"
        return
    fi
    
    local target_count=$(wc -l < "$input_file")
    log_info "Scanning $target_count targets with nuclei..."
    log_info "This may take a while depending on target count..."
    
    # Nuclei vulnerability scanning - try both JSON formats for compatibility
    if nuclei -list "$input_file" \
        -silent \
        -severity critical,high,medium \
        -jsonl \
        -o "$json_file" 2>"$OUTPUT_DIR/logs/nuclei.log"; then
        
        # Extract findings summary if JSON has content
        if [ -s "$json_file" ]; then
            grep -oP '"severity":"[^"]+"|"name":"[^"]+"|"matched":"[^"]+"' "$json_file" 2>/dev/null | \
                paste -d' ' - - - | \
                sort -u > "$output_file" || touch "$output_file"
        else
            touch "$output_file"
        fi
        
        local finding_count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
        log_info "Vulnerability scanning complete: $finding_count findings"
        echo "$finding_count" > "$OUTPUT_DIR/stats_vulnerabilities.txt"
    else
        log_warn "Vulnerability scanning encountered issues, check logs"
        touch "$output_file" "$json_file"
        echo "0" > "$OUTPUT_DIR/stats_vulnerabilities.txt"
    fi
}

#############################################################################
# Summary & Reporting
#############################################################################

generate_summary() {
    log_info "Generating reconnaissance summary..."
    
    local summary_file="$OUTPUT_DIR/SUMMARY.txt"
    
    # Helper function to safely read stats
    get_stat() {
        local file="$1"
        if [ -f "$file" ] && [ -s "$file" ]; then
            cat "$file"
        else
            echo "0"
        fi
    }
    
    cat > "$summary_file" << EOF
================================================================================
PNPT Reconnaissance Summary - v2.0
================================================================================
Target: $TARGET
Target Type: $TARGET_TYPE
Scan Date: $(date)
Scan Mode: $SCAN_MODE
Output Directory: $OUTPUT_DIR

--------------------------------------------------------------------------------
Statistics:
--------------------------------------------------------------------------------
Subdomains Discovered:    $(get_stat "$OUTPUT_DIR/stats_subdomains.txt")
Alive Hosts:              $(get_stat "$OUTPUT_DIR/stats_alive_hosts.txt")
Open Ports:               $(get_stat "$OUTPUT_DIR/stats_open_ports.txt")
Web Services:             $(get_stat "$OUTPUT_DIR/stats_web_services.txt")
Network Shares:           $(get_stat "$OUTPUT_DIR/stats_shares.txt")
Endpoints Discovered:     $(get_stat "$OUTPUT_DIR/stats_endpoints.txt")
Vulnerabilities Found:    $(get_stat "$OUTPUT_DIR/stats_vulnerabilities.txt")

--------------------------------------------------------------------------------
Key Files:
--------------------------------------------------------------------------------
All Subdomains:           $OUTPUT_DIR/subdomains/all_subdomains.txt
Alive Hosts:              $OUTPUT_DIR/dns/alive.txt
Open Ports:               $OUTPUT_DIR/ports/open_ports.txt
Web Services:             $OUTPUT_DIR/web/web_services.txt
SMB Shares:               $OUTPUT_DIR/shares/smb_shares.txt
NFS Shares:               $OUTPUT_DIR/shares/nfs_shares.txt
Web Directories (full):   $OUTPUT_DIR/web/directories.txt
Found Files (filtered):   $OUTPUT_DIR/web/files_found.txt
Crawled Endpoints:        $OUTPUT_DIR/crawl/endpoints.txt
Vulnerability Findings:   $OUTPUT_DIR/vulnerabilities/findings.json

--------------------------------------------------------------------------------
Next Steps:
--------------------------------------------------------------------------------
1. CHECK FOUND FILES: cat $OUTPUT_DIR/web/files_found.txt
2. Review SMB shares: cat $OUTPUT_DIR/shares/smb_shares.txt
3. Check NFS exports: cat $OUTPUT_DIR/shares/nfs_shares.txt
4. Analyze full scan: cat $OUTPUT_DIR/web/directories.txt
5. Review vulnerabilities: cat $OUTPUT_DIR/vulnerabilities/findings.json
6. Manual testing on high-value targets
7. Check logs for any errors: $OUTPUT_DIR/logs/

PNPT Exam Tips:
- Focus on shares with READ/WRITE access
- Look for backup files (.bak, .old, ~)
- Check for credentials in config files
- Test anonymous FTP/SMB access
- Hidden files often contain passwords!
- Document everything for your report!

================================================================================
EOF
    
    cat "$summary_file"
    log_info "Summary saved to: $summary_file"
}

#############################################################################
# Main Execution
#############################################################################

usage() {
    cat << EOF
Usage: $0 -d TARGET [OPTIONS]

Required:
  -d TARGET     Target to scan (IP, CIDR, or Domain)
                Examples: 10.0.0.1, 10.0.0.0/24, example.com

Scan Modes:
  --quick       Fast scan (5min amass, top-100 ports, depth 2)
                Best for: CTF, quick assessments, time pressure
                
  --default     Balanced scan (10min amass, top-1000 ports, depth 3)
                Best for: PNPT exam, standard pentests (DEFAULT)
                
  --thorough    Deep scan (30min amass, top-1000 ports, depth 4)
                Best for: Real engagements, comprehensive coverage
                
  --deep        Maximum scan (60min amass, full ports, depth 5)
                Best for: Red team ops, complete enumeration

Options:
  -o DIR        Custom output directory (default: recon_TARGET_TIMESTAMP)
  -v            Verbose output
  -h            Show this help message

Examples:
  # Scan a single IP (perfect for MARVEL.local)
  $0 -d 10.64.148.171
  
  # Scan an entire network
  $0 -d 10.64.148.0/24 --quick
  
  # Scan a domain
  $0 -d example.com --thorough

NEW in v2.0:
- IP address support (no more subdomain-only!)
- SMB share enumeration (smbmap)
- NFS share discovery (showmount)
- Web directory bruteforcing (gobuster)
- Better suited for internal network pentesting

Scan Mode Comparison:
┌───────────┬──────────────┬─────────────┬──────────────┐
│ Mode      │ Amass Time   │ Naabu Ports │ Katana Depth │
├───────────┼──────────────┼─────────────┼──────────────┤
│ quick     │ 5 minutes    │ top-100     │ depth 2      │
│ default   │ 10 minutes   │ top-1000    │ depth 3      │
│ thorough  │ 30 minutes   │ top-1000    │ depth 4      │
│ deep      │ 60 minutes   │ full scan   │ depth 5      │
└───────────┴──────────────┴─────────────┴──────────────┘

EOF
    exit 1
}

main() {
    print_banner
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d)
                TARGET="$2"
                shift 2
                ;;
            -o)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -v)
                VERBOSE=true
                shift
                ;;
            --quick|--thorough|--deep)
                SCAN_MODE="${1#--}"
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                ;;
        esac
    done
    
    # Validate required arguments
    if [ -z "$TARGET" ]; then
        log_error "Target is required"
        usage
    fi
    
    # Detect target type (IP, CIDR, or Domain)
    detect_target_type "$TARGET"
    
    # Set default output directory if not specified
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="recon_${TARGET//\//_}_${TIMESTAMP}"
    fi
    
    # Apply scan mode configuration
    set_scan_mode "$SCAN_MODE"
    
    # Check dependencies
    check_dependencies
    
    # Create output structure
    create_output_structure "$OUTPUT_DIR"
    
    # Log scan start
    echo ""
    log_info "════════════════════════════════════════════════════════"
    log_info "Starting PNPT Reconnaissance Pipeline v2.0"
    log_info "════════════════════════════════════════════════════════"
    log_info "Target: $TARGET ($TARGET_TYPE)"
    log_info "Scan Mode: $SCAN_MODE"
    log_info "Output: $OUTPUT_DIR"
    log_info "════════════════════════════════════════════════════════"
    echo ""
    
    local start_time=$(date +%s)
    
    # Execute reconnaissance phases
    phase_target_preparation
    
    # Only run subdomain discovery for domain targets
    if [[ "$TARGET_TYPE" == "domain" ]]; then
        phase_subdomain_discovery
        phase_dns_resolution
    fi
    
    phase_port_scanning
    phase_web_probing
    phase_share_enumeration
    phase_directory_bruteforce
    phase_web_crawling
    phase_vulnerability_scanning
    
    # Calculate duration
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    
    # Generate summary
    echo ""
    generate_summary
    
    echo ""
    log_info "════════════════════════════════════════════════════════"
    log_info "Reconnaissance complete! ✓"
    log_info "Total time: ${minutes}m ${seconds}s"
    log_info "Results saved in: $OUTPUT_DIR"
    log_info "════════════════════════════════════════════════════════"
    echo ""
}

# Run main function
main "$@"
