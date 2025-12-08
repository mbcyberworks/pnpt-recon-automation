#!/bin/bash

#############################################################################
# PNPT Reconnaissance Automation Pipeline
# 
# Author: MB Cyberworks (mbcyberworks.nl)
# Purpose: Automated reconnaissance for PNPT certification prep
# Version: 1.0
# License: MIT
#
# 🙏 ATTRIBUTION:
# This script integrates tools created by:
# - ProjectDiscovery (Subfinder, DNSx, Httpx, Naabu, Katana, Nuclei)
# - OWASP Amass Project
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
# Workflow:
# 1. Subdomain Discovery (subfinder + amass)
# 2. DNS Resolution & Validation (dnsx)
# 3. Port Scanning (naabu)
# 4. Web Service Probing (httpx)
# 5. Deep Web Crawling (katana)
# 6. Vulnerability Scanning (nuclei)
#
#############################################################################

set -Eeuo pipefail

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Global variables
DOMAIN=""
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
              MB Cyberworks - PNPT Edition
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
    echo -e "\n${BLUE}[Phase $1/6]${NC} $2"
    echo "================================================================"
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
    
    log_info "Checking dependencies..."
    
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
    
    log_info "All dependencies satisfied ✓"
}

validate_domain() {
    local domain="$1"
    
    # Basic domain validation
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        log_error "Invalid domain format: $domain"
        exit 1
    fi
}

create_output_structure() {
    local base_dir="$1"
    
    mkdir -p "$base_dir"/{subdomains,dns,ports,web,crawl,vulnerabilities,logs}
    
    log_info "Created output directory: $base_dir"
}

#############################################################################
# Reconnaissance Phases
#############################################################################

phase_subdomain_discovery() {
    log_phase 1 "Subdomain Discovery"
    
    local output_file="$OUTPUT_DIR/subdomains/all_subdomains.txt"
    local subfinder_out="$OUTPUT_DIR/subdomains/subfinder.txt"
    local amass_out="$OUTPUT_DIR/subdomains/amass.txt"
    
    # Subfinder - fast passive enumeration
    log_info "Running subfinder (passive sources)..."
    if subfinder -d "$DOMAIN" -all -silent -o "$subfinder_out" 2>"$OUTPUT_DIR/logs/subfinder.log"; then
        local subfinder_count=$(wc -l < "$subfinder_out" 2>/dev/null || echo 0)
        log_info "Subfinder found: $subfinder_count subdomains"
    else
        log_warn "Subfinder encountered issues, check logs"
    fi
    
    # Optional: Amass passive (can be slow, comment out if needed)
    if command -v amass &> /dev/null; then
        log_info "Running amass (timeout: ${AMASS_TIMEOUT}s)..."
        if timeout "$AMASS_TIMEOUT" amass enum -passive -d "$DOMAIN" -o "$amass_out" 2>"$OUTPUT_DIR/logs/amass.log"; then
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
    log_phase 2 "DNS Resolution & Validation"
    
    local input_file="$OUTPUT_DIR/subdomains/all_subdomains.txt"
    local output_file="$OUTPUT_DIR/dns/resolved.txt"
    local alive_file="$OUTPUT_DIR/dns/alive.txt"
    
    if [ ! -s "$input_file" ]; then
        log_warn "No subdomains to resolve, skipping DNS phase"
        return
    fi
    
    local input_count=$(wc -l < "$input_file")
    log_info "Resolving $input_count domains with dnsx..."
    
    # DNS resolution with wildcard detection and rate limiting
    # Rate limit to prevent overwhelming DNS resolvers
    if cat "$input_file" | \
        dnsx -silent \
        -a \
        -resp \
        -rate-limit 150 \
        -retry 2 \
        -o "$output_file" 2>"$OUTPUT_DIR/logs/dnsx.log"; then
        
        # Extract only the domain names for alive hosts
        grep -oE '^[a-zA-Z0-9.-]+' "$output_file" | sort -u > "$alive_file"
        
        local alive_count=$(wc -l < "$alive_file")
        log_info "DNS resolution complete: $alive_count alive hosts"
        echo "$alive_count" > "$OUTPUT_DIR/stats_alive_hosts.txt"
    else
        log_error "DNS resolution failed, but continuing..."
        touch "$alive_file"  # Create empty file to prevent script crash
        echo "0" > "$OUTPUT_DIR/stats_alive_hosts.txt"
    fi
}

phase_port_scanning() {
    log_phase 3 "Port Scanning"
    
    local input_file="$OUTPUT_DIR/dns/alive.txt"
    local output_file="$OUTPUT_DIR/ports/open_ports.txt"
    
    if [ ! -s "$input_file" ]; then
        log_warn "No alive hosts to scan, skipping port scanning"
        return
    fi
    
    local host_count=$(wc -l < "$input_file")
    log_info "Scanning $host_count hosts for open ports..."
    log_info "Port scan mode: $NAABU_PORTS"
    
    # Port scanning with naabu (configurable port range)
    # Split NAABU_PORTS into flag and value
    local naabu_flag=$(echo "$NAABU_PORTS" | cut -d' ' -f1)
    local naabu_value=$(echo "$NAABU_PORTS" | cut -d' ' -f2-)
    
    if sudo naabu -l "$input_file" \
        -"$naabu_flag" "$naabu_value" \
        -silent \
        -o "$output_file" 2>"$OUTPUT_DIR/logs/naabu.log"; then
        
        local port_count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
        log_info "Port scanning complete: $port_count open ports found"
        echo "$port_count" > "$OUTPUT_DIR/stats_open_ports.txt"
    else
        log_warn "Port scanning encountered issues, check logs"
    fi
}

phase_web_probing() {
    log_phase 4 "Web Service Probing"
    
    local input_file="$OUTPUT_DIR/dns/alive.txt"
    local output_file="$OUTPUT_DIR/web/web_services.txt"
    local json_file="$OUTPUT_DIR/web/web_services.json"
    
    if [ ! -s "$input_file" ]; then
        log_warn "No hosts to probe, skipping web probing"
        return
    fi
    
    local host_count=$(wc -l < "$input_file")
    log_info "Probing $host_count hosts for web services..."
    
    # Web probing with technology detection
    if httpx -l "$input_file" \
        -silent \
        -title \
        -status-code \
        -tech-detect \
        -web-server \
        -json \
        -o "$json_file" 2>"$OUTPUT_DIR/logs/httpx.log"; then
        
        # Extract URLs for easy access - use grep instead of jq for portability
        if [ -s "$json_file" ]; then
            grep -oP '"url":"https?://[^"]+' "$json_file" 2>/dev/null | \
                cut -d'"' -f4 | \
                sort -u > "$output_file" || touch "$output_file"
        else
            touch "$output_file"
        fi
        
        local web_count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
        log_info "Web probing complete: $web_count web services found"
        echo "$web_count" > "$OUTPUT_DIR/stats_web_services.txt"
    else
        log_warn "Web probing encountered issues, check logs"
        touch "$output_file"  # Create empty file to prevent crashes
        echo "0" > "$OUTPUT_DIR/stats_web_services.txt"
    fi
}

phase_web_crawling() {
    log_phase 5 "Deep Web Crawling"
    
    local input_file="$OUTPUT_DIR/web/web_services.txt"
    local output_file="$OUTPUT_DIR/crawl/endpoints.txt"
    
    if [ ! -s "$input_file" ]; then
        log_warn "No web services to crawl, skipping crawling phase"
        touch "$output_file"
        echo "0" > "$OUTPUT_DIR/stats_endpoints.txt"
        return
    fi
    
    local url_count=$(wc -l < "$input_file")
    log_info "Crawling $url_count web applications..."
    log_info "Crawl depth: $KATANA_DEPTH"
    
    # Deep crawling with JavaScript parsing
    if katana -list "$input_file" \
        -jc \
        -d "$KATANA_DEPTH" \
        -silent \
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
    log_phase 6 "Vulnerability Scanning"
    
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
    
    # Nuclei vulnerability scanning
    if nuclei -list "$input_file" \
        -silent \
        -severity critical,high,medium \
        -json \
        -o "$json_file" 2>"$OUTPUT_DIR/logs/nuclei.log"; then
        
        # Extract findings summary if JSON has content - use grep instead of jq
        if [ -s "$json_file" ]; then
            # Extract severity, name, and matched from JSON
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
PNPT Reconnaissance Summary
================================================================================
Target Domain: $DOMAIN
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
Endpoints Discovered:     $(get_stat "$OUTPUT_DIR/stats_endpoints.txt")
Vulnerabilities Found:    $(get_stat "$OUTPUT_DIR/stats_vulnerabilities.txt")

--------------------------------------------------------------------------------
Key Files:
--------------------------------------------------------------------------------
All Subdomains:           $OUTPUT_DIR/subdomains/all_subdomains.txt
Alive Hosts:              $OUTPUT_DIR/dns/alive.txt
Open Ports:               $OUTPUT_DIR/ports/open_ports.txt
Web Services:             $OUTPUT_DIR/web/web_services.txt
Crawled Endpoints:        $OUTPUT_DIR/crawl/endpoints.txt
Vulnerability Findings:   $OUTPUT_DIR/vulnerabilities/findings.json

--------------------------------------------------------------------------------
Next Steps:
--------------------------------------------------------------------------------
1. Review web services in: $OUTPUT_DIR/web/web_services.json
2. Analyze vulnerabilities: $OUTPUT_DIR/vulnerabilities/findings.json
3. Manual testing on high-value targets
4. Check logs for any errors: $OUTPUT_DIR/logs/

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
Usage: $0 -d DOMAIN [OPTIONS]

Required:
  -d DOMAIN     Target domain to scan

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
  -o DIR        Custom output directory (default: recon_DOMAIN_TIMESTAMP)
  -v            Verbose output
  -h            Show this help message

Examples:
  $0 -d example.com
  $0 -d tesla.com --quick
  $0 -d target.com --thorough -o /tmp/recon

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
                DOMAIN="$2"
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
    if [ -z "$DOMAIN" ]; then
        log_error "Domain is required"
        usage
    fi
    
    # Set default output directory if not specified
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="recon_${DOMAIN}_${TIMESTAMP}"
    fi
    
    # Apply scan mode configuration
    set_scan_mode "$SCAN_MODE"
    
    # Validate domain
    validate_domain "$DOMAIN"
    
    # Check dependencies
    check_dependencies
    
    # Create output structure
    create_output_structure "$OUTPUT_DIR"
    
    # Log scan start
    log_info "Starting PNPT Reconnaissance Pipeline"
    log_info "Target: $DOMAIN"
    log_info "Scan Mode: $SCAN_MODE"
    log_info "Output: $OUTPUT_DIR"
    
    local start_time=$(date +%s)
    
    # Execute reconnaissance phases
    phase_subdomain_discovery
    phase_dns_resolution
    phase_port_scanning
    phase_web_probing
    phase_web_crawling
    phase_vulnerability_scanning
    
    # Calculate duration
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    
    # Generate summary
    generate_summary
    
    echo ""
    log_info "Reconnaissance complete! ✓"
    log_info "Total time: ${minutes}m ${seconds}s"
    log_info "Results saved in: $OUTPUT_DIR"
}

# Run main function
main "$@"
