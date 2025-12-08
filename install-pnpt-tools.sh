#!/bin/bash

#############################################################################
# PNPT Tools Installation Script
#
# Author: MB Cyberworks (mbcyberworks.nl)
# Purpose: Automated installation of reconnaissance tools for PNPT prep
# Version: 1.0
# License: MIT
#
# Description:
# Installs all required ProjectDiscovery tools and dependencies using PDTM
# (ProjectDiscovery Tool Manager) for consistent versioning and updates.
#
#############################################################################

set -Eeuo pipefail

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║   PNPT Tools Installation                                 ║
║   Automated setup for reconnaissance tools                ║
║   MB Cyberworks - mbcyberworks.nl                         ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check for root/sudo
    if [ "$EUID" -eq 0 ]; then
        log_warn "Running as root. This is not recommended."
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Check for Go
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed. Installing Go..."
        install_go
    else
        log_info "Go is already installed: $(go version)"
    fi
    
    # Check for basic tools
    for tool in curl git; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "$tool is not installed"
            log_info "Installing $tool..."
            sudo apt update && sudo apt install -y "$tool"
        fi
    done
}

install_go() {
    log_info "Installing Go..."
    
    local GO_VERSION="1.21.5"
    local GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
    
    cd /tmp
    wget "https://golang.org/dl/${GO_TARBALL}" -O "$GO_TARBALL"
    sudo tar -C /usr/local -xzf "$GO_TARBALL"
    
    # Add to PATH
    if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    fi
    
    if ! grep -q "/usr/local/go/bin" ~/.zshrc 2>/dev/null; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc
        echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
    fi
    
    export PATH=$PATH:/usr/local/go/bin
    export PATH=$PATH:$HOME/go/bin
    
    log_info "Go installed successfully: $(go version)"
}

install_pdtm() {
    log_info "Installing ProjectDiscovery Tool Manager (PDTM)..."
    
    if command -v pdtm &> /dev/null; then
        log_info "PDTM is already installed"
        return 0
    fi
    
    go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
    
    # Ensure PDTM binary is in PATH
    if [ -f "$HOME/go/bin/pdtm" ]; then
        log_info "PDTM installed successfully"
    else
        log_error "PDTM installation failed"
        exit 1
    fi
}

install_projectdiscovery_tools() {
    log_info "Installing ProjectDiscovery tools via PDTM..."
    
    local tools=(
        "subfinder"
        "dnsx"
        "httpx"
        "naabu"
        "nuclei"
        "katana"
    )
    
    for tool in "${tools[@]}"; do
        log_info "Installing $tool..."
        # PDTM doesn't have -silent flag, redirect output instead
        if pdtm -i "$tool" > /dev/null 2>&1; then
            log_info "✓ $tool installed successfully"
        else
            log_info "Installing $tool (may already be installed)..."
            pdtm -i "$tool" 2>&1 | grep -E "(installed|already)" || true
        fi
    done
}

install_additional_tools() {
    log_info "Installing additional reconnaissance tools..."
    
    # Amass (optional but useful)
    if ! command -v amass &> /dev/null; then
        log_info "Installing amass..."
        go install -v github.com/owasp-amass/amass/v4/...@master
    fi
    
    # GAU (Get All URLs)
    if ! command -v gau &> /dev/null; then
        log_info "Installing gau..."
        go install -v github.com/lc/gau/v2/cmd/gau@latest
    fi
    
    # Assetfinder
    if ! command -v assetfinder &> /dev/null; then
        log_info "Installing assetfinder..."
        go install -v github.com/tomnomnom/assetfinder@latest
    fi
}

update_nuclei_templates() {
    log_info "Updating Nuclei templates..."
    
    if command -v nuclei &> /dev/null; then
        nuclei -update-templates -silent
        log_info "✓ Nuclei templates updated"
    else
        log_warn "Nuclei not found, skipping template update"
    fi
}

verify_installation() {
    log_info "Verifying installation..."
    
    local all_good=true
    local tools=(
        "subfinder"
        "dnsx"
        "httpx"
        "naabu"
        "nuclei"
        "katana"
    )
    
    echo ""
    echo "Tool Verification:"
    echo "=================="
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            # Get clean version string
            local version=$("$tool" -version 2>&1 | grep -oE "v[0-9]+\.[0-9]+\.[0-9]+" | head -1 || echo "installed")
            echo -e "${GREEN}✓${NC} $tool - $version"
        else
            echo -e "${RED}✗${NC} $tool - NOT FOUND"
            all_good=false
        fi
    done
    
    echo ""
    
    if [ "$all_good" = true ]; then
        log_info "All tools installed successfully!"
        return 0
    else
        log_error "Some tools are missing. Please check the installation."
        return 1
    fi
}

setup_configuration() {
    log_info "Setting up tool configurations..."
    
    # Create config directories
    mkdir -p ~/.config/subfinder
    mkdir -p ~/.config/nuclei
    
    # Create sample subfinder config if it doesn't exist
    if [ ! -f ~/.config/subfinder/provider-config.yaml ]; then
        cat > ~/.config/subfinder/provider-config.yaml << 'EOF'
# Subfinder Provider Configuration
# Add your API keys here for better results

# Example providers (uncomment and add your keys):
# shodan: 
#   - YOUR_SHODAN_API_KEY
# github:
#   - YOUR_GITHUB_TOKEN
# virustotal:
#   - YOUR_VIRUSTOTAL_KEY
# securitytrails:
#   - YOUR_SECURITYTRAILS_KEY

EOF
        log_info "Created sample subfinder config at ~/.config/subfinder/provider-config.yaml"
        log_info "Edit this file to add your API keys for better results"
    fi
}

main() {
    print_banner
    
    log_info "Starting PNPT tools installation..."
    echo ""
    
    check_prerequisites
    install_pdtm
    install_projectdiscovery_tools
    install_additional_tools
    update_nuclei_templates
    setup_configuration
    
    echo ""
    verify_installation
    
    echo ""
    log_info "Installation complete!"
    echo ""
    echo "Next steps:"
    echo "  1. Restart your terminal or run: source ~/.bashrc (or ~/.zshrc)"
    echo "  2. Add API keys to: ~/.config/subfinder/provider-config.yaml"
    echo "  3. Test your setup: subfinder -d example.com"
    echo "  4. Run the reconnaissance pipeline: ./pnpt-recon-pipeline.sh -d target.com"
    echo ""
}

main "$@"
