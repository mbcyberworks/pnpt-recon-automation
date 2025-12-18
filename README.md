# PNPT Reconnaissance Automation Pipeline

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](CHANGELOG.md)
[![Shell Script](https://img.shields.io/badge/shell_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Kali](https://img.shields.io/badge/Kali-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)](https://www.kali.org/)

> **Automate your PNPT reconnaissance workflow - from hours to minutes.**

⚠️ **[Read Legal & Security Guidelines](SECURITY.md) before use** - Unauthorized scanning is illegal.

Professional 9-phase reconnaissance automation for penetration testers preparing for the Practical Network Penetration Tester (PNPT) certification.

## 🆕 What's New in v2.0.0 (December 2025)

✅ **IP/CIDR Support** - Scan IPs and networks directly (no domain required!)  
✅ **SMB/NFS Enumeration** - Discover network shares  
✅ **Web File Discovery** - Find hidden files with Feroxbuster/Gobuster  
✅ **4x Faster** - Optimized performance (~4 min vs 6-7 min)  

See [CHANGELOG.md](CHANGELOG.md) for full details and migration guide.

## 🎯 Overview

This is a **workflow automation tool** that integrates industry-standard reconnaissance tools into a streamlined PNPT-focused pipeline. It orchestrates existing tools rather than replacing them.

**This tool does NOT:**
- Invent new reconnaissance techniques
- Replace existing security tools
- Provide unique scanning capabilities

**This tool DOES:**
- Automate tedious manual workflows
- Reduce reconnaissance time by 10x
- Provide exam-ready output structure
- Simplify tool orchestration for PNPT preparation

This automation pipeline reduces reconnaissance time by **10x** while maintaining professional-grade output quality.

## 🙏 Built With

This tool stands on the shoulders of giants. All reconnaissance capabilities come from these excellent open-source projects:

**Core Tools:**
- **[ProjectDiscovery](https://projectdiscovery.io/)** - Industry-leading security tool suite
  - [Subfinder](https://github.com/projectdiscovery/subfinder) - Subdomain discovery
  - [DNSx](https://github.com/projectdiscovery/dnsx) - Fast DNS resolution
  - [Httpx](https://github.com/projectdiscovery/httpx) - HTTP probing
  - [Naabu](https://github.com/projectdiscovery/naabu) - Port scanning
  - [Katana](https://github.com/projectdiscovery/katana) - Web crawling
  - [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanning
- **[OWASP Amass](https://github.com/owasp-amass/amass)** - Advanced subdomain enumeration

**v2.0 Additional Tools:**
- **[Gobuster](https://github.com/OJ/gobuster)** by OJ Reeves - Directory/file discovery
- **[Feroxbuster](https://github.com/epi052/feroxbuster)** by Ben "epi" Risher - Fast recursive scanner (optional)
- **Samba Tools** - SMB share enumeration
- **NFS Utilities** - Network File System discovery

**All credit for scanning capabilities goes to these incredible projects and their maintainers.**

This repository simply provides workflow automation and PNPT-specific orchestration.

### Key Features

✅ **Complete 9-phase workflow** - Target detection through vulnerability scanning  
✅ **IP/CIDR/Domain support** - Scan single IPs, networks, or domains  
✅ **Share enumeration** - Find SMB/NFS shares with credentials  
✅ **File discovery** - Locate hidden files, backups, configs  
✅ **Intelligent automation** - Handles errors gracefully, continues on failures  
✅ **Flexible scan modes** - Quick, Default, Thorough, and Deep presets  
✅ **Professional output** - Structured directories, comprehensive logging  
✅ **Zero dependencies** - No jq required, pure bash + standard tools  
✅ **Exam-ready** - Optimized for time-critical assessments  

### Performance

```
Scan Mode Performance (v2.0.0):

Quick Mode:     ~3 minutes   (was 5-15 min)
Default Mode:   ~4 minutes   (was 15-30 min)  
Thorough Mode:  ~6 minutes   (was 45-90 min)
Deep Mode:      15+ minutes  (was 2-4 hours)

Example Results (single IP target):
├─ 3 open ports identified
├─ 1 web service fingerprinted  
├─ 6 files/directories discovered
├─ 3 endpoints crawled
├─ 1 vulnerability detected
└─ Complete in ~4 minutes

Efficiency gain: 10x faster than manual reconnaissance
```

## 🚀 Quick Start

```bash
# 1. Clone repository
git clone https://github.com/mbcyberworks/pnpt-recon-automation.git
cd pnpt-recon-automation

# 2. Install dependencies
chmod +x install-pnpt-tools.sh
./install-pnpt-tools.sh

# 3. Run reconnaissance
chmod +x pnpt-recon-pipeline.sh

# Scan domain (classic)
./pnpt-recon-pipeline.sh -d target.com

# Scan IP (NEW in v2.0)
./pnpt-recon-pipeline.sh -d 10.10.10.10

# Scan network (NEW in v2.0)
./pnpt-recon-pipeline.sh -d 192.168.1.0/24
```

## 📋 Prerequisites

- **Operating System**: Linux (Kali Linux, Ubuntu, Debian)
- **Go**: Version 1.19+ (auto-installed by setup script)
- **Sudo privileges**: Required for port scanning
- **Internet**: Required for tool installation and scanning

**New in v2.0:**
- **Gobuster OR Feroxbuster** - At least one required
- **SMBmap** - Optional but recommended
- **NFS utilities** - Optional but recommended

## 🛠️ Installation

### Automated Installation

```bash
git clone https://github.com/mbcyberworks/pnpt-recon-automation.git
cd pnpt-recon-automation
chmod +x *.sh
./install-pnpt-tools.sh

# Restart terminal or reload shell
source ~/.bashrc
```

### Verify Installation

```bash
subfinder -version
dnsx -version
httpx -version
naabu -version
nuclei -version
katana -version
gobuster version        # NEW in v2.0
```

## 📖 Usage

### Basic Usage

```bash
# Domain scan
./pnpt-recon-pipeline.sh -d target.com

# IP scan (NEW)
./pnpt-recon-pipeline.sh -d 10.10.10.10

# Network scan (NEW)
./pnpt-recon-pipeline.sh -d 192.168.1.0/24

# Custom output directory
./pnpt-recon-pipeline.sh -d target.com -o /path/to/output

# Help
./pnpt-recon-pipeline.sh -h
```

### Scan Modes

| Mode | Duration | Ports | Use Case |
|------|----------|-------|----------|
| `--quick` | ~3 min | top-100 | CTF, Quick recon |
| default | ~4 min | top-1000 | PNPT exam |
| `--thorough` | ~6 min | top-1000 | Real pentests |
| `--deep` | 15+ min | full scan | Red team |

```bash
# Quick mode for CTF
./pnpt-recon-pipeline.sh -d target.com --quick

# Thorough mode for assessments
./pnpt-recon-pipeline.sh -d target.com --thorough

# Overnight deep scan
nohup ./pnpt-recon-pipeline.sh -d target.com --deep > scan.log 2>&1 &
```

## 📂 Output Structure

```
recon_target_TIMESTAMP/
├── SUMMARY.txt                  # Statistics and overview
├── subdomains/
│   └── all_subdomains.txt      # Unique subdomains
├── dns/
│   └── alive.txt               # Confirmed alive hosts
├── ports/
│   └── open_ports.txt          # Open ports per host
├── web/
│   ├── web_services.txt        # Web URLs
│   ├── web_services.json       # Detailed info
│   ├── directories.txt         # NEW: Full scan results
│   └── files_found.txt         # NEW: Filtered interesting files
├── shares/                     # NEW: Share enumeration
│   ├── smb_shares.txt          # SMB shares
│   └── nfs_shares.txt          # NFS exports
├── crawl/
│   └── endpoints.txt           # Discovered endpoints
├── vulnerabilities/
│   └── findings.json           # Vulnerability data
└── logs/                       # Detailed logs
```

## 📄 Reconnaissance Phases

**v2.0 has 9 phases (was 6):**

1. **Target Detection** - Automatic IP/CIDR/Domain identification (NEW)
2. **Subdomain Discovery** (Subfinder, Amass)
3. **DNS Resolution** (DNSx) 
4. **Port Scanning** (Naabu)
5. **Web Probing** (Httpx)
6. **Share Enumeration** (SMBmap, Showmount) - **NEW**
7. **File Discovery** (Feroxbuster/Gobuster) - **NEW**
8. **Deep Crawling** (Katana)
9. **Vulnerability Scanning** (Nuclei)

## ⚙️ Configuration

### Optional: API Keys

Enhance subdomain discovery:

```bash
nano ~/.config/subfinder/provider-config.yaml
```

Add keys from [Shodan](https://shodan.io), [GitHub](https://github.com/settings/tokens), [VirusTotal](https://virustotal.com), etc.

### Optional: Passwordless Sudo

For unattended scans:

```bash
echo "$USER ALL=(ALL) NOPASSWD: $(which naabu)" | sudo tee /etc/sudoers.d/naabu
```

## 🔍 Troubleshooting

**"Command not found"**
```bash
source ~/.bashrc
```

**"Permission denied"**
```bash
# Enter password when prompted, or setup passwordless sudo
```

**Slow performance**
```bash
./pnpt-recon-pipeline.sh -d target.com --quick
```

**"Neither gobuster nor feroxbuster found"**
```bash
sudo apt install gobuster
# Or: cargo install feroxbuster (faster)
```

## 🎓 PNPT Exam Tips

1. **Start early** - Let automation run while reading exam brief
2. **Review SUMMARY.txt** - Quick overview of findings
3. **Check shares first** - SMB/NFS often contain credentials (NEW)
4. **Review files_found.txt** - Focus on .bak, .old files (NEW)
5. **Prioritize** - Focus on web services and unusual ports
6. **Manual testing** - Deep dive on high-value targets
7. **Document** - Take notes continuously

## 🤝 Contributing

Contributions welcome! Please submit issues and pull requests.

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**MB Cyberworks**
- Website: [mbcyberworks.nl](https://mbcyberworks.nl)
- Focus: PNPT certification preparation
- Current: Preparing for January 2026 exam

## ⚠️ Legal Disclaimer

### ❌ UNAUTHORIZED SCANNING IS ILLEGAL

This tool performs **active reconnaissance** including port scanning, web probing, and vulnerability detection. Using it against systems without explicit authorization is **illegal** in most jurisdictions and may violate:

- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act - United Kingdom  
- Wet Computercriminaliteit - Netherlands
- European Cybercrime Directive
- Local laws in your jurisdiction

**Potential consequences:**
- Criminal prosecution
- Civil lawsuits
- Termination from bug bounty programs
- Professional sanctions

### ✅ AUTHORIZED USE ONLY

**You may ONLY scan:**

1. **Systems you own**
2. **Systems with explicit written permission**
3. **Bug bounty programs (within scope)**
4. **Intentional practice targets**

### 🚫 EXAMPLES OF UNAUTHORIZED USE

❌ Major corporations (Tesla, Microsoft, Google, Amazon, etc.)  
❌ Government websites  
❌ Financial institutions  
❌ E-commerce platforms  
❌ Any domain you don't own or have permission to test  

**When in doubt, DON'T SCAN. Get written permission first.**

## 🙏 Acknowledgments

**This tool would not exist without these outstanding open-source projects:**

- **[ProjectDiscovery Team](https://projectdiscovery.io/)** - Subfinder, DNSx, Httpx, Naabu, Katana, Nuclei
- **[OWASP Amass Project](https://github.com/owasp-amass/amass)** - Advanced subdomain enumeration
- **[OJ Reeves](https://github.com/OJ)** - Gobuster
- **[Ben "epi" Risher](https://github.com/epi052)** - Feroxbuster
- **[TCM Security](https://tcm-sec.com/)** - PNPT certification and training

**Please support the original projects** - star their repositories, read their documentation, and contribute if you can.

## 🔗 Related Tools

- **[AutoRecon](https://github.com/Tib3rius/AutoRecon)** - Multi-threaded reconnaissance
- **[Recon-ng](https://github.com/lanmaster53/recon-ng)** - Modular framework
- **[Reconness](https://github.com/reconness/reconness)** - Continuous monitoring

**Why Choose PNPT Recon Automation?**
- ✅ PNPT-specific methodology
- ✅ IP/CIDR support for internal networks (NEW)
- ✅ SMB/NFS enumeration built-in (NEW)
- ✅ 4x performance improvement (v2.0)
- ✅ Beginner-friendly setup

## 🔮 Roadmap

- Multi-threading for parallel scanning
- Custom wordlist support
- Screenshot capture
- HTML/PDF report generation

---

**⭐ Star this repo if you find it useful!**

*Built for the cybersecurity community by [MB Cyberworks](https://mbcyberworks.nl)*
