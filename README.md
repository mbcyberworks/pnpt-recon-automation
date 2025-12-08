# PNPT Reconnaissance Automation Pipeline

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell Script](https://img.shields.io/badge/shell_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Kali](https://img.shields.io/badge/Kali-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)](https://www.kali.org/)

> **Automate your PNPT reconnaissance workflow - from hours to minutes.**

⚠️ **[Read Legal & Security Guidelines](SECURITY.md) before use** - Unauthorized scanning is illegal.

Professional 6-phase reconnaissance automation for penetration testers preparing for the Practical Network Penetration Tester (PNPT) certification.

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

**All credit for scanning capabilities goes to these incredible projects and their maintainers.**

This repository simply provides workflow automation and PNPT-specific orchestration.

### Key Features

✅ **Complete 6-phase workflow** - Subdomain discovery through vulnerability scanning  
✅ **Intelligent automation** - Handles errors gracefully, continues on failures  
✅ **Flexible scan modes** - Quick, Default, Thorough, and Deep presets  
✅ **Professional output** - Structured directories, comprehensive logging  
✅ **Zero dependencies** - No jq required, pure bash + standard tools  
✅ **Exam-ready** - Optimized for time-critical assessments  

### Performance

```
Scan Mode Performance (target dependent):

Quick Mode:     5-15 minutes
Default Mode:   15-30 minutes  
Thorough Mode:  45-90 minutes
Deep Mode:      2-4 hours

Example Results (small-medium target):
├─ 20-50 subdomains discovered
├─ 10-30 alive hosts validated  
├─ 30-100 open ports identified
├─ 10-25 web services fingerprinted
├─ 100-500 endpoints crawled
└─ Complete in 10-20 minutes

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
./pnpt-recon-pipeline.sh -d target.com
```

## 📋 Prerequisites

- **Operating System**: Linux (Kali Linux, Ubuntu, Debian)
- **Go**: Version 1.19+ (auto-installed by setup script)
- **Sudo privileges**: Required for port scanning
- **Internet**: Required for tool installation and scanning

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
```

## 📖 Usage

### Basic Usage

```bash
# Standard scan
./pnpt-recon-pipeline.sh -d target.com

# Custom output directory
./pnpt-recon-pipeline.sh -d target.com -o /path/to/output

# Help
./pnpt-recon-pipeline.sh -h
```

### Scan Modes

| Mode | Duration | Ports | Use Case |
|------|----------|-------|----------|
| `--quick` | 5-15 min | top-100 | CTF, Quick recon |
| default | 15-30 min | top-1000 | PNPT exam |
| `--thorough` | 45-90 min | top-1000 | Real pentests |
| `--deep` | 2-4 hrs | full scan | Red team |

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
recon_target.com_TIMESTAMP/
├── SUMMARY.txt                  # Statistics and overview
├── subdomains/
│   └── all_subdomains.txt      # Unique subdomains
├── dns/
│   └── alive.txt               # Confirmed alive hosts
├── ports/
│   └── open_ports.txt          # Open ports per host
├── web/
│   ├── web_services.txt        # Web URLs
│   └── web_services.json       # Detailed info
├── crawl/
│   └── endpoints.txt           # Discovered endpoints
├── vulnerabilities/
│   └── findings.json           # Vulnerability data
└── logs/                       # Detailed logs
```

## 🔄 Reconnaissance Phases

1. **Subdomain Discovery** (Subfinder, Amass)
2. **DNS Resolution** (DNSx) 
3. **Port Scanning** (Naabu)
4. **Web Probing** (Httpx)
5. **Deep Crawling** (Katana)
6. **Vulnerability Scanning** (Nuclei)

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

## 🎓 PNPT Exam Tips

1. **Start early** - Let automation run while reading exam brief
2. **Review SUMMARY.txt** - Quick overview of findings
3. **Prioritize** - Focus on web services and unusual ports
4. **Manual testing** - Deep dive on high-value targets
5. **Document** - Take notes continuously

## 🤝 Contributing

Contributions welcome! Please submit issues and pull requests.

## 📝 License

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
   - Your own domains and servers
   - Your own VPS/cloud infrastructure
   - Your own network equipment

2. **Systems with explicit written permission**
   - Professional penetration testing engagements (with signed contract)
   - Client systems during authorized security assessments
   - Internal corporate networks (with IT approval)

3. **Bug bounty programs (within scope)**
   - **ONLY** targets explicitly listed in scope
   - Follow program rules and rate limits
   - **Most main domains are OUT OF SCOPE** (e.g., tesla.com itself)
   - Read scope carefully before scanning

4. **Intentional practice targets**
   - HackThisSite.org
   - TryHackMe lab machines (via VPN)
   - HackTheBox lab machines (via VPN)
   - VulnHub virtual machines
   - DVWA, Metasploitable, WebGoat
   - Your own lab environments

### 🚫 EXAMPLES OF UNAUTHORIZED USE

**DO NOT scan these without explicit permission:**

❌ Major corporations (Tesla, Microsoft, Google, Amazon, etc.)  
❌ Government websites  
❌ Financial institutions  
❌ E-commerce platforms  
❌ Social media sites  
❌ Educational institutions  
❌ Healthcare organizations  
❌ Any domain you don't own or have permission to test  

**Even if a company has a bug bounty program, the main domain is usually OUT OF SCOPE.**

### 📋 Safe Practice Targets

**Intentionally vulnerable / authorized for practice:**

✅ **Your own domains and infrastructure** - Always authorized  
✅ **TryHackMe.com** - Lab machines via VPN (specific IPs only)  
✅ **HackTheBox.eu** - Lab machines via VPN (specific IPs only)  
✅ **Practice platforms** - Within their explicit scope and rules:
   - HackThisSite.org (read their rules, respect scope)
   - OverTheWire.org (challenge-specific only)
   - PentesterLab.com (within exercise scope)
✅ **Intentionally vulnerable VMs** - Deploy yourself:
   - DVWA, Metasploitable, VulnHub, WebGoat

**Important:** Even on practice platforms, always:
- Read their terms of service and rules
- Stay within explicitly authorized scope
- Use provided VPN for lab environments
- Test only specific challenges/machines, not entire platforms  

### ⚖️ Author Disclaimer

**The author and contributors:**
- Provide this tool for **authorized security testing only**
- Are **not responsible** for any misuse or illegal activity
- Do **not authorize** or encourage unauthorized scanning
- Recommend consulting a lawyer before testing unfamiliar targets

**By using this tool, you agree:**
- To only scan authorized targets
- To obtain proper permission before scanning
- To comply with all applicable laws
- To accept full responsibility for your actions

### 🛡️ Responsible Disclosure

If you discover vulnerabilities:
1. Do NOT exploit them
2. Report through proper channels (bug bounty, security contact)
3. Give reasonable time for fixes
4. Do NOT publicly disclose without coordination

**When in doubt, DON'T SCAN. Get written permission first.**

## 🙏 Acknowledgments

**This tool would not exist without these outstanding open-source projects:**

### Tool Creators & Maintainers

- **[ProjectDiscovery Team](https://projectdiscovery.io/)** - For creating and maintaining the comprehensive security tool suite that powers this automation
  - Tools: Subfinder, DNSx, Httpx, Naabu, Katana, Nuclei
  - Their commitment to open-source security tools is incredible
  - [GitHub Organization](https://github.com/projectdiscovery)
  
- **[OWASP Amass Project](https://github.com/owasp-amass/amass)** - For advanced subdomain enumeration
  - Maintained by [@caffix](https://github.com/caffix) and contributors
  - Essential tool for deep reconnaissance

### Education & Training

- **[TCM Security](https://tcm-sec.com/)** - PNPT certification and training
  - [Heath Adams (@thecybermentor)](https://twitter.com/thecybermentor) - For excellent course content and methodology
  
### Community

- The cybersecurity community for feedback and support
- All contributors to this project

**Important:** This repository provides **workflow automation only**. All reconnaissance and scanning capabilities come from the tools above. 

**Please support the original projects:**
- ⭐ Star their repositories
- 📖 Read their documentation  
- 💬 Join their communities
- 💰 Support them financially if possible

Without them, this automation would be impossible.

## 🔗 Related Tools

If this tool doesn't fit your needs, consider these excellent alternatives:

**Comprehensive Frameworks:**
- **[AutoRecon](https://github.com/Tib3rius/AutoRecon)** by [@Tib3rius](https://github.com/Tib3rius)
  - Multi-threaded, highly configurable
  - Best for: Complex infrastructure assessments
  
- **[Recon-ng](https://github.com/lanmaster53/recon-ng)** by [@lanmaster53](https://github.com/lanmaster53)
  - Framework with modules
  - Best for: Extensible reconnaissance workflows
  
- **[Reconness](https://github.com/reconness/reconness)** 
  - Web-based continuous reconnaissance
  - Best for: Long-term monitoring

**Why Choose PNPT Recon Automation?**
- ✅ Specifically designed for PNPT exam methodology
- ✅ Preset scan modes (quick/thorough/deep)
- ✅ Minimal dependencies (no jq required)
- ✅ Beginner-friendly with comprehensive docs
- ✅ Fast setup (one command install)

**All tools have their place.** Choose what fits your workflow!

## 🔮 Roadmap (v2.0+)

- Intelligent finding prioritization
- HTML reports with visualizations
- Screenshot capture
- Enhanced analysis features

---

**⭐ Star this repo if you find it useful!**

*Built for the cybersecurity community by [MB Cyberworks](https://mbcyberworks.nl)*
