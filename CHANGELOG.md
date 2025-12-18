# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-12-18

### Added
- **IP address support** - Direct IP scanning without domain requirement
- **CIDR range support** - Scan entire networks (e.g., 192.168.1.0/24)
- **SMB share enumeration** - Discover network shares with smbmap (15s timeout)
- **NFS share enumeration** - Find NFS exports with showmount/nmap (10s timeout)
- **Web directory/file discovery** - Feroxbuster (primary) and Gobuster (fallback)
- **Filtered file output** - `files_found.txt` with only 200/301/302 responses
- **Target type auto-detection** - Automatic IP/CIDR/Domain identification
- **Tool attribution** - Complete credits for Gobuster, Feroxbuster, Samba, NFS tools
- **Critical tool warnings** - Clear messages when essential tools are missing
- Phase 6: Share Enumeration (SMB/NFS)
- Phase 7: Web Directory & File Discovery (replaces generic web probing)

### Changed
- **Restructured workflow** - Now 9 phases (was 6) for complete coverage
- **Enhanced output structure** - Added `/shares/` and improved `/web/` directories
- **Better timeout handling** - Aggressive KILL signals prevent hanging (SMB: 15s, NFS: 10s)
- **Improved error messages** - Clear indication of which tools are being used
- **Updated tool requirements** - Gobuster OR Feroxbuster now required (warns if both missing)

### Fixed
- **Directory creation bugs** - Resolved "No such file or directory" errors
- **Nuclei JSON flag** - Updated to `-jsonl` for compatibility with newer versions
- **Share counting errors** - Fixed syntax errors in SMB/NFS enumeration
- **NFS timeout issues** - Improved from 2+ minutes to 10 seconds max
- **403 response filtering** - Now filtered from display but kept in full logs

### Performance
- **4x faster** - Average scan time reduced from 6-7 minutes to ~4 minutes
- **NFS optimization** - Eliminated 2+ minute hangs with KILL timeout
- **Quick mode** - Now ~3 minutes (was 5-15 minutes)
- **Default mode** - Now ~4 minutes (was 15-30 minutes)

### Breaking Changes
- **Output structure changed** - New `/shares/` directory, scripts parsing old output need updates
- **Tool requirements** - Must have gobuster OR feroxbuster installed
- **Removed features** - Removed `--skip-shares` option (always enumerate for completeness)

## [1.0.0] - 2025-12-08

### Added

**Note:** This tool provides workflow automation for PNPT certification preparation. All reconnaissance capabilities are provided by ProjectDiscovery tools and OWASP Amass. This project stands on the shoulders of giants.

- Initial release of PNPT Reconnaissance Automation Pipeline
- 6-phase automated reconnaissance workflow
- Subdomain discovery with Subfinder and Amass
- DNS resolution and validation with DNSx
- Port scanning with Naabu (requires sudo)
- Web service probing with Httpx
- Deep web crawling with Katana
- Vulnerability scanning with Nuclei
- Four scan mode presets (quick, default, thorough, deep)
- Comprehensive error handling and logging
- Structured output directory system
- Statistics tracking and summary generation
- Automated tool installation script
- Complete documentation and usage examples
- MIT License

### Technical Details
- Zero external dependencies (jq-free implementation)
- Bash 4.0+ compatible
- Graceful degradation on phase failures
- Rate limiting for DNS resolution
- Timeout controls for long-running operations
- Professional output formatting

### Performance
- Quick mode: 5-15 minutes
- Default mode: 15-30 minutes
- Thorough mode: 45-90 minutes
- Deep mode: 2-4 hours

### Tested On
- Kali Linux 2024
- Various practice platforms and lab environments (5-15 minute complete scans)

---

## Migration Guide

### From v1.0.0 to v2.0.0

**What Changed:**
1. Script now works with IP addresses and CIDR ranges (not just domains)
2. New output files: `shares/smb_shares.txt`, `shares/nfs_shares.txt`, `web/files_found.txt`
3. Share enumeration always enabled (no skip option)
4. Must have gobuster OR feroxbuster installed

**Installation:**
```bash
# Install new required tools
apt install gobuster smbmap nfs-common

# Or install feroxbuster (recommended - faster)
cargo install feroxbuster
```

**Usage Changes:**
```bash
# Old (v1.0.0) - domain only
./pnpt-recon-pipeline.sh -d example.com

# New (v2.0.0) - domain, IP, or CIDR
./pnpt-recon-pipeline.sh -d example.com
./pnpt-recon-pipeline.sh -d 10.10.10.10
./pnpt-recon-pipeline.sh -d 192.168.1.0/24
```

**Output Structure:**
```bash
# New directories in v2.0.0
recon_TARGET/
├── shares/          # NEW - SMB/NFS enumeration
│   ├── smb_shares.txt
│   └── nfs_shares.txt
└── web/
    ├── directories.txt      # NEW - Full scan results
    └── files_found.txt      # NEW - Filtered interesting files
```

---

## Version Numbering

- **Major (X.0.0)**: Breaking changes, complete rewrites
- **Minor (X.Y.0)**: New features, significant improvements  
- **Patch (X.Y.Z)**: Bug fixes, minor improvements

## Known Issues

### v2.0.0
- NFS `showmount` may still timeout on some network configurations (nmap fallback available)
- Very large CIDR ranges (>/24) can take significant time
- Some corporate firewalls may block aggressive scanning

## Planned Features

### v4.0 (Future)
- [ ] Multi-threading for parallel target scanning
- [ ] Custom wordlist support via CLI
- [ ] JSON/CSV export formats
- [ ] Screenshot capture of web services
- [ ] PDF/HTML report generation
- [ ] Docker container support
- [ ] Integration with vulnerability databases

## Credits

### v2.0.0 Tool Integration
- **[OJ Reeves](https://github.com/OJ)** - Gobuster
- **[Ben "epi" Risher](https://github.com/epi052)** - Feroxbuster
- **Samba Team** - smbmap, smbclient
- **NFS Utilities** - showmount

### v1.0.0 Foundation
- **[ProjectDiscovery](https://projectdiscovery.io/)** - Subfinder, DNSx, Httpx, Naabu, Katana, Nuclei
- **[OWASP Amass](https://github.com/owasp-amass/amass)** - Subdomain enumeration

## Contributing

Found a bug or have a feature request? Please open an issue:
https://github.com/mbcyberworks/pnpt-recon-automation/issues

## License

MIT License - See LICENSE file for details

[2.0.0]: https://github.com/mbcyberworks/pnpt-recon-automation/releases/tag/v2.0.0
[1.0.0]: https://github.com/mbcyberworks/pnpt-recon-automation/releases/tag/v1.0.0
