# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-08

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

[1.0.0]: https://github.com/mbcyberworks/pnpt-recon-automation/releases/tag/v1.0.0
