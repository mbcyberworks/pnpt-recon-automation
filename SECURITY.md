# Security Policy and Legal Usage

## ⚠️ Legal Notice

**IMPORTANT**: This tool performs active security reconnaissance. Unauthorized use is illegal.

## 🚫 What is Unauthorized Scanning?

Scanning systems without permission violates laws worldwide:

- **United States**: Computer Fraud and Abuse Act (CFAA)
- **United Kingdom**: Computer Misuse Act 1990
- **Netherlands**: Wet Computercriminaliteit III
- **European Union**: Cybercrime Directive 2013/40/EU
- **Many other jurisdictions**: Similar cybercrime laws

### Potential Consequences

❌ Criminal prosecution (fines, imprisonment)  
❌ Civil lawsuits (damages, legal fees)  
❌ Termination from bug bounty programs  
❌ Professional sanctions and reputation damage  
❌ Network bans and blacklisting  

## ✅ Authorized Usage

### You MAY scan:

#### 1. Your Own Systems
- Domains you registered and own
- Servers you control (VPS, cloud, dedicated)
- Your home network and devices
- Your company's systems (with IT approval)

#### 2. With Written Permission
- Professional penetration testing contracts
- Signed authorization letters
- Security assessment agreements
- Internal security audits (with management approval)

#### 3. Bug Bounty Programs (IN SCOPE ONLY)
**Critical**: Just because a company has a bug bounty does NOT mean you can scan everything.

**✅ Allowed:**
- Targets explicitly listed in scope
- Following program rules (rate limits, methodology)
- Within specified IP ranges or domains

**❌ NOT Allowed:**
- Main corporate domains (usually out of scope)
- Infrastructure not listed in scope
- Exceeding rate limits
- Aggressive scanning techniques

**Example**: Tesla Bug Bounty
- ✅ Specific subdomains listed in scope
- ❌ tesla.com itself (main domain)
- ❌ Random tesla subdomains not in scope

**Always read the scope carefully!**

#### 4. Intentional Practice Targets
See "Safe Practice Targets" section below.

## 🎯 Safe Practice Targets

### Explicitly Authorized for Security Testing

#### Educational Platforms

**Important:** Even on practice platforms, respect their terms and scope.

- **HackThisSite.org** - Legal hacking challenges
  - ✅ Use for their intended challenges
  - ⚠️ Read their rules before scanning
  - ❌ Don't scan entire platform infrastructure

- **OverTheWire.org** - Wargames platform
  - ✅ Challenge-specific targets only
  - ⚠️ Follow their guidelines

**Better approach for practice:**
```bash
# Use your own domain
./pnpt-recon-pipeline.sh -d yourdomain.com --quick

# Or deploy intentionally vulnerable VMs
./pnpt-recon-pipeline.sh -d 192.168.1.100  # Your DVWA VM
```
  
#### CTF/Lab Platforms (via VPN)

**Critical:** These platforms provide **specific lab IPs** to scan, NOT their main domains.

- **TryHackMe.com** - Lab machines through VPN
  ```bash
  # ✅ CORRECT: Connect to VPN, scan specific lab IP
  sudo openvpn tryhackme.ovpn
  ./pnpt-recon-pipeline.sh -d 10.10.123.45  # Specific machine IP
  
  # ❌ WRONG: Don't scan tryhackme.com itself
  ```

- **HackTheBox.eu** - Penetration testing labs
  ```bash
  # ✅ CORRECT: Connect to VPN, scan specific box IP
  sudo openvpn hackthebox.ovpn
  ./pnpt-recon-pipeline.sh -d 10.10.10.123  # Specific box IP
  
  # ❌ WRONG: Don't scan hackthebox.eu itself
  ```

**Rule:** Scan the **lab IP**, never the **platform domain**.

#### Your Own Infrastructure
- Your registered domains
- Your VPS/cloud servers
- Your home lab

```bash
# Your own domain
./pnpt-recon-pipeline.sh -d yourdomain.com

# Your VPS
./pnpt-recon-pipeline.sh -d your-vps.example.com
```

#### Intentionally Vulnerable Applications
Deploy these yourself:
- **DVWA** (Damn Vulnerable Web Application)
- **WebGoat** (OWASP)
- **Metasploitable** (Rapid7)
- **VulnHub** VMs
- **bWAPP** (Buggy Web Application)

## 🚫 DO NOT Scan These (Examples)

**Even with this tool, DO NOT scan:**

### Major Corporations
❌ tesla.com, microsoft.com, google.com, amazon.com  
❌ apple.com, meta.com, netflix.com  
❌ Any Fortune 500 company main domain  

### Government & Critical Infrastructure
❌ Government websites (.gov, .mil)  
❌ Law enforcement sites  
❌ Critical infrastructure (utilities, transportation)  

### Financial Services
❌ Banks and credit unions  
❌ Payment processors  
❌ Stock exchanges  
❌ Insurance companies  

### Healthcare
❌ Hospitals and clinics  
❌ Health insurance providers  
❌ Medical device manufacturers  

### Education
❌ Universities and colleges  
❌ School districts  
❌ Educational platforms (without permission)  

### Other Prohibited Targets
❌ Social media platforms  
❌ E-commerce sites  
❌ News organizations  
❌ Cloud service providers  
❌ Anyone's website without explicit permission  

**"But they have a bug bounty!" is NOT permission to scan the main domain.**

## 📋 Pre-Scan Checklist

Before running any scan, verify:

- [ ] I own this system OR
- [ ] I have written authorization OR
- [ ] This is explicitly listed in a bug bounty scope OR
- [ ] This is an intentional practice target

If you checked none of the above → **DO NOT SCAN**

## 🛡️ Responsible Disclosure

If you discover vulnerabilities during authorized testing:

### DO:
✅ Report through proper channels (bug bounty, security@)  
✅ Provide detailed reproduction steps  
✅ Give reasonable time for fixes (typically 90 days)  
✅ Follow coordinated disclosure practices  

### DON'T:
❌ Exploit vulnerabilities  
❌ Access or modify data  
❌ Publicly disclose before coordination  
❌ Sell vulnerability information  
❌ Extort the organization  

## 📖 Bug Bounty Resources

### How to Find Legitimate Targets

**Bug Bounty Platforms:**
- [HackerOne](https://hackerone.com/directory/programs) - Directory of programs
- [Bugcrowd](https://bugcrowd.com/programs) - Active programs list
- [Intigriti](https://intigriti.com/programs) - European programs
- [YesWeHack](https://yeswehack.com/programs) - Global programs

**Always:**
1. Read the full program rules
2. Check the scope carefully
3. Follow rate limits
4. Use approved methodologies
5. Report findings properly

## 🎓 PNPT Exam Context

During your PNPT exam:
- ✅ You HAVE permission to scan exam targets
- ✅ Targets are provided by TCM Security
- ✅ This is a controlled environment
- ✅ This tool is appropriate for exam use

**Outside the exam:**
- ❌ Do NOT scan random domains for practice
- ✅ Use intentional practice targets instead
- ✅ Set up your own lab environment

## ⚖️ When in Doubt

**ASK FIRST. SCAN LATER.**

If you're unsure whether you have permission:
1. Don't scan
2. Contact the system owner
3. Get written authorization
4. Keep records of permission

**"I didn't know" is not a legal defense.**

## 🔒 Reporting Security Issues

Found a vulnerability in this tool?

**DO NOT** open a public GitHub issue.

Contact: [maintainer security email]

We follow responsible disclosure and will:
- Acknowledge within 48 hours
- Provide fixes promptly
- Credit researchers (with permission)

## 📝 Legal Resources

- [CFAA Explained](https://www.nacdl.org/Landing/ComputerFraudandAbuseAct)
- [Bug Bounty Forum Legal Guide](https://forum.bugcrowd.com/t/legal-faq/1439)
- [SANS Penetration Testing Policy](https://www.sans.org/information-security-policy/)

## ✍️ Author's Commitment

As the tool author, I:
- Provide this for **authorized testing only**
- Do **not encourage** or **condone** illegal activity
- Am **not responsible** for user actions
- Recommend consulting legal counsel when uncertain
- Support responsible security research

## 📞 Need Help?

**Unsure if you can scan a target?**
- Consult a lawyer specializing in cybersecurity law
- Contact the target's security team
- Use only confirmed safe practice targets

**Remember:** No scan is worth legal trouble.

---

**By using this tool, you agree to use it legally, ethically, and responsibly.**

*Last updated: December 2024*
