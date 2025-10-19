# 💻  Offensive Security Engineering & Forensics Portfolio

**Kalaichelvan Thieveshkar (Individual)** · Staffordshire University · **COMP50009**  
**Module:** COMP50009 — Ethical Hacking   
**Assessment:** Assignment 2 — Individual Portfolio

**Technical Report (PDF):** [Download Full Technical Report](https://drive.google.com/file/d/1xANeyDaDr3e3tH9rp5JoEWZBMiq33hsZ/view?usp=sharing)

---

## Overview
This repository contains the full portfolio for the Ethical Hacking Individual Assignment 2, demonstrating practical and analytical skills across several cybersecurity domains. It documents **forensics, threat hunting, penetration testing, vulnerability assessment, and exploitation walkthroughs** in a professional and evidence-backed manner.

> **Intended use:** Educational / academic submission only. All testing was performed in isolated lab environments or on authorised vulnerable machines.

---

## Student Details

| Name | Student ID | University |
|------|------------|------------|
| Kalaichelvan Thieveshkar | CB013248 | Staffordshire University |

---

## 🛡️ Part A: Design, Analysis, Forensics & Scripting

### 1. Multi-Factor Authentication (MFA) Implementation for SSH
Hardening an Ubuntu SSH server with Google Authenticator-based MFA and security best practices.

| Component | Description & Key Action | Commands / Tools Used |
|-----------|-------------------------|----------------------|
| Initial Setup | Configured an Ubuntu SSH server and a client machine. | `sudo apt install openssh-server` |
| Penetration Test | Brute-forced weak password using Kali Linux. | `ifconfig`, `netdiscover`, `nmap -sV`, `Hydra` |
| SSH Hardening | Changed default SSH port, set strong password, limited MaxAuthTries. | `passwd`, `sudo nano /etc/ssh/sshd_config`, `sudo systemctl restart ssh` |
| MFA Integration | Configured Google Authenticator PAM module for OTP-based authentication. | `sudo apt install libpam-google-authenticator`, `google-authenticator`, PAM edits |
| Access Control | Limited SSH access to a specific user and IP. | `AllowUsers thieveshkar-server@192.168.163.137` |

---

### 2. Memory Forensics Analysis (Windows XP SP3)
Analysis of a captured memory dump using the Volatility Framework.

| Task | Key Findings & Evidence | Volatility Plugin / OS Info |
|------|------------------------|----------------------------|
| OS Identification | Windows XP SP3 32-bit (Major 5, Minor 1, Build 2600). | `windows.info` |
| Process Analysis | Suspicious processes: ps.exe, cmd.exe launched by svchost.exe, memory dumper mdd.exe. | `windows.pstree` |
| Network Investigation | Multiple TCP connections to 172.16.223.47:445 indicating likely C2 activity. | `connscan` |
| Code Injection | RWX memory regions in critical system processes with shellcode/PE injection. | `malfind` |
| DLL Anomalies | Suspicious DLL (acadproc.dll) loaded for persistence. | `ldrmodules` |
| Conclusion | System compromised with clear evidence of code injection and persistence. | - |

---

### 3. SOC Threat Hunting Exercise (Splunk & BOTS v3)

| Task | SPL Query Key / Finding | IoC / Conclusion |
|------|------------------------|-----------------|
| Login Attempts | EventCode=4624 (Successful). No brute-force attempts detected. | Credential-based attacks not prominent. |
| Suspicious DNS | Reverse DNS lookup: 61.68.107.40.in-addr.arpa | Potential C2 / uncommon traffic. |
| Command-Line Activity | `search "net.exe" OR "whoami"` detected privilege escalation prep. | Indication of reconnaissance / privilege escalation. |
| Malware Incident | PowerShell command connecting to 34.215.24.255 with download/invoke activity. | Evidence of malware execution and C2 communication. |
| Summary & Alerts | Monitoring recommendations: unusual logins, DNS lookups, PowerShell download/invoke commands. | Real-time alert setup suggested. |

---

### 4. Network Forensics Analysis (GootLoader Infection PCAP)

| Analysis Area | Key Findings | Indicators of Compromise (IoC) |
|---------------|-------------|-------------------------------|
| Traffic Overview | 95% TCP, 61% TLS data (likely C2). | High TLS traffic indicates encrypted C2. |
| Host Behavior | Victim IP: 10.12.29.101. Remote hosts deliver payloads / beacon. | 130.208.214.3, 185.84.28.15 |
| Protocol Analysis | Suspicious domains in DNS, HTTP trigger URL found. | parubok-lesia.com, latesthentai.com, www.repslagarna.se/?adfee1f=2365933 |
| Payload Inspection | Obfuscated JavaScript redirects to next malware stage. | Malicious URL: `http://www.repslagarna.se/?adfee1f=2365933` |
| Risk Assessment | High severity; immediate containment recommended. | Block identified IoCs, isolate victim system. |

---

### 5. Image Forensics Analysis (Steganography)

| Step | Technique / Tool | Key Finding |
|------|-----------------|-------------|
| Metadata Analysis | `exiftool` | Base64 string hint, not final flag |
| String Extraction | `strings` | Revealed hidden file `flag.txt` |
| File Structure Analysis | `binwalk` | Embedded ZIP at offset 0x6FEA containing encrypted `flag.txt` |
| Steganography Extraction | `steghide` | Extracted flag using key `Lay3rz_0f_Obfusc4t10n` |

---

## 😈 Part B: Exploiting Vulnerabilities and Penetration Testing (Cybersploit-1)

### Stages of Ethical Hacking Walkthrough

| Stage | Activity | Tools Used |
|-------|---------|------------|
| Reconnaissance | Identified Kali IP & scanned local network for target. | `ifconfig`, `netdiscover` |
| Scanning & Enumeration | Aggressive port/service scan and web enumeration. | `nmap -p- -sC -sV -A --open`, `Dirb` |
| Gaining Access | Exploited info leak from webpage & robots.txt for SSH login. | `ssh` |
| Privilege Escalation | Scanned system, exploited kernel vulnerability for root. | `LinPEAS`, OverlayFS Kernel Exploit (CVE-2015-1328) |
| Post-Exploitation | Confirmed root and retrieved final flag. | `whoami`, `cat /root/final_flag.txt` |

---

### Key Vulnerabilities Identified

| Vulnerability | Description | Evidence | Severity | CVE / CVSS |
|---------------|-------------|---------|---------|------------|
| Linux Kernel OverlayFS | Outdated Kernel 3.13.0-32 vulnerable to local root exploit | `whoami` returns root | Critical | CVE-2015-1328 / 9.8 |
| Outdated SSH | OpenSSH 5.9p1, known vulnerabilities | Port 22/tcp open | High | CVE-2014-1692 / 7.5 |
| Outdated Apache | Apache 2.2.22, end-of-life | Port 80/tcp open | High | CVE-2013-2248 / 7.5 |
| Web Information Leak | Username in HTML source comment | Page source | Medium | N/A |
| Weak SSH Authentication | Login achieved with discovered credentials | SSH success | High | N/A |

---

### Privilege Escalation Techniques & Mitigation

| Technique | Description | Mitigation |
|-----------|------------|------------|
| Linux Kernel Exploits | Exploit outdated kernel (OverlayFS) | Update OS/kernel |
| SUID/SGID Binaries | Misconfigured binaries run with elevated permissions | Audit SUID/SGID, use AppArmor/SELinux |
| Linux Keyring Escalation | Exploit kernel key management bugs | Apply security patches |
| LinPEAS Evaluation | Automated discovery script that identified outdated kernel & exploit vector | Confirm vulnerability & guide remediation |

---

### Framework Relevance

| Framework | Relevance |
|-----------|-----------|
| MITRE ATT&CK | Maps attacks to tactics: Initial Access, Discovery, Privilege Escalation |
| Cyber Kill Chain | Defines stages: Recon, Delivery, Exploitation, Actions on Objectives |

---

## Licensing & Usage
**Custom Educational Use License** (`./LICENSE`):

- Permitted: personal testing, learning, practice in isolated labs.  
- Prohibited: unauthorised redistribution, modification, or running exploit code outside authorized environments.

---

**Technical Report (PDF):** [Download Full Technical Report](https://drive.google.com/file/d/1xANeyDaDr3e3tH9rp5JoEWZBMiq33hsZ/view?usp=sharing)
