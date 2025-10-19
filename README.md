# 🛡️ Offensive Security Engineering & Forensics Portfolio

**Kalaichelvan Thieveshkar** · Staffordshire University · **Jul 2025 – Oct 2025**

---

## 🚀 Project Overview

This assignment is an individual portfolio showcasing comprehensive technical skills across core cybersecurity domains: defensive engineering, structured threat hunting, advanced digital forensics, and documented penetration testing — all mapped to industry frameworks (MITRE ATT&CK, Cyber Kill Chain).

---

## 🛠️ Technical Focus Areas

### 1. Digital Forensics & Threat Hunting

| Domain | Methodology | Key Outcomes |
|---|---|---|
| **Memory Forensics** | Performed Volatility Framework analysis on a compromised Windows memory dump. | Identified process anomalies, shellcode injection (RWX memory regions in `csrss.exe`, `winlogon.exe`, and `msimn.exe`), C2 communication, and suspicious DLL loading (e.g., `acadproc.dll`). |
| **SOC / Threat Hunting** | Used Splunk against the BOTS v3 dataset to hunt for C2 communication, privilege checks, and malware execution. | Correlated suspicious reverse DNS lookups and detected PowerShell commands using download & invoke (indicating malware delivery), confirming reconnaissance and C2 activity. |
| **Network Analysis** | Analyzed GootLoader PCAP traffic via Wireshark (HTTP / TLS). | Identified malware downloads, obfuscated JavaScript payload injection via compromised WordPress, and subsequent TLS C2 beaconing. |
| **Image Forensics** | Applied `ExifTool`, `strings`, and `steghide` against a JPEG file. | Successfully bypassed steganography by using hidden metadata and a cleartext passphrase to extract an embedded flag. |

---

### 2. Penetration Testing & Defense‑in‑Depth

| Phase | Technique & Tooling | Result |
|---|---|---|
| **Defense‑in‑Depth** | SSH Hardening (MFA): implemented Google Authenticator PAM, IP whitelisting, custom SSH port, and connection rate limiting. | Hardened SSH access; reduced risk from brute‑force and credential‑stuffing attacks. |
| **Penetration Test** | Vulnerability assessment using `nmap`, `Metasploit` (pre/post hardening). | Demonstrated effectiveness of controls by comparing attack surface and successful attempts before vs after MFA. |
| **Privilege Escalation** | `linPEAS`, manual enumeration, and kernel exploit (OverlayFS — CVE‑2015‑1328); exploited misconfigured sudo privileges. | Achieved root access; findings were classified, risk‑scored, and mapped to Cyber Kill Chain / MITRE ATT&CK. |

---

## 🔗 Documentation & Licensing

- **Full Technical Report & Summary (PDF):** [Download Technical Report (Drive)](https://drive.google.com/file/d/1xANeyDaDr3e3tH9rp5JoEWZBMiq33hsZ/view?usp=sharing)  
- **License:** `license_security_forensics.md`

---

## 📜 Custom Educational Use License

This project is protected under a **Custom Educational Use License**.  
Permitted: personal testing, learning, and non‑commercial practice within isolated lab environments.  
Prohibited: modification of challenge content, redistribution of the VM or challenge assets without explicit permission, or use of exploit code on systems without written authorization.

---

*If you want me to replace the walkthrough placeholder with a live link, or add SHA256 checksums / file sizes for the report or VM, paste those links or values and I’ll update the markdown exactly where you want them.*
