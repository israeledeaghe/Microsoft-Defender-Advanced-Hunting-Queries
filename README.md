# 🛡️ Microsoft Defender Advanced Hunting Query Library

![Platform](https://img.shields.io/badge/Platform-Microsoft%20Defender%20XDR-blue)
![Queries](https://img.shields.io/badge/Queries-30%2B-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

A library of 30+ production-ready KQL queries for Microsoft Defender XDR Advanced Hunting, each mapped to MITRE ATT&CK tactics and techniques. Built and tested in a live MDE P2 environment as part of a SOC analyst portfolio project.

## 📋 About This Project

This repository demonstrates practical detection engineering skills using Microsoft Defender for Endpoint Plan 2. Every query has been:
- Written and tested in a live Microsoft Defender XDR environment
- Mapped to specific MITRE ATT&CK techniques
- Documented with false positive analysis and tuning guidance
- Validated against real endpoint telemetry

## 🗂️ Query Library Structure

| Folder | MITRE Tactic | Queries |
|--------|-------------|---------|
| [01-Execution](queries/01-Execution/) | TA0002 - Execution | PowerShell abuse, script interpreters |
| [02-Persistence](queries/02-Persistence/) | TA0003 - Persistence | Registry, scheduled tasks, WMI |
| [03-Privilege-Escalation](queries/03-Privilege-Escalation/) | TA0004 - Privilege Escalation | Token abuse, UAC bypass |
| [04-Defense-Evasion](queries/04-Defense-Evasion/) | TA0005 - Defense Evasion | LOLBins, process injection |
| [05-Credential-Access](queries/05-Credential-Access/) | TA0006 - Credential Access | LSASS dumping, credential theft |
| [06-Discovery](queries/06-Discovery/) | TA0007 - Discovery | System enumeration, network scanning |
| [07-Lateral-Movement](queries/07-Lateral-Movement/) | TA0008 - Lateral Movement | Pass-the-hash, remote execution |
| [08-Collection](queries/08-Collection/) | TA0009 - Collection | Data staging, keylogging |
| [09-Command-and-Control](queries/09-Command-and-Control/) | TA0011 - C2 | Suspicious outbound connections |
| [10-Exfiltration](queries/10-Exfiltration/) | TA0010 - Exfiltration | Large data transfers, DNS tunnelling |

## 🔧 Environment

- **Platform:** Microsoft Defender XDR
- **Licence:** Microsoft Defender for Endpoint Plan 2
- **Data Tables Used:** DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents
- **Tested On:** Windows 11 Pro

## 🚀 How to Use These Queries

1. Log in to [Microsoft Defender XDR](https://security.microsoft.com)
2. Navigate to **Hunting → Advanced Hunting**
3. Copy any query from this library
4. Paste into the query editor and click **Run query**
5. Review results and adapt thresholds to your environment

## 📊 Query Template Format

Each query file follows this structure:

**Title:** Query Name  
**MITRE Technique:** Txxxx - Technique Name  
**MITRE Tactic:** TAxxxx - Tactic Name  
**Severity:** High / Medium / Low  
**Description:** What this detects  
**False Positive Rate:** Low / Medium / High  
**Tuning Notes:** How to reduce noise  

## 👤 Author

**Israel Edeaghe**  
SOC Analyst | Detection Engineer  
[GitHub](https://github.com/israeledeaghe)

---
*Part of a broader SOC analyst portfolio. All queries tested in a live enterprise environment.*
