# Suspicious File Downloads - Ingress Tool Transfer

**MITRE Technique:** T1105 - Ingress Tool Transfer  
**MITRE Tactic:** TA0011 - Command and Control  
**Severity:** High  
**False Positive Rate:** Medium  

## Description
Detects executable files, scripts, and DLLs downloaded via browsers or command line tools into user-writable directories. Attackers frequently download tools and payloads into Downloads, Temp, or AppData folders to stage further attack activity.

## KQL Query
```kql
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType == "FileCreated"
| where FileName endswith ".exe" 
    or FileName endswith ".ps1"
    or FileName endswith ".bat"
    or FileName endswith ".vbs"
    or FileName endswith ".dll"
| where FolderPath has_any (
    "\\Downloads\\",
    "\\Temp\\",
    "\\AppData\\Local\\Temp\\",
    "\\Public\\"
)
| where InitiatingProcessFileName has_any (
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "powershell.exe",
    "cmd.exe",
    "bitsadmin.exe"
)
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessAccountName,
    SHA256
| order by Timestamp desc
```

## Results in Lab
- **Hit found:** YES — 1 real detection
- **File detected:** PPEccwgK.exe
- **Location:** C:\Users\HP\Downloads\
- **Downloaded via:** firefox.exe
- **Account:** hp
- **Verdict:** SUSPICIOUS — randomly named executable downloaded via Firefox. Random character filenames are a strong indicator of malicious or auto-generated payloads. Warrants immediate investigation.

## Investigation Notes
- SHA256 hash should be submitted to VirusTotal for reputation check
- File should be quarantined pending investigation
- Correlate with browser history to identify the download source URL
- Check if the file was executed using DeviceProcessEvents

## Tuning Notes
- Exclude known software update processes (e.g. software installers with consistent naming)
- Focus on files with random or unusual names as highest priority
- Correlate SHA256 with threat intelligence feeds for automated enrichment

## References
- [MITRE ATT&CK T1105](https://attack.mitre.org/techniques/T1105/)
- [Microsoft Defender Advanced Hunting Schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)
