# LOLBin Abuse - Living off the Land Binaries

**MITRE Technique:** T1218 - System Binary Proxy Execution  
**MITRE Tactic:** TA0005 - Defense Evasion  
**Severity:** High  
**False Positive Rate:** Medium  

## Description
Detects abuse of legitimate Windows binaries to download payloads, execute scripts, or proxy malicious code execution. These binaries are trusted by the OS and are often whitelisted by security tools, making them ideal for attackers to blend into normal activity.

## KQL Query
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ (
    "certutil.exe",
    "bitsadmin.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "msiexec.exe",
    "forfiles.exe",
    "pcalua.exe"
)
| where ProcessCommandLine has_any (
    "http",
    "ftp",
    "decode",
    "urlcache",
    "transfer",
    "javascript",
    "vbscript"
)
| project
    Timestamp,
    DeviceName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessAccountName
| order by Timestamp desc
```

## Results in Lab
- **Hit found:** No results
- **Verdict:** Expected baseline — no LOLBin abuse observed in last 24 hours
- **Notes:** Query validated against live MDE P2 telemetry on Windows 11 Pro

## Tuning Notes
- rundll32.exe and msiexec.exe may generate false positives during software installations
- Whitelist known software deployment processes by InitiatingProcessFileName
- Focus on executions originating from browser processes or email clients as high priority

## References
- [MITRE ATT&CK T1218](https://attack.mitre.org/techniques/T1218/)
- [Microsoft Defender Advanced Hunting Schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
