# Process Injection via Suspicious Parent-Child Relationships

**MITRE Technique:** T1055 - Process Injection  
**MITRE Tactic:** TA0004 - Privilege Escalation / TA0005 - Defense Evasion  
**Severity:** Critical  
**False Positive Rate:** Low  

## Description
Detects suspicious parent-child process relationships where Office applications, PDF readers, or other document handlers spawn command-line interpreters. This is a classic indicator of malicious macro execution or exploit code injecting into a trusted process.

## KQL Query
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "acrord32.exe",
    "foxit.exe",
    "notepad.exe",
    "mspaint.exe"
)
| where FileName in~ (
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe"
)
| project
    Timestamp,
    DeviceName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by Timestamp desc
```

## Results in Lab
- **Hit found:** No results
- **Verdict:** Expected baseline — no suspicious parent-child process relationships observed
- **Notes:** Query validated against live MDE P2 telemetry on Windows 11 Pro

## Tuning Notes
- Any hit on this query from a document application should be treated as critical
- Extend the initiating process list to include any document viewer in your environment
- Correlate with DeviceFileEvents to check if the child process dropped additional files

## References
- [MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)
- [Microsoft Defender Advanced Hunting Schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
