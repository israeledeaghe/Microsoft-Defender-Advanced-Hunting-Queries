# Suspicious Child Process Spawned by Browser

**MITRE Technique:** T1203 - Exploitation for Client Execution  
**MITRE Tactic:** TA0002 - Execution  
**Severity:** Critical  
**False Positive Rate:** Low  

## Description
Detects browsers spawning unexpected child processes such as PowerShell, CMD, or script hosts. This is a strong indicator of drive-by exploitation where a malicious website exploits a browser vulnerability to execute arbitrary code. Legitimate browsers should never directly spawn command interpreters.

## KQL Query
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "iexplore.exe",
    "opera.exe",
    "brave.exe"
)
| where FileName in~ (
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe"
)
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessAccountName
| order by Timestamp desc
```

## Results in Lab
- **Hit found:** No results
- **Verdict:** Expected baseline — no browsers spawning command interpreters observed
- **Notes:** Query validated against live MDE P2 telemetry on Windows 11 Pro

## Tuning Notes
- Any hit on this query should be treated as critical
- Browsers have no legitimate reason to spawn PowerShell or CMD directly
- Correlate with DeviceNetworkEvents to identify the malicious URL visited

## References
- [MITRE ATT&CK T1203](https://attack.mitre.org/techniques/T1203/)
- [Microsoft Defender Advanced Hunting Schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
