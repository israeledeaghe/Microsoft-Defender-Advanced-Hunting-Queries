# Lateral Movement via PsExec and Remote Execution Tools

**MITRE Technique:** T1570 - Lateral Tool Transfer  
**MITRE Tactic:** TA0008 - Lateral Movement  
**Severity:** Critical  
**False Positive Rate:** Low  

## Description
Detects use of PsExec and similar remote execution tools commonly used by attackers to move laterally across networks. PsExec allows executing processes on remote systems using admin credentials. While used legitimately by IT admins, unexpected use should be treated as suspicious.

## KQL Query
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ (
    "psexec.exe",
    "psexec64.exe",
    "paexec.exe",
    "remcom.exe",
    "csexec.exe"
)
or ProcessCommandLine has_any (
    "\\\\*\\admin$",
    "\\\\*\\ipc$",
    "accepteula"
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
- **Verdict:** Expected baseline — no PsExec or remote execution tools observed
- **Notes:** Query validated against live MDE P2 telemetry on Windows 11 Pro

## Tuning Notes
- Any hit on this query warrants immediate investigation
- IT admins using PsExec legitimately should be whitelisted by AccountName
- Correlate with DeviceLogonEvents to track subsequent remote logons

## References
- [MITRE ATT&CK T1570](https://attack.mitre.org/techniques/T1570/)
- [Microsoft Defender Advanced Hunting Schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
