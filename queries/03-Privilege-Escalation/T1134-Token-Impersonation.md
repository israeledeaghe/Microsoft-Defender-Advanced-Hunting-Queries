# Privilege Escalation via Token Impersonation

**MITRE Technique:** T1134 - Access Token Manipulation  
**MITRE Tactic:** TA0004 - Privilege Escalation  
**Severity:** Critical  
**False Positive Rate:** Low  

## Description
Detects processes running under high privilege accounts when initiated by lower privilege processes. Attackers manipulate access tokens to escalate privileges and operate as SYSTEM or Administrator without triggering UAC prompts. Any unexpected process running as SYSTEM initiated by a non-system process warrants investigation.

## KQL Query
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where AccountName in~ ("system", "administrator", "trustedinstaller")
| where InitiatingProcessAccountName !in~ ("system", "trustedinstaller", "")
| where FileName !in~ (
    "svchost.exe",
    "services.exe",
    "wininit.exe",
    "csrss.exe",
    "smss.exe",
    "lsass.exe",
    "MsMpEng.exe",
    "senseir.exe"
)
| project
    Timestamp,
    DeviceName,
    FileName,
    ProcessCommandLine,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessAccountName
| order by Timestamp desc
```

## Results in Lab
- **Hit found:** No results
- **Verdict:** Expected baseline — no unexpected privilege escalation observed
- **Notes:** Query validated against live MDE P2 telemetry on Windows 11 Pro

## Tuning Notes
- Any hit on this query should be treated as critical
- Extend exclusion list with any legitimate services in your environment that run as SYSTEM
- Correlate with DeviceLogonEvents to check for subsequent privileged actions

## References
- [MITRE ATT&CK T1134](https://attack.mitre.org/techniques/T1134/)
- [Microsoft Defender Advanced Hunting Schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
