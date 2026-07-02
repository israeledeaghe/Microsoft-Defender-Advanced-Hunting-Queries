# Suspicious Logon Events - Valid Accounts Abuse

**MITRE Technique:** T1078 - Valid Accounts  
**MITRE Tactic:** TA0008 - Lateral Movement  
**Severity:** High  
**False Positive Rate:** Medium  

## Description
Detects unusual logon patterns including remote interactive logons and network logons occurring outside business hours. Attackers who have obtained valid credentials often use them to move laterally or maintain access during off-hours to avoid detection.

## KQL Query
```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonSuccess"
| where LogonType in ("RemoteInteractive", "Network", "NetworkCleartext")
| where AccountName !in~ ("system", "local service", "network service")
| extend HourOfDay = datetime_part("Hour", Timestamp)
| where HourOfDay !between (8 .. 18)
| project
    Timestamp,
    DeviceName,
    AccountName,
    AccountDomain,
    LogonType,
    RemoteIP,
    HourOfDay,
    InitiatingProcessFileName
| order by Timestamp desc
```

## Results in Lab
- **Hit found:** No results
- **Verdict:** Expected baseline — no suspicious remote logons observed outside business hours
- **Notes:** Query validated against live MDE P2 telemetry on Windows 11 Pro

## Tuning Notes
- Adjust business hours window (8-18) to match your organisation's working hours
- Exclude known remote administration tools and jump servers by RemoteIP
- Correlate with DeviceNetworkEvents to trace the source of remote logons

## References
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)
- [Microsoft Defender Advanced Hunting Schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table)
