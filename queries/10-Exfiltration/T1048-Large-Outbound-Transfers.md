# Large Outbound Data Transfers - Exfiltration Detection

**MITRE Technique:** T1048 - Exfiltration Over Alternative Protocol  
**MITRE Tactic:** TA0010 - Exfiltration  
**Severity:** High  
**False Positive Rate:** Medium  

## Description
Detects processes making unusually high numbers of outbound connections on non-standard ports within short time windows, indicating potential data exfiltration activity. Attackers exfiltrate data over alternative protocols to avoid detection by DLP tools monitoring standard web traffic.

## KQL Query
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemotePort !in (80, 443)
| where InitiatingProcessFileName !in~ (
    "onedrive.exe",
    "dropbox.exe",
    "MsMpEng.exe",
    "senseir.exe"
)
| summarize
    ConnectionCount = count(),
    UniqueRemoteIPs = dcount(RemoteIP)
    by DeviceName, InitiatingProcessFileName, RemotePort, bin(Timestamp, 10m)
| where ConnectionCount > 20
| order by ConnectionCount desc
```

## Results in Lab
- **Hit found:** No results
- **Verdict:** Expected baseline — no suspicious high-volume outbound connections observed
- **Notes:** Query validated against live MDE P2 telemetry on Windows 11 Pro

## Tuning Notes
- Adjust ConnectionCount threshold based on your environment's baseline traffic
- Add known cloud backup and sync tools to the exclusion list
- Correlate with DeviceFileEvents to identify what files were accessed before the transfer

## References
- [MITRE ATT&CK T1048](https://attack.mitre.org/techniques/T1048/)
- [Microsoft Defender Advanced Hunting Schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)
