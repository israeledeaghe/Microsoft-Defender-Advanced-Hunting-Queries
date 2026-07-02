# Network Port Scanning Activity

**MITRE Technique:** T1046 - Network Service Discovery  
**MITRE Tactic:** TA0007 - Discovery  
**Severity:** High  
**False Positive Rate:** Low  

## Description
Detects rapid outbound connections to multiple ports within a short time window, indicating port scanning activity. Attackers scan networks to discover open services and identify lateral movement targets. This query uses summarisation to identify processes making connections to more than 10 unique remote ports within any 5-minute window.

## KQL Query
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType in ("ConnectionSuccess", "ConnectionFailed", "ConnectionAttempt")
| where InitiatingProcessFileName !in~ (
    "svchost.exe",
    "MsMpEng.exe",
    "senseir.exe"
)
| summarize 
    UniqueRemotePorts = dcount(RemotePort),
    UniqueRemoteIPs = dcount(RemoteIP),
    ConnectionCount = count()
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where UniqueRemotePorts > 10
| order by UniqueRemotePorts desc
```

## Results in Lab
- **Hit found:** No results
- **Verdict:** Expected baseline — no port scanning activity observed
- **Notes:** Query validated against live MDE P2 telemetry on Windows 11 Pro

## Tuning Notes
- Adjust the UniqueRemotePorts threshold based on your environment
- Exclude known network monitoring tools and vulnerability scanners
- Correlate with DeviceLogonEvents to check for subsequent access attempts

## References
- [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)
- [Microsoft Defender Advanced Hunting Schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)
