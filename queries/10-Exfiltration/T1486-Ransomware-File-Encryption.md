# Ransomware File Encryption Detection

**MITRE Technique:** T1486 - Data Encrypted for Impact  
**MITRE Tactic:** TA0040 - Impact  
**Severity:** Critical  
**False Positive Rate:** Low  

## Description
Detects mass file modifications with ransomware-associated file extensions. Ransomware encrypts victim files and appends custom extensions to signal infection and demand payment. Early detection of these file extension changes can allow containment before the full environment is encrypted.

## KQL Query
```kql
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileModified", "FileRenamed")
| where FileName endswith ".encrypted"
    or FileName endswith ".locked"
    or FileName endswith ".crypt"
    or FileName endswith ".crypto"
    or FileName endswith ".enc"
    or FileName endswith ".ransom"
    or FileName endswith ".wnry"
    or FileName endswith ".wncry"
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
- **Hit found:** No results
- **Verdict:** Expected baseline — no ransomware file encryption observed
- **Notes:** Query validated against live MDE P2 telemetry on Windows 11 Pro

## Tuning Notes
- Any hit on this query requires immediate incident response — isolate the device
- Extend the extension list with newly observed ransomware extensions
- Correlate with DeviceNetworkEvents to identify C2 communication prior to encryption
- Correlate with DeviceLogonEvents to identify the compromised account

## References
- [MITRE ATT&CK T1486](https://attack.mitre.org/techniques/T1486/)
- [Microsoft Defender Advanced Hunting Schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)
