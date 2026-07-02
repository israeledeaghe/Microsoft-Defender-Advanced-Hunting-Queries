# Shadow Copy Deletion - Ransomware Pre-Encryption Indicator

**MITRE Technique:** T1490 - Inhibit System Recovery  
**MITRE Tactic:** TA0040 - Impact  
**Severity:** Critical  
**False Positive Rate:** Low  

## Description
Detects deletion of Windows Volume Shadow Copies via vssadmin.exe, wmic.exe, or PowerShell. Shadow copy deletion is one of the most reliable ransomware pre-encryption indicators — attackers delete backups to prevent victims from recovering files without paying the ransom. Any hit on this query requires immediate incident response.

## KQL Query
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("vssadmin.exe", "wmic.exe", "powershell.exe")
| where ProcessCommandLine has_any (
    "delete shadows",
    "shadowcopy delete",
    "resize shadowstorage",
    "Delete Shadows /All",
    "Win32_ShadowCopy"
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
- **Verdict:** Expected baseline — no shadow copy deletion observed
- **Notes:** Query validated against live MDE P2 telemetry on Windows 11 Pro

## Tuning Notes
- Any hit on this query requires immediate device isolation and incident response
- Correlate with T1486 ransomware file extension query for full picture
- Check DeviceProcessEvents for ransomware binary execution in the same timeframe

## References
- [MITRE ATT&CK T1490](https://attack.mitre.org/techniques/T1490/)
- [Microsoft Defender Advanced Hunting Schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
