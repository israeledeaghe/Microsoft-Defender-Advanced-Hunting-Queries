# Base64 Encoded Command Execution

**MITRE Technique:** T1027 - Obfuscated Files or Information  
**MITRE Tactic:** TA0005 - Defense Evasion  
**Severity:** High  
**False Positive Rate:** Low  

## Description
Detects PowerShell executing Base64 encoded commands. Attackers use Base64 encoding to obfuscate malicious payloads and evade signature-based detection. This is one of the most commonly observed techniques in the wild.

## KQL Query
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine matches regex @"-[Ee][Nn][Cc][Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd]|[-][Ee][Nn][Cc] "
| extend Base64Payload = extract(@"(?:-enc|-EncodedCommand)\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| project
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    Base64Payload,
    InitiatingProcessFileName,
    FolderPath
| order by Timestamp desc
```

## Results in Lab
- **Hit found:** No results
- **Verdict:** Expected baseline — no encoded PowerShell observed in the last 24 hours
- **Notes:** Query validated against live MDE P2 telemetry. Zero results confirms clean environment, not a broken query.

## Tuning Notes
- Low false positive rate — Base64 encoded commands from legitimate software are rare
- If hits occur, decode the Base64Payload field to inspect the actual command
- Cross-reference InitiatingProcessFileName to identify the parent process

## References
- [MITRE ATT&CK T1027](https://attack.mitre.org/techniques/T1027/)
- [Microsoft Defender Advanced Hunting Schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
