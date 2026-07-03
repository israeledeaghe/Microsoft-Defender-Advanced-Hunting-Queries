# Attack Simulations

This folder documents MITRE ATT&CK technique simulations performed against a live Windows 11 Pro endpoint onboarded to Microsoft Defender for Endpoint Plan 2.

## Environment
- **Target:** Windows 11 Pro (israels-pc)
- **Tool:** Atomic Red Team v2.3.0
- **Date:** July 2026
- **Purpose:** Validate KQL detection queries against real attack telemetry

## Simulations Performed

| Technique | Name | Tool Used | Detection Fired |
|-----------|------|-----------|-----------------|
| T1059.001 | PowerShell Encoded Command | Manual PowerShell | Yes |
| T1053.005 | Scheduled Task Creation | schtasks.exe | Yes |
| T1547.001 | Registry Run Key Persistence | reg.exe | Yes |
| T1136.001 | Local Account Creation | net.exe | Yes |

## Cleanup
All test artifacts were removed after simulation:
- Scheduled task `AtomicRedTeam-T1053` deleted
- Registry key `AtomicTest` deleted
- User account `AtomicTestUser` deleted
