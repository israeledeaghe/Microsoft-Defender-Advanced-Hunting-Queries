# Attack Simulations

This folder documents MITRE ATT&CK technique simulations performed against a live Windows 11 Pro endpoint onboarded to Microsoft Defender for Endpoint Plan 2.

## Environment
- **Target:** Windows 11 Pro (israels-pc)
- **Tool:** Atomic Red Team v2.3.0 + Manual simulation
- **Date:** July 2026
- **Purpose:** Validate KQL detection queries against real attack telemetry

## Simulations Performed

| Technique | Name | Method | Outcome |
|-----------|------|--------|---------|
| T1059.001 | PowerShell Encoded Command | Manual — powershell.exe -EncodedCommand | Blocked by Defender — telemetry captured |
| T1053.005 | Scheduled Task Creation | schtasks.exe /create | Successfully executed — telemetry captured |
| T1547.001 | Registry Run Key Persistence | reg add HKCU\...\Run | Successfully executed — telemetry captured |
| T1136.001 | Local Account Creation | net user /add | Successfully executed — telemetry captured |

## Key Finding — Defender Detection in Action

During simulation of T1059.001 (PowerShell Encoded Command), Microsoft Defender 
for Endpoint identified and blocked the execution, generating a real-time alert:

**"Unwanted enterprise application removed"**

This is a significant finding — it demonstrates that:
1. The MDE sensor is actively monitoring process execution in real time
2. Defender's behavioural engine detected the encoded command technique
3. The custom detection rule AND Defender's built-in protection both fired simultaneously

This validates the defence-in-depth principle — custom KQL detection rules provide 
an additional layer of visibility on top of Defender's built-in protection.

## Commands Executed

```powershell
# T1059.001 - PowerShell Encoded Command (Base64 encoded "whoami")
powershell.exe -EncodedCommand "dwBoAG8AYQBtAGkA" -WindowStyle Hidden -NoProfile

# T1053.005 - Scheduled Task Creation
schtasks.exe /create /tn "AtomicRedTeam-T1053" /tr "cmd.exe /c whoami" /sc onlogon /ru "System" /f

# T1547.001 - Registry Run Key Persistence
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AtomicTest" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f

# T1136.001 - Local Account Creation
net user AtomicTestUser P@ssw0rd123! /add
```

## Cleanup Commands Executed

```powershell
schtasks.exe /delete /tn "AtomicRedTeam-T1053" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AtomicTest" /f
net user AtomicTestUser /delete
```

## Lessons Learned

1. **Defender blocks known attack tools aggressively** — Atomic Red Team tests 
   involving Mimikatz were blocked immediately, demonstrating Defender's 
   effectiveness against known malware signatures

2. **Manual simulation generates cleaner telemetry** — Hand-crafted attack 
   commands using native Windows binaries (schtasks, reg, net) successfully 
   bypassed signature-based detection while still being captured by MDE telemetry

3. **Defence in depth works** — Custom KQL detection rules provide visibility 
   into techniques that Defender's built-in protection may not alert on, and 
   vice versa

4. **Telemetry ingestion lag is real** — MDE telemetry can take 15-40 minutes 
   to appear in Advanced Hunting, which is a critical consideration for 
   real-time SOC operations
