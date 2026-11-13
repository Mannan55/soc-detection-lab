# SOC Incident Investigation Playbook: Suspicious Encoded PowerShell Execution

**Rule ID:** `a8b1c2d3-e4f5-4678-90ab-cdef12345678`  
**MITRE ATT&CK Techniques:** T1059.001 (Command and Scripting Interpreter: PowerShell), T1027 (Obfuscated Files or Information)  
**Tactic:** Execution, Defense Evasion  
**Default Severity:** High  

---

## 1. Overview and Threat Context

Adversaries frequently leverage `powershell.exe` with base64 encoding (`-enc`, `-encodedcommand`) and hidden window flags (`-w hidden`, `-nop`) to bypass basic command-line auditing and execute in-memory download cradles, Cobalt Strike beacons, or reconnaissance scripts.

While base64 encoding is occasionally used by enterprise deployment utilities, interactive or unexpected encoded executions from user directories or unprivileged parent processes represent high-fidelity attack indicators.

---

## 2. Tier 1 Initial Triage Checklist

When an alert triggers, complete the following validation steps within 15 minutes:

1. **Extract and Decode the Command Line:**
   - Locate the base64 string following the `-enc` or `-encodedcommand` flag.
   - Decode using CyberChef or PowerShell:
     ```powershell
     [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("BASE64_STRING"))
     ```
   - Analyze decoded contents for web download calls (`DownloadString`, `Invoke-WebRequest`, `Net.WebClient`), process injection, or reflective DLL loading.

2. **Verify Parent Process Lineage:**
   - Check `ParentProcessName` (Event ID 4688).
   - Suspicious parents: `cmd.exe`, `excel.exe`, `winword.exe`, `wscript.exe`, `cscript.exe`, `wmiprvse.exe`.
   - Benign administrative parents: Known deployment agents under `C:\Program Files\`.

3. **Analyze User Context and Host Role:**
   - Is `TargetUserName` a standard user account or a service account?
   - Is the executing endpoint an administrative workstation, domain controller, or standard user laptop?

4. **Correlate Network Telemetry:**
   - Query firewall, proxy, or EDR telemetry for outbound HTTP/S or anomalous TCP connections initiated by the `ProcessId` within +/- 5 minutes of execution.

---

## 3. Tier 2 Deep Dive Investigation

If initial triage indicates unapproved or hostile execution:

1. **Query PowerShell Script Block Logs (Event ID 4104):**
   - Inspect Microsoft-Windows-PowerShell/Operational log for the deobfuscated script block content.
2. **Inspect Child Processes:**
   - Did `powershell.exe` spawn child binaries such as `rundll32.exe`, `regsvr32.exe`, `certutil.exe`, or `whoami.exe`?
3. **Check Persistence Mechanisms:**
   - Check for newly registered Scheduled Tasks (`Event ID 4698`) or Registry Run key modifications (`Event ID 4657`).

---

## 4. Containment and Remediation

1. **Immediate Process Termination:**
   - Terminate the suspicious PowerShell process tree by PID.
2. **Host Isolation:**
   - If external C2 communication or credential dumping is observed, isolate the host from the network immediately via EDR or network switch port VLAN quarantine.
3. **Credential Invalidation:**
   - Reset credentials for the compromised user account.
4. **Artifact Eradication:**
   - Remove any downloaded payloads, scheduled tasks, or persistence artifacts identified during investigation.

---

## 5. False Positive Tuning

* **Known Admin Tools:** If genuine enterprise tools utilize encoded PowerShell commands, create targeted exclusion filters specifying both the full parent binary path and the exact signing certificate.
