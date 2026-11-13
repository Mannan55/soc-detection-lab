# SOC Investigation Playbook: Windows Authentication Brute-Force (Event 4625)

## Overview
- **Rule ID:** `d7e8b91a-4c2f-4a3b-9801-6f23d5a49811`
- **Severity:** High
- **ATT&CK Tactic:** Credential Access (TA0006)
- **ATT&CK Techniques:** 
  - T1110: Brute Force
  - T1110.001: Password Guessing
  - T1110.003: Password Spraying
- **Target Event:** Windows Security Event ID 4625 (Logon Failure)

---

## Technical Context
Windows Security Event ID 4625 is generated whenever a logon request fails. During an active brute-force or password spray attack, an adversary submits repeated authentication requests across network protocols (Logon Type 3: SMB, WinRM, RPC) or remote desktop endpoints (Logon Type 10: RDP).

Key status and sub-status codes provide critical triage telemetry:
- `0xC000006A`: Bad user password (user exists, incorrect secret).
- `0xC0000064`: User name does not exist (potential account enumeration or dictionary sweep).
- `0xC0000234`: User account locked out (account lockout threshold triggered).

---

## Triage and Investigation Steps

### Step 1: Initial Telemetry Extraction
1. Extract the `IpAddress` (source workstation/IP), `WorkstationName`, and `TargetUserName`.
2. Inspect the `LogonType`:
   - `LogonType 10`: Direct RDP attempt.
   - `LogonType 3`: Network logon over SMB, WMI, or remote services.
3. Check the failure velocity (events per minute):
   - Fast bursts (>10 attempts/sec from single IP): Automated brute-force tool (Hydra, Crowbar, Ncrack).
   - Slow cadence (1 attempt per user every 30 mins): Low-and-slow password spray designed to bypass lockout thresholds.

### Step 2: Scope Assessment and Correlation
1. Query SIEM for successful logons (`Event ID 4624`) from the same source IP within +/- 2 hours:
   - If a 4624 success follows multiple 4625 failures for the same user: **Confirmed Account Compromise**.
2. Identify blast radius:
   - How many distinct user accounts were targeted by the source IP?
   - Are privileged accounts (Domain Admins, Enterprise Admins, SQL Service) in the target list?
3. Check threat intelligence feeds for the external source IP reputation.

---

## Containment Actions

1. **Network Layer Isolation:**
   - Immediately apply edge firewall or perimeter ACL drop rules for the offending external IP address.
   - For internal source IPs, isolate the originating host using EDR host isolation.
2. **Identity Layer Containment:**
   - If Event 4624 was observed for any targeted account, immediately disable the user account in Active Directory or Azure AD.
   - Terminate all active Kerberos ticket granting tickets (TGTs) and revoke refresh tokens.
   - Force an out-of-band password reset with MFA requirement.

---

## Eradication and Recovery

1. Audit all post-authentication activity under the compromised account (process creation Event 4688, PowerShell execution Event 4104, privilege escalation Event 4672).
2. Scan the source host for persistence mechanisms (scheduled tasks, run keys, remote access tools).
3. If internet-facing RDP (port 3389) or SMB (port 445) was accessible, restrict remote access behind a secure VPN with mandatory MFA.
4. Document root cause and report incident metrics to senior SOC management.
