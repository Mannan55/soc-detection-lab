# SOC Investigation Playbook: Suspicious Windows Account Creation (Event 4720)

## Overview
- **Rule ID:** `b4a2c918-1e5f-4a3d-8210-9f5b3c4d7e21`
- **Severity:** Medium
- **ATT&CK Tactic:** Persistence (TA0003)
- **ATT&CK Techniques:** 
  - T1136: Create Account
  - T1136.001: Local Account
  - T1136.002: Domain Account
- **Target Event:** Windows Security Event ID 4720 (A user account was created)

---

## Technical Context
Adversaries establish persistence or maintain access across an enterprise by creating new local or domain user accounts. Once an account is created, attackers frequently elevate it by adding it to privileged security groups such as `Administrators` (Event 4728 / 4732) or `Remote Desktop Users`.

Key fields to examine in Event 4720:
- `TargetUserName`: The name of the newly created account.
- `SubjectUserName`: The identity of the user or process that executed the creation.
- `SubjectDomainName`: Domain origin of the creator.
- `TargetSid`: Unique Security Identifier assigned to the new user.

---

## Triage and Investigation Steps

### Step 1: Change Ticket and Authorization Verification
1. Check the enterprise change management system (ServiceNow, Jira) for an approved user onboarding ticket matching `TargetUserName`.
2. Inspect `SubjectUserName`:
   - Is it an automated provisioning tool (e.g., Azure AD Connect, Okta, SCCM)?
   - Is it an authorized IT Helpdesk administrator?
   - Is it a compromised standard user, service account, or unexpected local administrator?

### Step 2: Immediate Telemetry Correlation
1. Query SIEM for group membership modification events within 15 minutes of creation:
   - `Event ID 4728`: Member added to security-enabled global group.
   - `Event ID 4732`: Member added to security-enabled local group.
   - High alert if the user is added to `BUILTIN\Administrators` or `Domain Admins`.
2. Query for password reset or enable events:
   - `Event ID 4724`: Attempt was made to reset an account's password.
   - `Event ID 4722`: User account was enabled.
3. Review process creation logs (`Event ID 4688` or Sysmon 1) on the machine where the creation occurred:
   - Were commands such as `net user <name> <password> /add` or `New-LocalUser` executed from `cmd.exe` or `powershell.exe`?

---

## Containment Actions

1. **Immediate Account Disablement:**
   - Immediately disable the created account in Active Directory or the local SAM database:
     ```powershell
     Disable-ADAccount -Identity "<TargetUserName>"
     # Or locally:
     net user "<TargetUserName>" /active:no
     ```
2. **Revoke Permissions:**
   - Remove the account from any privileged groups.
3. **Isolate Creator Session:**
   - If the account creation was unauthorized, assume the `SubjectUserName` account is compromised.
   - Reset the creator's credentials, revoke all active tokens/Kerberos TGTs, and terminate active RDP/SSH sessions.

---

## Eradication and Recovery

1. Perform forensic triage on the host where the creation command was issued. Look for web shells, reverse shells, or remote management tooling.
2. Review audit logs for any actions executed under the new account between creation and containment.
3. Verify that all domain controllers and member servers have Event ID 4720 auditing enabled under Advanced Audit Policy Configuration.
