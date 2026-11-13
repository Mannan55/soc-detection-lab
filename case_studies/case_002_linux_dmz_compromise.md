# SOC Case Study 002: Linux DMZ Server Compromise and Privilege Escalation

## Executive Summary
This case study documents an incident investigation of an external intrusion against a Linux DMZ web server. The threat actor executed an automated SSH brute-force attack to compromise a developer account, followed by immediate privilege escalation to root through sudo GTFOBins abuse of the `find` binary.

---

## Intrusion Timeline and Kill Chain Mapping

| Time (UTC) | Kill Chain Phase | MITRE ATT&CK | Observed Activity | Event Telemetry |
| :--- | :--- | :--- | :--- | :--- |
| 16:00:10 | Credential Access | T1110.001, T1021.004 | SSH brute-force attack against root | `/var/log/auth.log` (`Failed password for root`) |
| 16:00:22 | Discovery & Spray | T1110.003 | SSH username sweep targeting admin | `/var/log/auth.log` (`Failed password for invalid user admin`) |
| 16:05:45 | Privilege Escalation | T1548.003 | Interactive root shell spawned via sudo find | `/var/log/auth.log` (`COMMAND=/usr/bin/find . -exec /bin/sh \; -quit`) |

---

## Detailed Technical Analysis

### Phase 1: External SSH Credential Attack
- **Source IP:** `198.51.100.20`
- **Target Port:** `22` (SSH)
- **Target Accounts:** `root`, `admin`
- **Detection Trigger:** Rule `e3a1f82b-9c4d-4b82-95f3-7801a2d59642` (Potential Linux SSH Authentication Brute-Force)
- **Telemetry Indicators:** Rapid sequence of authentication failures in `/var/log/auth.log` within 12 seconds.
- **Analyst Action:** Queried firewall netflow to determine session duration and byte counts.

### Phase 2: Sudo GTFOBins Privilege Escalation
- **Compromised Account:** `webdev`
- **Target Privilege:** `root` (UID 0)
- **Executed Command:** `sudo /usr/bin/find . -exec /bin/sh \; -quit`
- **Working Directory:** `/var/www/html`
- **Detection Trigger:** Rule `b9c2d3e4-f5a6-4789-91bc-def012345679` (Suspicious Sudo Privilege Escalation via GTFOBins)
- **Telemetry Indicators:** Sudoers configuration had allowed `/usr/bin/find` without password prompt, which allows immediate execution of arbitrary commands via `-exec`.
- **Analyst Action:** Confirmed child process `/bin/sh` spawned under root UID via auditd process tracking.

---

## SOC Containment and Remediation Checklist

1. **Session Termination:**
   - Terminated rogue interactive root shell (`pkill -KILL -t pts/1`).
   - Terminated all active connections associated with account `webdev`.
2. **Network Perimeter Isolation:**
   - Blocked attacker IP `198.51.100.20` on border router and host `iptables`.
3. **Sudoers File Remediation:**
   - Audited `/etc/sudoers` and `/etc/sudoers.d/`:
     ```text
     # REMOVED INSECURE DIRECTIVE:
     # webdev ALL=(ALL) NOPASSWD: /usr/bin/find
     ```
   - Enforced strict least-privilege administrative access controls.
4. **Credential and Key Revocation:**
   - Locked password for account `webdev` (`passwd -l webdev`).
   - Cleared and regenerated all SSH keys in `/home/webdev/.ssh/authorized_keys`.
5. **Hardening Posture:**
   - Disabled root SSH logins (`PermitRootLogin no`).
   - Bound SSH access strictly to internal management VPN.
