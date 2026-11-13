# SOC Investigation Playbook: Linux SSH Authentication Attack

## Overview
- **Rule ID:** `e3a1f82b-9c4d-4b82-95f3-7801a2d59642`
- **Severity:** High
- **ATT&CK Tactic:** Credential Access (TA0006), Lateral Movement (TA0008)
- **ATT&CK Techniques:** 
  - T1110: Brute Force
  - T1110.001: Password Guessing
  - T1110.003: Password Spraying
  - T1021.004: Remote Services (SSH)
- **Target Logs:** Linux `/var/log/auth.log`, `/var/log/secure`, systemd journal (`sshd`)

---

## Technical Context
SSH (port 22) exposed to untrusted networks experiences near-continuous scanning and automated brute-force attempts. Adversaries use wordlists and automated tools (Paramiko scripts, Hydra, Medusa) to guess passwords or find default credentials for accounts such as `root`, `admin`, `ubuntu`, and `oracle`.

Key syslog indicators:
- `Failed password for root`: Direct attempt against highest-privilege account.
- `Failed password for invalid user <user>`: Enumeration of non-existent usernames.
- `Accepted password` or `Accepted publickey`: Successful authentication. A success occurring immediately after repeated failures strongly indicates compromised credentials.

---

## Triage and Investigation Steps

### Step 1: Volume and Pattern Analysis
1. Extract `source_ip`, `user`, and timestamp sequence from alerts.
2. Determine connection volume and failure rate:
   - High volume (>50 attempts within 5 minutes): High-velocity dictionary brute force.
   - Low volume (1 to 3 attempts every hour): Low-and-slow password spray across common service accounts.
3. Check if multiple internal servers report attacks from the same IP (evidence of internal lateral movement).

### Step 2: Critical Compromise Verification
1. Run a log query to check for any `Accepted` events from the source IP:
   ```bash
   grep "Accepted" /var/log/auth.log | grep "<ATTACKER_IP>"
   ```
2. If `Accepted` is found:
   - **Immediate Escalation:** Active unauthorized access confirmed.
   - Identify the compromised user account and terminal session.
   - Run `who`, `w`, or `last` on the affected host to locate active sessions.

### Step 3: Blast Radius and Post-Exploitation Triage
1. Inspect commands run by the compromised user via bash history, `auditd`, or `/var/log/syslog`.
2. Inspect for unauthorized SSH keys added to `~/.ssh/authorized_keys`.
3. Check for privilege escalation attempts (`sudo` commands, SUID binary exploitation).

---

## Containment Actions

1. **Firewall Drop Rule:**
   - Block offending source IP on the host level using `iptables` or `nftables`:
     ```bash
     sudo iptables -I INPUT -s <ATTACKER_IP> -j DROP
     ```
   - Push edge firewall ACL update to block the IP perimeter-wide.
2. **Session Termination:**
   - If an active session exists, kill the associated process tree:
     ```bash
     sudo pkill -KILL -u <COMPROMISED_USER>
     ```
3. **Account Locking:**
   - Lock compromised account password:
     ```bash
     sudo passwd -l <COMPROMISED_USER>
     ```

---

## Hardening and Eradication

1. Ensure SSH password authentication is disabled (`PasswordAuthentication no` in `/etc/ssh/sshd_config`).
2. Enforce key-based authentication with Ed25519 or RSA-4096 keys.
3. Prohibit direct root logins over SSH (`PermitRootLogin no`).
4. Enable automated rate-limiting protection such as `fail2ban` or host-based security agents.
5. Move SSH listening port away from default 22 or restrict port access via zero-trust VPN or bastion bastion hosts.
