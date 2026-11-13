# SOC Incident Investigation Playbook: Linux Sudo Privilege Abuse via Suspicious Binaries

**Rule ID:** `b9c2d3e4-f5a6-4789-91bc-def012345679`  
**MITRE ATT&CK Technique:** T1548.003 (Abuse Elevation Control Mechanism: Sudo and Sudo Caching)  
**Tactic:** Privilege Escalation, Defense Evasion  
**Default Severity:** High  

---

## 1. Overview and Threat Context

Linux sudo configuration weaknesses often grant unprivileged users access to execute standard administrative utilities with root permissions. Attackers exploit known GTFOBins patterns in binaries like `find`, `vim`, `less`, `awk`, or `bash -p` to escape constrained shells or execute arbitrary root-level shell sessions without credential verification.

---

## 2. Tier 1 Initial Triage Checklist

When an alert triggers, execute the following triage steps within 15 minutes:

1. **Verify Sudo Command Parameters:**
   - Inspect the exact command executed:
     - `find . -exec /bin/sh -p \;`: Direct interactive shell escape.
     - `vim -c :!/bin/sh`: Shell breakout via editor escape commands.
     - `less /etc/shadow`: Unauthorized credential read attempt.
2. **Determine Authentication Origin:**
   - Cross-reference `/var/log/auth.log` or syslog for recent SSH logins matching `User`.
   - Was the login from an internal management IP, VPN gateway, or unexpected external subnet?
3. **Inspect Sudoers Configuration:**
   - Review `/etc/sudoers` and `/etc/sudoers.d/*` entries for the user:
     - Is the user granted `NOPASSWD` access to interactive binaries?

---

## 3. Tier 2 Deep Dive Investigation

1. **Inspect Auditd System Call Logs:**
   - Query `ausearch -m EXECVE -ts recent` to identify child processes spawned by the sudo command.
   - Look for interactive `/bin/sh` or `/bin/bash` child processes with `euid=0` (root).
2. **Review User Shell History:**
   - Inspect `~/.bash_history` and `/root/.bash_history` for attacker post-exploitation reconnaissance (for example: `cat /etc/shadow`, `useradd`, `curl http://...`).
3. **Check for Created Backdoors:**
   - Verify `/root/.ssh/authorized_keys` for unauthorized SSH public keys.
   - Check cron directories (`/etc/cron.*`, `/var/spool/cron/crontabs`) for newly scheduled cron jobs.

---

## 4. Containment and Remediation

1. **Terminate Active Attacker Sessions:**
   - Identify the attacker pseudo-terminal (`pts/X`) and terminate processes:
     ```bash
     pkill -u <username>
     ```
2. **Lock Compromised Account:**
   - Prevent immediate re-authentication:
     ```bash
     usermod -L <username>
     ```
3. **Remediate Sudoers Permissions:**
   - Remove interactive binaries (`find`, `vim`, `less`, `awk`, `python`) from `sudoers` files.
   - Restrict permissions to non-interactive command arguments or custom wrapper scripts.
4. **Credential Rotation:**
   - Rotate all root SSH keys and local administrative passwords across the server fleet.

---

## 5. False Positive Tuning

* If developers legitimately require text editors on development machines, restrict root editing to tools that do not permit shell escapes (such as `sudoedit`), which creates a safe temporary file copy rather than running the editor as root.
