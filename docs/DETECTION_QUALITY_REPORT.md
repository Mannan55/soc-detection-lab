# Detection Quality and Coverage Report

## Executive Summary
This report provides an automated assessment of detection coverage, rule metadata integrity,
MITRE ATT&CK technique mapping, and synthetic laboratory validation metrics for the SOC Detection Lab.

> [!IMPORTANT]
> **Telemetry Scope Disclaimer:** All True Positive Rate (TPR), False Positive Rate (FPR),
> and False Negative Rate (FNR) metrics documented below reflect deterministic validation
> across synthetic laboratory test fixtures. Enterprise production environments exhibit
> broader operational noise, varied logging pipelines, and environmental nuances.

## Detection Rule Inventory Metrics

- **Total Active Sigma Rules:** 5
- **Windows Coverage Rules:** 3
- **Linux Coverage Rules:** 2
- **Unique MITRE ATT&CK Techniques:** 10
- **Unique MITRE ATT&CK Tactics:** 6

### Severity Distribution

| Severity Level | Rule Count | Percentage |
| :--- | :--- | :--- |
| Critical | 0 | 0.0% |
| High | 4 | 80.0% |
| Medium | 1 | 20.0% |
| Low | 0 | 0.0% |

## MITRE ATT&CK Coverage Breakdown

### Tactics Represented
- Credential Access
- Defense Evasion
- Execution
- Lateral Movement
- Persistence
- Privilege Escalation

### Techniques Mapped
- T1021.004
- T1027
- T1059.001
- T1110
- T1110.001
- T1110.003
- T1136
- T1136.001
- T1136.002
- T1548.003

## Synthetic Validation Performance

| Metric | Laboratory Fixtures Result | Production Enterprise Efficacy Note |
| :--- | :--- | :--- |
| **True Positive Rate (TPR)** | 100.0% (All positive fixtures detected) | Baseline expectations: ~92-96% depending on logging reliability |
| **False Positive Rate (FPR)** | 0.0% (Zero false alerts on negative fixtures) | Dependent on organizational software baselines and admin behavior |
| **False Negative Rate (FNR)** | 0.0% (No undetected test attacks) | Evasion techniques (e.g. unhooking, custom crypters) require layered defense |

## Comprehensive Rule Catalog

| Rule Title | Platform | Severity | Primary Technique | Rule File |
| :--- | :--- | :--- | :--- | :--- |
| Linux Sudo Privilege Abuse via Suspicious Binaries | Linux | High | T1548.003 | [`rules/linux/sys_auth_linux_sudo_privilege_abuse.yml`](../rules/linux/sys_auth_linux_sudo_privilege_abuse.yml) |
| Potential Linux SSH Authentication Brute-Force or Dictionary Attack | Linux | High | T1110 | [`rules/linux/sys_auth_linux_ssh_bruteforce.yml`](../rules/linux/sys_auth_linux_ssh_bruteforce.yml) |
| Potential Windows Authentication Brute-Force or Password Spray | Windows | High | T1110 | [`rules/windows/win_auth_failed_logon_bruteforce.yml`](../rules/windows/win_auth_failed_logon_bruteforce.yml) |
| Suspicious Encoded PowerShell Process Execution | Windows | High | T1059.001 | [`rules/windows/proc_creation_win_powershell_suspicious_encoded.yml`](../rules/windows/proc_creation_win_powershell_suspicious_encoded.yml) |
| Suspicious Local or Domain Account Creation | Windows | Medium | T1136 | [`rules/windows/win_account_creation_suspicious.yml`](../rules/windows/win_account_creation_suspicious.yml) |
