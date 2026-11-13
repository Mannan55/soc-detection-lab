# SOC Detection Engineering Laboratory

<p align="left">
  <strong>Detection-as-Code (DaC) Research, Rule Testing, and SOC Investigation Laboratory</strong><br>
  <em>Author: Mannan Shah (<a href="https://github.com/Mannan55">@Mannan55</a>) • Focus: Security Operations Center, Detection Engineering, and Telemetry Validation</em>
</p>

<p align="left">
  <img src="https://img.shields.io/badge/CI-Automated%20Verification-success" alt="CI Status" />
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/Framework-Sigma%20Standard-orange" alt="Sigma Standard" />
  <img src="https://img.shields.io/badge/Threat%20Model-MITRE%20ATT%26CK-red" alt="MITRE ATT&CK" />
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" />
</p>

---

## 1. Overview and Engineering Objective

Modern Security Operations Centers treat detection engineering with software development rigor: treating detection rules as code, testing them against positive and negative telemetry fixtures, and preventing detection drift via automated continuous integration.

This laboratory provides an end-to-end **Detection-as-Code (DaC)** workflow:
1. Threat intelligence research mapped to the **MITRE ATT&CK** matrix.
2. Standardized **Sigma** rule authoring with explicit log source definitions and false-positive boundaries.
3. Realistic synthetic telemetry fixtures representing both hostile adversary behavior (true positives) and benign operational noise (false positives).
4. Adversarial evasion resilience testing (carets, backticks, case variation, and irregular whitespace).
5. Automated **pytest** regression testing verifying zero false negatives and documented baseline immunity.
6. Actionable analyst investigation playbooks and reproducible incident case studies.

---

## 2. Laboratory Architecture

```text
       Adversary TTPs (MITRE ATT&CK)
                     |
                     v
            Sigma Rule Authoring
          (rules/windows/ & rules/linux/)
                     |
                     +---------------------------------+
                     |                                 |
                     v                                 v
          Positive Attack Telemetry         Negative Benign Telemetry
          (Must trigger alert: 100%)       (Must NOT trigger alert: 0%)
                     |                                 |
                     +----------------+----------------+
                                      |
                                      v
                        Automated Pytest CI Engine
                         (engine/rule_matcher.py)
                                      |
                                      v
                       SOC Alert & Investigation Playbook
                               (playbooks/)
                                      |
                                      v
                        End-to-End Case Studies
                             (case_studies/)
```

---

## 3. Implemented Detection Rules Matrix

| Scenario | Platform | MITRE ATT&CK | Telemetry Source | Rule Specification | Playbook Reference |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Suspicious Encoded PowerShell** | Windows | T1059.001 (PowerShell)<br>T1027 (Obfuscation) | Security Event 4688 / Sysmon 1 | [`rules/windows/...`](rules/windows/proc_creation_win_powershell_suspicious_encoded.yml) | [`playbooks/...`](playbooks/win_t1059_encoded_powershell.md) |
| **Windows Authentication Brute-Force** | Windows | T1110.001 (Password Guessing)<br>T1110.003 (Password Spraying) | Security Event 4625 | [`rules/windows/...`](rules/windows/win_auth_failed_logon_bruteforce.yml) | [`playbooks/...`](playbooks/win_t1110_account_bruteforce.md) |
| **Suspicious Account Creation** | Windows | T1136.001 (Local Account)<br>T1136.002 (Domain Account) | Security Event 4720 | [`rules/windows/...`](rules/windows/win_account_creation_suspicious.yml) | [`playbooks/...`](playbooks/win_t1136_suspicious_account_creation.md) |
| **Sudo Privilege Abuse (GTFOBins)** | Linux | T1548.003 (Sudo Caching)<br>T1078 (Valid Accounts) | Linux `/var/log/auth.log` / Syslog | [`rules/linux/...`](rules/linux/sys_auth_linux_sudo_privilege_abuse.yml) | [`playbooks/...`](playbooks/linux_t1548_sudo_privilege_abuse.md) |
| **Linux SSH Authentication Attack** | Linux | T1110.001 (Password Guessing)<br>T1021.004 (SSH) | Linux `/var/log/auth.log` / `sshd` | [`rules/linux/...`](rules/linux/sys_auth_linux_ssh_bruteforce.yml) | [`playbooks/...`](playbooks/linux_t1110_ssh_attack.md) |

---

## 4. Evidence-Based SOC Investigation Case Studies

Comprehensive incident investigation walkthroughs with full synthetic telemetry streams:

* **[Case Study 001: Windows Enterprise Multi-Stage Intrusion](case_studies/case_001_windows_enterprise_intrusion.md):**  
  Chronological recreation of an attack progressing from external RDP brute-forcing (Event 4625) to backdoor account creation (Event 4720) and hidden encoded PowerShell cradle execution (Event 4688). Includes triage steps, SIEM query logic, and containment procedures.

* **[Case Study 002: Linux DMZ Server Compromise](case_studies/case_002_linux_dmz_compromise.md):**  
  Incident investigation covering automated SSH brute-force credential attacks, compromised service account triage, and root privilege escalation via sudo GTFOBins execution.

---

## 5. Detection Quality and Coverage Reporting

Comprehensive coverage analytics, MITRE mapping tables, and synthetic validation scores are automatically maintained in the project documentation:

* **Full Report:** [Detection Quality and Coverage Report](docs/DETECTION_QUALITY_REPORT.md)
* **Rule Engine Specification:** [Sigma Specification Document](docs/SIGMA_SPECIFICATION.md)

### Synthetic Validation Summary

| Metric | Laboratory Fixtures Result | Enterprise Production Note |
| :--- | :--- | :--- |
| **True Positive Rate (TPR)** | 100.0% | Baseline expectations: ~92-96% depending on host log pipeline health |
| **False Positive Rate (FPR)** | 0.0% | Driven by environment-specific baseline tuning and admin behavior |
| **False Negative Rate (FNR)** | 0.0% | Layered defenses required for advanced binary unhooking or crypters |

---

## 6. Verification and Test Suite

The laboratory includes an automated test harness executing in GitHub Actions:
* **True Positive Rate:** 100% of malicious attack samples trigger alerts with matching severity and MITRE tags.
* **False Positive Immunity:** 0% of benign operational logs trigger alerts.
* **Adversarial Resilience:** Verifies detection resilience against caret escaping (`p^o^w^e^r`), backticks, casing, and whitespace padding.
* **Multi-Stage Correlation:** Validates chronological event stream detection across full kill-chain intrusions.
* **Sigma Schema Conformance:** Validates YAML structure, UUID format, and metadata completeness.
* **Typography Enforcement:** Automated test strictly prohibiting Unicode em dashes (`U+2014`).

### Running Tests Locally

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Execute full validation suite
pytest -v

# 3. Check detection quality metrics report
python scripts/generate_detection_metrics.py --check
```

---

## 7. Directory Structure

```text
soc-detection-lab/
├── .github/
│   └── workflows/
│       └── ci.yml             # Automated CI pipeline
├── case_studies/              # Detailed SOC incident investigations
├── docs/
│   ├── DETECTION_QUALITY_REPORT.md # Automated metrics and coverage report
│   └── SIGMA_SPECIFICATION.md # Supported Sigma engine specification
├── engine/
│   ├── __init__.py
│   ├── parser.py              # Log normalizer for Windows and Linux telemetry
│   └── rule_matcher.py        # Resilient Sigma pattern matching engine
├── playbooks/                 # Analyst investigation guides (Tier-1 and Tier-2 triage)
├── rules/
│   ├── windows/               # Windows detection rules
│   └── linux/                 # Linux detection rules
├── scripts/
│   └── generate_detection_metrics.py # Automated metric reporting script
├── telemetry/
│   ├── case_studies/          # Chronological multi-stage attack streams
│   ├── windows/               # Positive and negative Windows test logs
│   └── linux/                 # Positive and negative Linux test logs
├── tests/                     # Automated pytest validation suite
├── requirements.txt
└── README.md
```

---

## 8. License

This project is licensed under the [MIT License](LICENSE).
