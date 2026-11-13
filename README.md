# SOC Detection Engineering Laboratory

<p align="left">
  <strong>Detection-as-Code (DaC) Research and Rule Testing Environment</strong><br>
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
4. Automated **pytest** regression testing verifying zero false negatives and documented baseline immunity.
5. Actionable analyst investigation playbooks for Tier-1 and Tier-2 triage.

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
```

---

## 3. Implemented Detection Rules Matrix

| Scenario | Platform | MITRE ATT&CK | Telemetry Source | Rule Specification | Playbook Reference |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Suspicious Encoded PowerShell** | Windows | T1059.001 (PowerShell)<br>T1027 (Obfuscation) | Security Event 4688 / Sysmon 1 | [`rules/windows/...`](rules/windows/proc_creation_win_powershell_suspicious_encoded.yml) | [`playbooks/...`](playbooks/win_t1059_encoded_powershell.md) |
| **Sudo Privilege Abuse (GTFOBins)** | Linux | T1548.003 (Sudo Caching)<br>T1078 (Valid Accounts) | Linux `/var/log/auth.log` / Syslog | [`rules/linux/...`](rules/linux/sys_auth_linux_sudo_privilege_abuse.yml) | [`playbooks/...`](playbooks/linux_t1548_sudo_privilege_abuse.md) |

---

## 4. Detection Scenarios Detail

### Scenario 1: Windows Suspicious Encoded PowerShell Process Execution
* **Threat Context:** Adversaries leverage `powershell.exe` with base64 encoded parameters (`-enc`, `-encodedcommand`) and hidden window flags (`-w hidden`, `-nop`) to evade command-line auditing and execute in-memory download cradles.
* **Positive Fixture:** Process creation events containing obfuscated payload strings and hidden window arguments.
* **Negative Fixture (False Positive Control):** Administrative tasks executing standard scripts (`-File C:\Scripts\backup.ps1`) or enterprise deployment tools (`SystemCenter`), ensuring zero alert noise.

### Scenario 2: Linux Sudo Privilege Abuse via Suspicious Binaries
* **Threat Context:** Unprivileged users or compromised service accounts exploiting sudo permissions on standard binaries (`find`, `vim`, `less`, `awk`, `bash -p`) to escape constrained shells and execute root sessions without re-authenticating (GTFOBins pattern).
* **Positive Fixture:** Sudo execution logs running shell escapes (`find . -exec /bin/sh -p \;` or `vim /etc/shadow`).
* **Negative Fixture (False Positive Control):** Standard administrative commands (`sudo systemctl restart nginx`, `sudo apt update`) and non-root targets.

---

## 5. Verification and Test Suite

The laboratory includes an automated test harness ensuring:
* **True Positive Rate:** 100% of malicious attack samples trigger alerts with matching severity and MITRE tags.
* **False Positive Immunity:** 0% of benign operational logs trigger alerts.
* **Sigma Schema Conformance:** Validates YAML structure, UUID format, and metadata completeness.
* **Typography and Formatting:** Automated test enforcing zero Unicode em dashes (`U+2014`).

### Running Tests Locally

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Execute full validation suite
pytest -v
```

---

## 6. Directory Structure

```text
soc-detection-lab/
├── .github/
│   └── workflows/
│       └── ci.yml             # Automated CI pipeline
├── engine/
│   ├── __init__.py
│   ├── parser.py              # Log normalizer for Windows and Linux telemetry
│   └── rule_matcher.py        # Sigma pattern matching and condition evaluator
├── rules/
│   ├── windows/               # Windows detection rules
│   └── linux/                 # Linux detection rules
├── telemetry/
│   ├── windows/               # Positive and negative Windows test logs
│   └── linux/                 # Positive and negative Linux test logs
├── playbooks/                 # Analyst investigation guides (Tier-1 and Tier-2 triage)
├── tests/                     # Automated pytest validation suite
├── requirements.txt
└── README.md
```

---

## 7. License

This project is licensed under the [MIT License](LICENSE).
