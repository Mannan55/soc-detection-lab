import os
import json
import pytest
from engine.rule_matcher import load_rules
from engine.parser import (
    normalize_windows_process_creation,
    normalize_windows_logon_failure,
    normalize_windows_account_creation,
    normalize_linux_ssh_event,
    normalize_linux_sudo_event,
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RULES_DIR = os.path.join(PROJECT_ROOT, "rules")
CASE_1_STREAM = os.path.join(
    PROJECT_ROOT, "telemetry", "case_studies", "case_001_windows_intrusion_stream.json"
)
CASE_2_STREAM = os.path.join(
    PROJECT_ROOT, "telemetry", "case_studies", "case_002_linux_compromise_stream.json"
)


@pytest.fixture
def all_rules():
    rules = load_rules(RULES_DIR)
    assert len(rules) >= 4, "Must have at least 4 rules loaded"
    return {r.id: r for r in rules}


def test_windows_multi_stage_intrusion_correlation(all_rules):
    with open(CASE_1_STREAM, "r", encoding="utf-8") as f:
        stream = json.load(f)

    # Stage 1: Brute Force
    raw_s1 = stream[0]["event"]
    norm_s1 = normalize_windows_logon_failure(raw_s1)
    matched_s1, alert_s1 = all_rules["d7e8b91a-4c2f-4a3b-9801-6f23d5a49811"].evaluate(norm_s1)
    assert matched_s1 is True, "Stage 1 failed to trigger brute-force alert"
    assert alert_s1["severity"] == "high"

    # Stage 2: Account Creation
    raw_s2 = stream[1]["event"]
    norm_s2 = normalize_windows_account_creation(raw_s2)
    matched_s2, alert_s2 = all_rules["b4a2c918-1e5f-4a3d-8210-9f5b3c4d7e21"].evaluate(norm_s2)
    assert matched_s2 is True, "Stage 2 failed to trigger account creation alert"
    assert alert_s2["severity"] == "medium"

    # Stage 3: Suspicious Encoded PowerShell
    raw_s3 = stream[2]["event"]
    norm_s3 = normalize_windows_process_creation(raw_s3)
    matched_s3, alert_s3 = all_rules["a8b1c2d3-e4f5-4678-90ab-cdef12345678"].evaluate(norm_s3)
    assert matched_s3 is True, "Stage 3 failed to trigger encoded powershell alert"
    assert alert_s3["severity"] == "high"

    # Stage 4: Benign Baseline Noise (No alert across any rule)
    raw_s4 = stream[3]["event"]
    norm_s4 = normalize_windows_process_creation(raw_s4)
    for rule_id, rule in all_rules.items():
        matched, _ = rule.evaluate(norm_s4)
        assert matched is False, f"Rule {rule_id} triggered false alert on benign baseline event"


def test_linux_multi_stage_compromise_correlation(all_rules):
    with open(CASE_2_STREAM, "r", encoding="utf-8") as f:
        stream = json.load(f)

    # Stage 1: SSH Brute Force (root)
    raw_s1 = stream[0]["event"]
    norm_s1 = normalize_linux_ssh_event(raw_s1)
    matched_s1, alert_s1 = all_rules["e3a1f82b-9c4d-4b82-95f3-7801a2d59642"].evaluate(norm_s1)
    assert matched_s1 is True, "Stage 1 failed to trigger SSH brute-force alert"

    # Stage 2: SSH Invalid User (admin)
    raw_s2 = stream[1]["event"]
    norm_s2 = normalize_linux_ssh_event(raw_s2)
    matched_s2, alert_s2 = all_rules["e3a1f82b-9c4d-4b82-95f3-7801a2d59642"].evaluate(norm_s2)
    assert matched_s2 is True, "Stage 2 failed to trigger SSH invalid user alert"

    # Stage 3: Sudo GTFOBins Privilege Escalation
    raw_s3 = stream[2]["event"]
    norm_s3 = normalize_linux_sudo_event(raw_s3)
    matched_s3, alert_s3 = all_rules["b9c2d3e4-f5a6-4789-91bc-def012345679"].evaluate(norm_s3)
    assert matched_s3 is True, "Stage 3 failed to trigger sudo abuse alert"
    assert alert_s3["severity"] == "high"

    # Stage 4: Benign Administrative Task (No alert)
    raw_s4 = stream[3]["event"]
    norm_s4 = normalize_linux_sudo_event(raw_s4)
    for rule_id, rule in all_rules.items():
        matched, _ = rule.evaluate(norm_s4)
        assert matched is False, f"Rule {rule_id} triggered false alert on benign baseline event"
