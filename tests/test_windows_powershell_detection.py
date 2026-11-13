import os
import json
import pytest
from engine.rule_matcher import SigmaRule
from engine.parser import normalize_windows_process_creation

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RULE_PATH = os.path.join(PROJECT_ROOT, "rules", "windows", "proc_creation_win_powershell_suspicious_encoded.yml")
POSITIVE_FIXTURE = os.path.join(PROJECT_ROOT, "telemetry", "windows", "positive_encoded_powershell.json")
NEGATIVE_FIXTURE = os.path.join(PROJECT_ROOT, "telemetry", "windows", "negative_benign_powershell.json")


@pytest.fixture
def powershell_rule():
    assert os.path.exists(RULE_PATH), f"Rule file missing: {RULE_PATH}"
    return SigmaRule(RULE_PATH)


def test_positive_telemetry_triggers_alert(powershell_rule):
    with open(POSITIVE_FIXTURE, "r", encoding="utf-8") as f:
        events = json.load(f)

    assert len(events) > 0, "Positive telemetry fixture must contain test logs"

    alerts_generated = 0
    for raw_ev in events:
        normalized = normalize_windows_process_creation(raw_ev)
        matched, alert = powershell_rule.evaluate(normalized)
        assert matched is True, f"Failed to alert on malicious event: {normalized['CommandLine']}"
        assert alert["rule_id"] == "a8b1c2d3-e4f5-4678-90ab-cdef12345678"
        assert alert["severity"] == "high"
        assert "attack.t1059.001" in alert["tags"]
        alerts_generated += 1

    assert alerts_generated == len(events), "True positive rate must be 100%"


def test_negative_telemetry_produces_zero_false_positives(powershell_rule):
    with open(NEGATIVE_FIXTURE, "r", encoding="utf-8") as f:
        events = json.load(f)

    assert len(events) > 0, "Negative telemetry fixture must contain test logs"

    for raw_ev in events:
        normalized = normalize_windows_process_creation(raw_ev)
        matched, alert = powershell_rule.evaluate(normalized)
        assert matched is False, f"False positive triggered on benign event: {normalized['CommandLine']}"

