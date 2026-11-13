import os
import json
import pytest
from engine.rule_matcher import SigmaRule
from engine.parser import normalize_windows_logon_failure

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RULE_PATH = os.path.join(PROJECT_ROOT, "rules", "windows", "win_auth_failed_logon_bruteforce.yml")
POSITIVE_FIXTURE = os.path.join(PROJECT_ROOT, "telemetry", "windows", "positive_auth_failed_logon_4625.json")
NEGATIVE_FIXTURE = os.path.join(PROJECT_ROOT, "telemetry", "windows", "negative_auth_benign_typo_4625.json")


@pytest.fixture
def auth_bruteforce_rule():
    assert os.path.exists(RULE_PATH), f"Rule file missing: {RULE_PATH}"
    return SigmaRule(RULE_PATH)


def test_positive_telemetry_triggers_alert(auth_bruteforce_rule):
    with open(POSITIVE_FIXTURE, "r", encoding="utf-8") as f:
        events = json.load(f)

    assert len(events) > 0, "Positive telemetry fixture must contain test logs"

    alerts_generated = 0
    for raw_ev in events:
        normalized = normalize_windows_logon_failure(raw_ev)
        matched, alert = auth_bruteforce_rule.evaluate(normalized)
        assert matched is True, f"Failed to alert on malicious event: {normalized}"
        assert alert["rule_id"] == "d7e8b91a-4c2f-4a3b-9801-6f23d5a49811"
        assert alert["severity"] == "high"
        assert "attack.t1110" in alert["tags"]
        alerts_generated += 1

    assert alerts_generated == len(events), "True positive rate must be 100% on synthetic test fixtures"


def test_negative_telemetry_produces_zero_false_positives(auth_bruteforce_rule):
    with open(NEGATIVE_FIXTURE, "r", encoding="utf-8") as f:
        events = json.load(f)

    assert len(events) > 0, "Negative telemetry fixture must contain test logs"

    for raw_ev in events:
        normalized = normalize_windows_logon_failure(raw_ev)
        matched, alert = auth_bruteforce_rule.evaluate(normalized)
        assert matched is False, f"False positive triggered on benign event: {normalized}"
