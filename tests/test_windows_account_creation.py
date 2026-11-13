import os
import json
import pytest
from engine.rule_matcher import SigmaRule
from engine.parser import normalize_windows_account_creation

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RULE_PATH = os.path.join(PROJECT_ROOT, "rules", "windows", "win_account_creation_suspicious.yml")
POSITIVE_FIXTURE = os.path.join(PROJECT_ROOT, "telemetry", "windows", "positive_account_creation_4720.json")
NEGATIVE_FIXTURE = os.path.join(PROJECT_ROOT, "telemetry", "windows", "negative_account_creation_4720.json")


@pytest.fixture
def account_creation_rule():
    assert os.path.exists(RULE_PATH), f"Rule file missing: {RULE_PATH}"
    return SigmaRule(RULE_PATH)


def test_positive_telemetry_triggers_alert(account_creation_rule):
    with open(POSITIVE_FIXTURE, "r", encoding="utf-8") as f:
        events = json.load(f)

    assert len(events) > 0, "Positive telemetry fixture must contain test logs"

    alerts_generated = 0
    for raw_ev in events:
        normalized = normalize_windows_account_creation(raw_ev)
        matched, alert = account_creation_rule.evaluate(normalized)
        assert matched is True, f"Failed to alert on suspicious account creation: {normalized}"
        assert alert["rule_id"] == "b4a2c918-1e5f-4a3d-8210-9f5b3c4d7e21"
        assert alert["severity"] == "medium"
        assert "attack.t1136" in alert["tags"]
        alerts_generated += 1

    assert alerts_generated == len(events), "True positive rate must be 100% on synthetic test fixtures"


def test_negative_telemetry_produces_zero_false_positives(account_creation_rule):
    with open(NEGATIVE_FIXTURE, "r", encoding="utf-8") as f:
        events = json.load(f)

    assert len(events) > 0, "Negative telemetry fixture must contain test logs"

    for raw_ev in events:
        normalized = normalize_windows_account_creation(raw_ev)
        matched, alert = account_creation_rule.evaluate(normalized)
        assert matched is False, f"False positive triggered on benign event: {normalized}"
