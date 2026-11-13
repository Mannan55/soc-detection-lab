import os
import json
import pytest
from engine.rule_matcher import SigmaRule
from engine.parser import normalize_linux_sudo_event

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RULE_PATH = os.path.join(PROJECT_ROOT, "rules", "linux", "sys_auth_linux_sudo_privilege_abuse.yml")
POSITIVE_FIXTURE = os.path.join(PROJECT_ROOT, "telemetry", "linux", "positive_sudo_abuse.json")
NEGATIVE_FIXTURE = os.path.join(PROJECT_ROOT, "telemetry", "linux", "negative_benign_sudo.json")


@pytest.fixture
def sudo_rule():
    assert os.path.exists(RULE_PATH), f"Rule file missing: {RULE_PATH}"
    return SigmaRule(RULE_PATH)


def test_positive_telemetry_triggers_alert(sudo_rule):
    with open(POSITIVE_FIXTURE, "r", encoding="utf-8") as f:
        events = json.load(f)

    assert len(events) > 0, "Positive telemetry fixture must contain test logs"

    alerts_generated = 0
    for raw_ev in events:
        normalized = normalize_linux_sudo_event(raw_ev)
        matched, alert = sudo_rule.evaluate(normalized)
        assert matched is True, f"Failed to alert on malicious sudo event: {normalized['Command']}"
        assert alert["rule_id"] == "b9c2d3e4-f5a6-4789-91bc-def012345679"
        assert alert["severity"] == "high"
        assert "attack.t1548.003" in alert["tags"]
        alerts_generated += 1

    assert alerts_generated == len(events), "True positive rate must be 100%"


def test_negative_telemetry_produces_zero_false_positives(sudo_rule):
    with open(NEGATIVE_FIXTURE, "r", encoding="utf-8") as f:
        events = json.load(f)

    assert len(events) > 0, "Negative telemetry fixture must contain test logs"

    for raw_ev in events:
        normalized = normalize_linux_sudo_event(raw_ev)
        matched, alert = sudo_rule.evaluate(normalized)
        assert matched is False, f"False positive triggered on benign event: {normalized['Command']}"
