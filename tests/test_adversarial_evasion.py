import os
import pytest
from engine.rule_matcher import SigmaRule, deobfuscate_string
from engine.parser import (
    normalize_windows_process_creation,
    normalize_windows_logon_failure,
    normalize_linux_sudo_event,
    normalize_linux_ssh_event,
    normalize_windows_account_creation,
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
POWERSHELL_RULE_PATH = os.path.join(
    PROJECT_ROOT, "rules", "windows", "proc_creation_win_powershell_suspicious_encoded.yml"
)
SUDO_RULE_PATH = os.path.join(
    PROJECT_ROOT, "rules", "linux", "sys_auth_linux_sudo_privilege_abuse.yml"
)


def test_deobfuscate_string_removes_carets_and_backticks():
    raw_caret = "p^o^w^e^r^s^h^e^l^l.e^x^e"
    assert deobfuscate_string(raw_caret) == "powershell.exe"

    raw_backtick = "p`o`w`e`r`s`h`e`l`l"
    assert deobfuscate_string(raw_backtick) == "powershell"

    raw_spaces = "powershell.exe     -enc      SQBFAFgA"
    assert deobfuscate_string(raw_spaces) == "powershell.exe -enc SQBFAFgA"


def test_adversarial_caret_obfuscation_detected():
    rule = SigmaRule(POWERSHELL_RULE_PATH)
    raw_event = {
        "EventID": 4688,
        "TimeCreated": "2026-11-13T14:00:00.000Z",
        "EventData": {
            "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\p^o^w^e^r^s^h^e^l^l.exe",
            "CommandLine": "powershell.exe -w^i^n^d^o^w^s^t^y^l^e h^i^d^d^e^n -e^n^c SQBFAFgA",
            "TargetUserName": "attacker"
        }
    }
    normalized = normalize_windows_process_creation(raw_event)
    matched, alert = rule.evaluate(normalized)
    assert matched is True
    assert alert["rule_id"] == "a8b1c2d3-e4f5-4678-90ab-cdef12345678"


def test_adversarial_backtick_and_whitespace_obfuscation():
    rule = SigmaRule(POWERSHELL_RULE_PATH)
    raw_event = {
        "EventID": 4688,
        "TimeCreated": "2026-11-13T14:05:00.000Z",
        "EventData": {
            "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe    -`n`o`p    -`e`n`c`o`d`e`d`c`o`m`m`a`n`d    SQBFAFgA",
            "TargetUserName": "attacker"
        }
    }
    normalized = normalize_windows_process_creation(raw_event)
    matched, alert = rule.evaluate(normalized)
    assert matched is True


def test_case_insensitive_field_resolution():
    rule = SigmaRule(SUDO_RULE_PATH)
    # Event with lowercase field names instead of CamelCase
    event = {
        "user": "evil_actor",
        "targetuser": "root",
        "command": "/usr/bin/find . -exec /bin/sh \\; -quit"
    }
    matched, alert = rule.evaluate(event)
    assert matched is True
    assert alert["rule_id"] == "b9c2d3e4-f5a6-4789-91bc-def012345679"


def test_engine_gracefully_handles_empty_and_corrupted_events():
    rule = SigmaRule(POWERSHELL_RULE_PATH)
    empty_event = {}
    matched, alert = rule.evaluate(empty_event)
    assert matched is False
    assert alert is None

    null_field_event = {
        "Image": None,
        "CommandLine": None,
        "User": None
    }
    matched, alert = rule.evaluate(null_field_event)
    assert matched is False
    assert alert is None

    numeric_field_event = {
        "Image": 12345,
        "CommandLine": 99999
    }
    matched, alert = rule.evaluate(numeric_field_event)
    assert matched is False
