import os
import re
import pytest
import yaml

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RULES_DIR = os.path.join(PROJECT_ROOT, "rules")


def get_all_rules():
    rule_files = []
    for root, _, files in os.walk(RULES_DIR):
        for f in files:
            if f.endswith((".yml", ".yaml")):
                rule_files.append(os.path.join(root, f))
    return rule_files


@pytest.mark.parametrize("rule_path", get_all_rules())
def test_sigma_rule_schema(rule_path):
    with open(rule_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert "title" in data, f"Missing 'title' in {rule_path}"
    assert "id" in data, f"Missing 'id' in {rule_path}"
    # Validate UUID format
    uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    assert re.match(uuid_pattern, data["id"].lower()), f"Invalid UUID format in {rule_path}: {data['id']}"

    assert "status" in data, f"Missing 'status' in {rule_path}"
    assert "description" in data, f"Missing 'description' in {rule_path}"
    assert "level" in data, f"Missing 'level' in {rule_path}"
    assert data["level"] in ["low", "medium", "high", "critical"], f"Invalid severity level: {data['level']}"

    assert "tags" in data and isinstance(data["tags"], list), f"Missing 'tags' list in {rule_path}"
    assert any(tag.startswith("attack.t") for tag in data["tags"]), f"Rule {rule_path} must have at least one MITRE technique tag (e.g. attack.t1059.001)"

    assert "logsource" in data, f"Missing 'logsource' in {rule_path}"
    assert "detection" in data, f"Missing 'detection' in {rule_path}"
    assert "condition" in data["detection"], f"Missing 'condition' in detection block of {rule_path}"

