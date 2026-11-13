"""
Sigma rule evaluator and pattern matching engine for SOC Detection Lab.
Evaluates normalized security events against Sigma rule YAML specifications.

Strictly zero em dashes (U+2014).
"""

import os
import re
import yaml
from typing import Dict, Any, List, Optional, Tuple


def deobfuscate_string(val: str) -> str:
    """
    Normalizes command lines and strings against common evasion techniques:
    - Removes caret (^) command-prompt escape characters
    - Removes PowerShell backtick escape characters
    - Collapses consecutive whitespace (spaces, tabs) into single spaces
    """
    if not val or not isinstance(val, str):
        return ""
    # Strip caret and backtick evasion
    cleaned = val.replace("^", "").replace("`", "")
    # Normalize excessive spacing
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


class SigmaRule:
    def __init__(self, rule_path: str):
        self.rule_path = rule_path
        with open(rule_path, "r", encoding="utf-8") as f:
            self.data = yaml.safe_load(f)

        self.title = self.data.get("title", "Untitled Rule")
        self.id = self.data.get("id", "")
        self.status = self.data.get("status", "experimental")
        self.description = self.data.get("description", "")
        self.level = self.data.get("level", "medium")
        self.tags = self.data.get("tags", [])
        self.logsource = self.data.get("logsource", {})
        self.detection = self.data.get("detection", {})
        self.condition = self.detection.get("condition", "selection")

    def _match_field_value(self, event_val: Any, target_val: Any, modifier: Optional[str] = None) -> bool:
        if event_val is None:
            return False

        # If target_val is a list, match ANY value (OR condition)
        if isinstance(target_val, list):
            return any(self._match_field_value(event_val, item, modifier) for item in target_val)

        event_str = str(event_val).lower()
        target_str = str(target_val).lower()
        deobf_event_str = deobfuscate_string(event_str)

        if modifier == "contains":
            return (target_str in event_str) or (target_str in deobf_event_str)
        elif modifier == "startswith":
            return event_str.startswith(target_str) or deobf_event_str.startswith(target_str)
        elif modifier == "endswith":
            return event_str.endswith(target_str) or deobf_event_str.endswith(target_str)
        else:
            return (event_str == target_str) or (deobf_event_str == target_str)

    def _evaluate_block(self, block_def: Any, event: Dict[str, Any]) -> bool:
        # A block can be a dictionary of field: value or a list of dictionaries (OR of blocks)
        if isinstance(block_def, list):
            return any(self._evaluate_block(item, event) for item in block_def)

        if not isinstance(block_def, dict):
            return False

        # All fields in a dictionary must match (AND condition)
        for field_spec, target_val in block_def.items():
            field_name = field_spec
            modifier = None
            if "|" in field_spec:
                parts = field_spec.split("|")
                field_name = parts[0]
                modifier = parts[1]

            # Direct lookup or case-insensitive fallback
            event_val = event.get(field_name)
            if event_val is None:
                for k, v in event.items():
                    if k.lower() == field_name.lower():
                        event_val = v
                        break

            if not self._match_field_value(event_val, target_val, modifier):
                return False

        return True

    def evaluate(self, event: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Evaluates a normalized log event against the Sigma rule.
        Returns (matched, alert_metadata).
        """
        block_results = {}
        for key, val in self.detection.items():
            if key == "condition":
                continue
            block_results[key] = self._evaluate_block(val, event)

        cond = self.condition.strip()
        matched = False

        if " and not " in cond:
            pos_part, neg_part = cond.split(" and not ", 1)
            pos_matched = False
            if "all of selection*" in pos_part:
                pos_matched = all(v for k, v in block_results.items() if k.startswith("selection"))
            elif "1 of selection*" in pos_part:
                pos_matched = any(v for k, v in block_results.items() if k.startswith("selection"))
            else:
                pos_matched = block_results.get(pos_part.strip(), False)

            neg_matched = False
            if "1 of filter*" in neg_part:
                neg_matched = any(v for k, v in block_results.items() if k.startswith("filter"))
            else:
                neg_matched = block_results.get(neg_part.strip(), False)

            matched = pos_matched and not neg_matched
        elif "all of selection*" in cond:
            matched = all(v for k, v in block_results.items() if k.startswith("selection"))
        elif "1 of selection*" in cond:
            matched = any(v for k, v in block_results.items() if k.startswith("selection"))
        elif cond == "selection":
            matched = block_results.get("selection", False)
        elif cond in block_results:
            matched = block_results[cond]
        else:
            matched = block_results.get("selection", False)

        if matched:
            alert = {
                "rule_id": self.id,
                "rule_title": self.title,
                "severity": self.level,
                "tags": self.tags,
                "description": self.description,
                "triggering_event": event
            }
            return True, alert

        return False, None


def load_rules(rules_dir: str) -> List[SigmaRule]:
    rules = []
    for root, _, files in os.walk(rules_dir):
        for f in files:
            if f.endswith((".yml", ".yaml")):
                full_path = os.path.join(root, f)
                rules.append(SigmaRule(full_path))
    return rules
