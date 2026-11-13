import os
import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def test_zero_em_dashes_in_soc_lab():
    """
    Enforces strict requirement: Zero Unicode em dashes (U+2014) across
    all project files, code, tests, documentation, and telemetry fixtures.
    """
    extensions = {".py", ".md", ".yml", ".yaml", ".json", ".txt"}
    dirs_to_skip = {".git", "__pycache__", ".pytest_cache"}

    violations = []

    for root, dirs, files in os.walk(PROJECT_ROOT):
        dirs[:] = [d for d in dirs if d not in dirs_to_skip]
        for file in files:
            _, ext = os.path.splitext(file)
            if ext.lower() in extensions:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, PROJECT_ROOT)
                try:
                    with open(full_path, "r", encoding="utf-8") as f:
                        text = f.read()
                        if "\u2014" in text:
                            count = text.count("\u2014")
                            violations.append(f"{rel_path}: {count} occurrence(s) of U+2014")
                except Exception as e:
                    violations.append(f"Could not read {rel_path}: {e}")

    assert len(violations) == 0, "U+2014 em dash detected in files:\n" + "\n".join(violations)
