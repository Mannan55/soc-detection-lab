import os
import subprocess
import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT_PATH = os.path.join(PROJECT_ROOT, "scripts", "generate_detection_metrics.py")
REPORT_PATH = os.path.join(PROJECT_ROOT, "docs", "DETECTION_QUALITY_REPORT.md")


def test_detection_metrics_script_generation():
    assert os.path.exists(SCRIPT_PATH), f"Script missing: {SCRIPT_PATH}"
    # Run the generation script
    res = subprocess.run(["python", SCRIPT_PATH], capture_output=True, text=True, cwd=PROJECT_ROOT)
    assert res.returncode == 0, f"Generation failed: {res.stderr}"
    assert os.path.exists(REPORT_PATH), f"Report missing: {REPORT_PATH}"

    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    assert "Detection Quality and Coverage Report" in content
    assert "Total Active Sigma Rules" in content
    assert "Synthetic Validation Performance" in content
    assert "True Positive Rate (TPR)" in content
    assert "\u2014" not in content, "Em dash found in generated report"


def test_detection_metrics_check_flag():
    res = subprocess.run(["python", SCRIPT_PATH, "--check"], capture_output=True, text=True, cwd=PROJECT_ROOT)
    assert res.returncode == 0, f"--check failed: {res.stderr}"
