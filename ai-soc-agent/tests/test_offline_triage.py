import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_offline_triage_script_exists():
    script = ROOT / "agent" / "offline_triage.py"
    assert script.exists(), "offline_triage.py should exist in agent/"


def test_required_sample_alert_exists():
    alert = ROOT / "sample-alerts" / "rule-100101-alert-redacted.json"
    assert alert.exists(), "rule-100101 sample alert should exist"


def test_sample_alert_json_is_valid():
    alert = ROOT / "sample-alerts" / "rule-100101-alert-redacted.json"
    with alert.open() as f:
        data = json.load(f)

    assert data is not None


def test_rule_100101_sample_contains_expected_lab_evidence():
    alert = ROOT / "sample-alerts" / "rule-100101-alert-redacted.json"
    text = alert.read_text()

    assert "100101" in text
    assert "web-server-01" in text
    assert "10.10.30.10" in text
    assert "labuser" in text


def test_offline_triage_dry_run_generates_report(tmp_path):
    script = ROOT / "agent" / "offline_triage.py"
    alert = ROOT / "sample-alerts" / "rule-100101-alert-redacted.json"

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--alert",
            str(alert),
            "--output-dir",
            str(tmp_path),
            "--dry-run",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=30,
         check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "AI-Assisted Triage Report" in result.stdout
    assert "rule 100101" in result.stdout

    reports = list(tmp_path.glob("triage-100101-*.md"))
    assert len(reports) == 1

    report_text = reports[0].read_text()
    assert "Authoritative Evidence" in report_text
    assert "MITRE ATT&CK" in report_text
    assert "T1110" in report_text