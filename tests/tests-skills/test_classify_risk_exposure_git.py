"""Unit tests for classify_risk script in git-exposure-checker."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# pyrefly: ignore [missing-import]
import classify_risk
import pytest

# pyrefly: ignore [missing-import]
from classify_risk import (
    TAXONOMY_RULES,
    ExposureState,
    RiskLevel,
    classify_state,
    determine_state,
    enrich_payload,
    main,
)

SCRIPTS_DIR = Path(classify_risk.__file__).resolve().parent


def test_all_exposure_states_mapped_in_taxonomy():
    """Verify that every defined ExposureState exists in TAXONOMY_RULES."""
    for state in ExposureState:
        assert state in TAXONOMY_RULES
        rule = TAXONOMY_RULES[state]
        assert "risk_level" in rule
        assert "description" in rule
        assert "risk_assessment" in rule
        assert rule["risk_level"] in [r.value for r in RiskLevel]


@pytest.mark.parametrize(
    ("state_name", "expected_risk", "expected_prefix"),
    [
        ("LOCAL_ONLY", RiskLevel.LOW.value, "LOW -"),
        ("LOCAL_IGNORED", RiskLevel.LOW.value, "LOW -"),
        ("UNTRACKED_UNIGNORED", RiskLevel.HIGH.value, "HIGH -"),
        ("TRACKED_DESPITE_IGNORE", RiskLevel.CRITICAL.value, "CRITICAL -"),
        ("TRACKED_ACTIVE", RiskLevel.CRITICAL.value, "CRITICAL -"),
        ("COMMITTED_HISTORICAL", RiskLevel.CRITICAL.value, "CRITICAL -"),
    ],
)
def test_classify_state_valid(state_name: str, expected_risk: str, expected_prefix: str):
    result = classify_state(state_name)
    assert result["exposure_state"] == state_name
    assert result["risk_level"] == expected_risk
    assert result["risk_assessment"].startswith(expected_prefix)


def test_classify_state_invalid():
    with pytest.raises(ValueError, match="Unknown exposure state 'NON_EXISTENT'"):
        classify_state("NON_EXISTENT")


@pytest.mark.parametrize(
    ("is_repo", "is_tracked", "is_ignored", "in_history", "expected_state"),
    [
        (False, False, False, False, ExposureState.LOCAL_ONLY),
        (False, True, True, False, ExposureState.LOCAL_ONLY),
        (True, False, True, False, ExposureState.LOCAL_IGNORED),
        (True, False, False, False, ExposureState.UNTRACKED_UNIGNORED),
        (True, True, True, False, ExposureState.TRACKED_DESPITE_IGNORE),
        (True, True, False, False, ExposureState.TRACKED_ACTIVE),
        (True, False, False, True, ExposureState.COMMITTED_HISTORICAL),
        (True, True, False, True, ExposureState.COMMITTED_HISTORICAL),
    ],
)
def test_determine_state(is_repo: bool, is_tracked: bool, is_ignored: bool, in_history: bool, expected_state: ExposureState):
    assert determine_state(is_repo, is_tracked, is_ignored, in_history) == expected_state


def test_enrich_payload_with_exposure_state():
    payload = {
        "path": "config/deploy.env",
        "is_git_repo": True,
        "is_tracked": True,
        "is_ignored": True,
        "ignore_rule": ".gitignore:14:*.env",
        "working_tree_flag": "M ",
        "exposure_state": "TRACKED_DESPITE_IGNORE",
    }
    enriched = enrich_payload(payload)
    assert enriched["risk_level"] == "Critical"
    assert "CRITICAL - File is tracked" in enriched["risk_assessment"]
    assert enriched["path"] == "config/deploy.env"


def test_enrich_payload_derives_missing_exposure_state():
    payload = {
        "path": "secret.env",
        "is_git_repo": True,
        "is_tracked": False,
        "is_ignored": False,
    }
    enriched = enrich_payload(payload)
    assert enriched["exposure_state"] == "UNTRACKED_UNIGNORED"
    assert enriched["risk_level"] == "High"


def test_enrich_payload_missing_fields_raises_value_error():
    with pytest.raises(ValueError, match="Payload must provide 'exposure_state'"):
        enrich_payload({"path": "file.txt"})


def test_cli_state_flag(capsys):
    exit_code = main(["--state", "TRACKED_ACTIVE"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["exposure_state"] == "TRACKED_ACTIVE"
    assert data["risk_level"] == "Critical"


def test_cli_list_flag(capsys):
    exit_code = main(["--list"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data) == 6
    assert "LOCAL_ONLY" in data


def test_cli_enrich_flag(capsys):
    raw_payload = json.dumps({"path": ".env", "exposure_state": "LOCAL_IGNORED"})
    exit_code = main(["--enrich", raw_payload])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["risk_level"] == "Low"


def test_cli_stdin_flag(monkeypatch, capsys):
    raw_payload = json.dumps({"path": ".env", "exposure_state": "LOCAL_ONLY"})
    monkeypatch.setattr("sys.stdin", type("StdinMock", (), {"read": lambda self: raw_payload})())
    exit_code = main(["--stdin"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["risk_level"] == "Low"


def test_cli_flag_resolution(capsys):
    exit_code = main([
        "--is-repo", "true",
        "--is-tracked", "true",
        "--is-ignored", "false",
        "--path", "app.py",
    ])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["exposure_state"] == "TRACKED_ACTIVE"
    assert data["risk_level"] == "Critical"
    assert data["path"] == "app.py"


def test_cli_invalid_state_returns_exit_code_1(capsys):
    exit_code = main(["--state", "INVALID_STATE"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Error:" in captured.err


def test_cli_subprocess_execution():
    script_path = SCRIPTS_DIR / "classify_risk.py"
    res = subprocess.run(
        [sys.executable, str(script_path), "--state", "COMMITTED_HISTORICAL"],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(res.stdout)
    assert data["risk_level"] == "Critical"
