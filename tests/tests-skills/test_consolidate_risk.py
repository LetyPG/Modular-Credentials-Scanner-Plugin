"""Unit and integration tests for deterministic risk consolidator in safe-audit-reporter."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# pyrefly: ignore [missing-import]
import consolidate_risk
import pytest

# pyrefly: ignore [missing-import]
from consolidate_risk import (
    CREDENTIAL_IMPACT_TAXONOMY,
    RISK_DECISION_MATRIX,
    VALID_EXPOSURE_STATES,
    FinalRiskTier,
    ImpactTier,
    classify_credential_type,
    consolidate_payload,
    main,
    score_finding,
)

SCRIPTS_DIR = Path(consolidate_risk.__file__).resolve().parent


# ---------------------------------------------------------------------------
# Taxonomy & Impact Classification Tests
# ---------------------------------------------------------------------------


def test_taxonomy_definitions_complete():
    """Verify that all predefined categories in taxonomy have valid attributes."""
    for item in CREDENTIAL_IMPACT_TAXONOMY.values():
        assert item.category
        assert item.impact_tier in [t for t in ImpactTier]
        assert item.technical_impact
        assert item.escalation_consequence


def test_valid_exposure_states():
    """Verify that all expected exposure states are declared."""
    assert len(VALID_EXPOSURE_STATES) == 6
    assert "TRACKED_ACTIVE" in VALID_EXPOSURE_STATES
    assert "LOCAL_ONLY" in VALID_EXPOSURE_STATES


def test_risk_decision_matrix_completeness():
    """Verify that every combination of exposure group and impact tier is mapped."""
    assert len(RISK_DECISION_MATRIX) == 12
    for score, final_tier in RISK_DECISION_MATRIX.values():
        assert 1 <= score <= 10
        assert final_tier in [t for t in FinalRiskTier]




@pytest.mark.parametrize(
    ("secret_type", "expected_category", "expected_tier"),
    [
        ("AWS Access Key ID", "Cloud Provider Keys (AWS, GCP, Azure)", ImpactTier.CRITICAL),
        ("GCP Service Account", "Cloud Provider Keys (AWS, GCP, Azure)", ImpactTier.CRITICAL),
        ("PostgreSQL Connection String", "Database Credentials", ImpactTier.CRITICAL),
        ("SSH Private Key", "Private Keys (SSH, RSA, EC)", ImpactTier.CRITICAL),
        ("Stripe Live Secret Key", "Payment Gateways (Stripe, PayPal)", ImpactTier.CRITICAL),
        ("GitHub Personal Access Token", "VCS Tokens (GitHub, GitLab)", ImpactTier.HIGH),
        ("JWT Session Secret", "Internal Auth / JWT Secrets", ImpactTier.MEDIUM),
        ("Generic Telemetry Key", "Generic API Key / Webhook Token", ImpactTier.LOW),
    ],
)
def test_classify_credential_type(secret_type: str, expected_category: str, expected_tier: ImpactTier):
    result = classify_credential_type(secret_type)
    assert result.category == expected_category
    assert result.impact_tier == expected_tier


# ---------------------------------------------------------------------------
# Scoring Matrix & Boundary Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exposure_state", "secret_type", "expected_score", "expected_tier"),
    [
        # Critical exposure (weight 4)
        ("TRACKED_ACTIVE", "AWS Secret Key", 10, FinalRiskTier.HIGH.value),
        ("TRACKED_DESPITE_IGNORE", "GitHub Token", 9, FinalRiskTier.HIGH.value),
        ("COMMITTED_HISTORICAL", "JWT Secret", 7, FinalRiskTier.HIGH.value),
        ("TRACKED_ACTIVE", "Generic Webhook", 5, FinalRiskTier.MEDIUM.value),
        # High exposure (weight 3)
        ("UNTRACKED_UNIGNORED", "PostgreSQL URL", 8, FinalRiskTier.HIGH.value),
        ("UNTRACKED_UNIGNORED", "GitLab Token", 7, FinalRiskTier.HIGH.value),
        ("UNTRACKED_UNIGNORED", "Session Token", 5, FinalRiskTier.MEDIUM.value),
        ("UNTRACKED_UNIGNORED", "Generic Webhook", 4, FinalRiskTier.MEDIUM.value),
        # Low exposure (weight 1)
        ("LOCAL_ONLY", "AWS Access Key", 5, FinalRiskTier.MEDIUM.value),
        ("LOCAL_IGNORED", "GitHub Token", 4, FinalRiskTier.MEDIUM.value),
        ("LOCAL_ONLY", "JWT Secret", 3, FinalRiskTier.LOW.value),
        ("LOCAL_IGNORED", "Generic Webhook", 1, FinalRiskTier.LOW.value),
    ],
)
def test_score_finding_matrix(
    exposure_state: str,
    secret_type: str,
    expected_score: int,
    expected_tier: str,
):
    result = score_finding(exposure_state, secret_type)
    assert result["final_risk_score"] == expected_score
    assert result["final_risk_tier"] == expected_tier
    assert result["technical_impact"]
    assert result["potential_escalation"]


def test_score_finding_invalid_state():
    with pytest.raises(ValueError, match="Unknown exposure state 'INVALID_STATE'"):
        score_finding("INVALID_STATE", "AWS Access Key")


# ---------------------------------------------------------------------------
# Payload Consolidation & Metric Aggregation Tests
# ---------------------------------------------------------------------------


def test_consolidate_payload_empty():
    result = consolidate_payload([])
    assert result["metrics"]["total_findings"] == 0
    assert result["metrics"]["overall_assessment"] == "CLEAN"
    assert result["findings"] == []


def test_consolidate_payload_multiple():
    findings = [
        {"id": "SEC-001", "exposure_state": "TRACKED_ACTIVE", "secret_type": "AWS Access Key"},
        {"id": "SEC-002", "exposure_state": "UNTRACKED_UNIGNORED", "secret_type": "JWT Secret"},
        {"id": "SEC-003", "exposure_state": "LOCAL_IGNORED", "secret_type": "Generic Token"},
    ]
    result = consolidate_payload(findings)
    metrics = result["metrics"]

    assert metrics["total_findings"] == 3
    assert metrics["high_risk_count"] == 1
    assert metrics["medium_risk_count"] == 1
    assert metrics["low_risk_count"] == 1
    assert metrics["tracked_count"] == 1
    assert metrics["untracked_count"] == 1
    assert metrics["local_count"] == 1
    assert metrics["overall_assessment"] == "CONFIRMED EXPOSURE DETECTED"

    # Verify findings are properly enriched
    assert len(result["findings"]) == 3
    assert result["findings"][0]["final_risk_tier"] == "HIGH"
    assert result["findings"][0]["final_risk_score"] == 10
    assert result["findings"][1]["final_risk_tier"] == "MEDIUM"
    assert result["findings"][2]["final_risk_tier"] == "LOW"


def test_consolidate_payload_potential_exposure():
    findings = [
        {"id": "SEC-001", "exposure_state": "LOCAL_IGNORED", "secret_type": "Generic Token"},
    ]
    result = consolidate_payload(findings)
    assert result["metrics"]["overall_assessment"] == "POTENTIAL SECRETS DETECTED"


# ---------------------------------------------------------------------------
# CLI Entry Point Tests
# ---------------------------------------------------------------------------


def test_cli_list_flag(capsys):
    exit_code = main(["--list"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "credential_impacts" in data
    assert "cloud_keys" in data["credential_impacts"]
    assert "risk_matrix" in data


def test_cli_finding_flag(capsys):
    raw_payload = json.dumps({"exposure_state": "TRACKED_ACTIVE", "secret_type": "AWS Access Key"})
    exit_code = main(["--finding", raw_payload])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["final_risk_tier"] == "HIGH"
    assert data["final_risk_score"] == 10


def test_cli_file_flag(tmp_path: Path, capsys):
    test_file = tmp_path / "findings.json"
    test_file.write_text(
        json.dumps([{"exposure_state": "LOCAL_ONLY", "secret_type": "AWS Access Key"}]),
        encoding="utf-8",
    )
    exit_code = main(["--file", str(test_file)])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["metrics"]["total_findings"] == 1
    assert data["metrics"]["medium_risk_count"] == 1


def test_cli_stdin_flag(monkeypatch, capsys):
    raw_payload = json.dumps([{"exposure_state": "LOCAL_IGNORED", "secret_type": "Generic Key"}])
    monkeypatch.setattr("sys.stdin", type("StdinMock", (), {"read": lambda self: raw_payload})())
    exit_code = main(["--stdin"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["metrics"]["low_risk_count"] == 1


def test_cli_subprocess_execution():
    script_path = SCRIPTS_DIR / "consolidate_risk.py"
    payload = json.dumps({"exposure_state": "COMMITTED_HISTORICAL", "secret_type": "SSH Private Key"})
    res = subprocess.run(
        [sys.executable, str(script_path), "--finding", payload],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(res.stdout)
    assert data["final_risk_tier"] == "HIGH"
    assert data["final_risk_score"] == 10
