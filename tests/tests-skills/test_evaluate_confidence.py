"""Unit and integration tests for deterministic Confidence Rating Matrix and False-Positive Filter."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# pyrefly: ignore [missing-import]
import pytest

# pyrefly: ignore [missing-import]
import rate_confidence

# pyrefly: ignore [missing-import]
from rate_confidence import (
    ConfidenceLevel,
    calculate_shannon_entropy,
    check_false_positive,
    evaluate_candidate,
    evaluate_payload,
    is_valid_jwt_header,
    main,
)

# pyrefly: ignore [missing-import]
from rate_confidence import (
    rate_confidence as rate_conf,
)

SCRIPTS_DIR = Path(rate_confidence.__file__).resolve().parent


# ---------------------------------------------------------------------------
# Shannon Entropy & Helper Tests
# ---------------------------------------------------------------------------

def test_calculate_shannon_entropy_empty():
    assert calculate_shannon_entropy("") == 0.0


def test_calculate_shannon_entropy_uniform():
    # String of identical characters has 0 entropy
    assert calculate_shannon_entropy("aaaaaaaaaa") == 0.0


def test_calculate_shannon_entropy_random():
    # Random alphanumeric string should have higher entropy (> 3.0)
    entropy = calculate_shannon_entropy("aB8$kP2#zL9!vW3*")
    assert entropy > 3.0


def test_is_valid_jwt_header():
    # Header: {"alg":"HS256","typ":"JWT"} -> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
    valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
    assert is_valid_jwt_header(valid_jwt) is True

    invalid_token = "not.a.jwt"
    assert is_valid_jwt_header(invalid_token) is False


# ---------------------------------------------------------------------------
# False-Positive Screening Tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("snippet", "context", "path", "expected_discard_prefix"),
    [
        # Category 1: Documentation & Placeholders
        ("AKIAIOSFODNN7EXAMPLE", "AWS_KEY='AKIAIOSFODNN7EXAMPLE'", "config.py", "Documentation placeholder"),
        ("YOUR_API_KEY", "export API_KEY=YOUR_API_KEY", "deploy.sh", "Documentation placeholder"),
        ("dummy_token", "token = 'dummy_token'", "app.js", "Documentation placeholder"),
        ("replace_me", "client_secret = replace_me", "config.yml", "Documentation placeholder"),
        ("CHANGEME", "pass=CHANGEME", "env.dist", "Documentation placeholder"),
        # Category 2: Templating & Dynamic References
        ("{{API_KEY}}", "key: {{API_KEY}}", "template.yaml", "Templating or dynamic code"),
        ("${SECRET_TOKEN}", "token: ${SECRET_TOKEN}", "k8s.yaml", "Templating or dynamic code"),
        ("process.env.SECRET", "const s = process.env.SECRET;", "index.js", "Templating or dynamic code"),
        ("os.environ.get('KEY')", "key = os.environ.get('KEY')", "settings.py", "Templating or dynamic code"),
        # Category 3: Test Fixtures & Local Mocking
        ("AKIA1234567890123456", "aws_key = 'AKIA1234567890123456'", "tests/test_auth.py", "Hardcoded candidate situated in test"),
        ("AKIA1234567890123456", "aws_key = 'AKIA1234567890123456'", "src/__tests__/fixture.json", "Hardcoded candidate situated in test"),
        ("admin:admin", "auth='admin:admin'", "main.py", "Well-known mock credential"),
        ("foo:bar", "auth='foo:bar'", "src/app.py", "Well-known mock credential"),
        # Category 4: Metric & Counter Names, UUIDs, SVG
        ("total_tokens", "total_tokens: 150", "usage.json", "Code metric or counter schema"),
        ("550e8400-e29b-41d4-a716-446655440000", "id: 550e8400-e29b-41d4-a716-446655440000", "res.json", "Non-secret identifier matching standard UUID"),
        ("M10 20 L30 40", 'd="M10 20 L30 40"', "icon.svg", "SVG vector path coordinate data"),
    ],
)
def test_check_false_positive_discards(snippet: str, context: str, path: str, expected_discard_prefix: str):
    candidate = {
        "file_path": path,
        "candidate_snippet": snippet,
        "raw_context": context,
    }
    is_fp, reason = check_false_positive(candidate)
    assert is_fp is True
    assert reason is not None
    assert reason.startswith(expected_discard_prefix)


def test_check_false_positive_retains_legitimate():
    candidate = {
        "file_path": "production/secrets.env",
        "candidate_snippet": "AKIA1234567890ABCDEF",
        "raw_context": "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
    }
    is_fp, reason = check_false_positive(candidate)
    assert is_fp is False
    assert reason is None


# ---------------------------------------------------------------------------
# Confidence Rating Matrix Tests (HIGH, MEDIUM, LOW)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("snippet", "context", "secret_type"),
    [
        ("AKIA1234567890ABCDEF", "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF", "AWS Access Key"),
        ("AIzaSyD1234567890abcdefghijklmnopqrstuv", "API_KEY='AIzaSyD1234567890abcdefghijklmnopqrstuv'", "Google API Key"),
        ("ghp_123456789012345678901234567890123456", "token='ghp_123456789012345678901234567890123456'", "GitHub Token"),
        ("github_pat_11AAAAAAA01234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz", "pat='...'", "GitHub Fine-Grained PAT"),
        ("xoxb-123456789012-1234567890123-abcdef123456", "SLACK_BOT_TOKEN='xoxb-...'", "Slack Token"),
        ("sk_live_1234567890abcdefghijklmn", "stripe_key = 'sk_live_1234567890abcdefghijklmn'", "Stripe Secret Key"),
        ("sk-proj-1234567890abcdefghijklmnopqrstuvwxyz123456", "OPENAI_API_KEY='sk-proj-...'", "OpenAI API Key"),
        ("hf_1234567890123456789012345678901234", "HF_TOKEN='hf_...'", "Hugging Face Token"),
        ("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...", "Private Cryptographic Key"),
        ("PuTTY-User-Key-File-2", "PuTTY-User-Key-File-2: ssh-rsa", "PuTTY Private Key"),
    ],
)
def test_rate_confidence_high(snippet: str, context: str, secret_type: str):
    candidate = {
        "candidate_snippet": snippet,
        "raw_context": context,
        "secret_type": secret_type,
    }
    level, reason = rate_conf(candidate)
    assert level == ConfidenceLevel.HIGH
    assert reason != ""


@pytest.mark.parametrize(
    ("snippet", "context"),
    [
        ("postgres://admin:SuperSecret123@db.prod.internal:5432/main", "DATABASE_URL='postgres://admin:SuperSecret123@db.prod.internal:5432/main'"),
        ("mongodb+srv://root:P%40ssw0rd!@cluster0.mongodb.net/test", "MONGO_URI='mongodb+srv://root:P%40ssw0rd!@cluster0.mongodb.net/test'"),
        ("https://app_user:ComplexP@ssw0rd!@api.enterprise.com", "BASIC_AUTH='https://app_user:ComplexP@ssw0rd!@api.enterprise.com'"),
        ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "jwt_token = 'eyJhbGciOiJIUzI1Ni...'"),
        ("d8f7b3a9c2e1f408b6d3a5e7", "api_key = 'd8f7b3a9c2e1f408b6d3a5e7'"),
        ("p@ssw0rd#Secure99", "password = 'p@ssw0rd#Secure99'"),
    ],
)
def test_rate_confidence_medium(snippet: str, context: str):
    candidate = {
        "candidate_snippet": snippet,
        "raw_context": context,
    }
    level, reason = rate_conf(candidate)
    assert level == ConfidenceLevel.MEDIUM
    assert reason != ""


@pytest.mark.parametrize(
    ("snippet", "context"),
    [
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "const hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';"),
        ("dGhpcyBpcyBhIHZlcnkgbG9uZyByYW5kb20gc3RyaW5nIHdpdGggZW5vdWdoIGNoYXJz", "buf = 'dGhpcyBpcyBhIHZlcnkgbG9uZyByYW5kb20gc3RyaW5nIHdpdGggZW5vdWdoIGNoYXJz';"),
    ],
)
def test_rate_confidence_low(snippet: str, context: str):
    candidate = {
        "candidate_snippet": snippet,
        "raw_context": context,
    }
    level, reason = rate_conf(candidate)
    assert level == ConfidenceLevel.LOW
    assert reason != ""


# ---------------------------------------------------------------------------
# Pipeline & Payload Evaluation Tests
# ---------------------------------------------------------------------------

def test_evaluate_candidate_discarded():
    candidate = {
        "file_path": "docs/quickstart.md",
        "line_number": 42,
        "candidate_snippet": "AIzaSyDummyKeyForDocs1234567890123456",
        "raw_context": "export API_KEY=AIzaSyDummyKeyForDocs1234567890123456",
    }
    result = evaluate_candidate(candidate)
    assert result["status"] == "DISCARDED"
    assert "dummy" in result["discard_reason"].lower()


def test_evaluate_candidate_credible():
    candidate = {
        "id": "SEC-001",
        "file_path": "config/production.env",
        "line_number": 14,
        "candidate_snippet": "AKIA1234567890ABCDEF",
        "raw_context": "AWS_ACCESS_KEY_ID='AKIA1234567890ABCDEF'",
        "secret_type": "AWS Access Key",
    }
    result = evaluate_candidate(candidate)
    assert result["status"] == "CREDIBLE"
    assert result["confidence"] == "HIGH"
    assert "AWS" in result["confidence_reason"]


def test_evaluate_payload_splits_correctly():
    payload = {
        "candidates": [
            {
                "file_path": "docs/readme.md",
                "line_number": 5,
                "candidate_snippet": "YOUR_API_KEY",
                "raw_context": "curl -H 'Auth: YOUR_API_KEY'",
            },
            {
                "id": "SEC-002",
                "file_path": "prod.env",
                "line_number": 12,
                "candidate_snippet": "ghp_123456789012345678901234567890123456",
                "raw_context": "GITHUB_TOKEN=ghp_123456789012345678901234567890123456",
            },
        ]
    }
    results = evaluate_payload(payload)
    assert "credible_findings" in results
    assert "discarded_candidates" in results
    assert len(results["credible_findings"]) == 1
    assert len(results["discarded_candidates"]) == 1
    assert results["credible_findings"][0]["confidence"] == "HIGH"


# ---------------------------------------------------------------------------
# CLI Integration Tests
# ---------------------------------------------------------------------------

def test_cli_candidate_arg(capsys: pytest.CaptureFixture[str]):
    candidate = {
        "file_path": "app.py",
        "line_number": 10,
        "candidate_snippet": "AKIA1234567890ABCDEF",
        "raw_context": "AWS_KEY='AKIA1234567890ABCDEF'",
    }
    exit_code = main(["--candidate", json.dumps(candidate)])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data["credible_findings"]) == 1
    assert data["credible_findings"][0]["confidence"] == "HIGH"


def test_cli_file_arg(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(
        json.dumps([
            {
                "file_path": "tests/test.py",
                "candidate_snippet": "foo:bar",
                "raw_context": "cred = 'foo:bar'",
            }
        ]),
        encoding="utf-8",
    )
    exit_code = main(["--file", str(findings_file)])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data["discarded_candidates"]) == 1


def test_cli_subprocess_execution():
    candidate_json = json.dumps({
        "file_path": "config/db.env",
        "line_number": 4,
        "candidate_snippet": "postgres://user:secret123@localhost:5432/app",
        "raw_context": "DB_URL=postgres://user:secret123@localhost:5432/app",
    })
    cmd = [
        sys.executable,
        str(SCRIPTS_DIR / "rate_confidence.py"),
        "--candidate",
        candidate_json,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    output = json.loads(proc.stdout)
    assert len(output["credible_findings"]) == 1
    assert output["credible_findings"][0]["confidence"] == "MEDIUM"
