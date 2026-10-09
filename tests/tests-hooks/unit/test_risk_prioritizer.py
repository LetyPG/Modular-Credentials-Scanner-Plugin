"""
Unit tests for hooks/components/risk_prioritizer.py
Validates risk tier classification (Tier 1 vs Tier 2 vs Tier 3), CI/CD path matching,
case-insensitivity, deterministic sorting, and allocation saturation.
"""
from pathlib import Path

import pytest

from hooks.components.risk_prioritizer import RiskPrioritizer

# ---------------------------------------------------------------------------
# Tier 1 Classification (Parametrized Patterns & CI/CD Paths)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "file_path_str",
    [
        # Cryptographic keys and certificates
        "id_rsa",
        "id_rsa.pub",
        "id_ed25519",
        "server.pem",
        "private.key",
        "cert.crt",
        "ca.cer",
        "bundle.p12",
        "cert.pfx",
        "auth.pkcs12",
        # Env and secret configurations
        ".env",
        ".env.local",
        ".env.production",
        "production.env",
        "staging.env.bak",
        # Common configuration formats
        "config.yaml",
        "values.yml",
        "appsettings.json",
        "pyproject.toml",
        "settings.ini",
        "pom.xml",
        "application.properties",
        "nginx.conf",
        "setup.cfg",
        # CI/CD and deployment configurations
        "Dockerfile",
        "Dockerfile.dev",
        "docker-compose.yml",
        "docker-compose.override.yaml",
        "Jenkinsfile",
        "Jenkinsfile.build",
        "main.tf",
        "terraform.tfvars",
        # CI/CD path matching
        ".github/workflows/deploy.yml",
        "subproject/.github/workflows/ci.yaml",
        ".gitlab-ci.yml",
        "sub/.gitlab-ci/pipeline.yml",
        "azure-pipelines.yml",
        "pipelines/azure-pipelines-ci.yaml",
        # Case-insensitivity checks
        "ID_RSA.KEY",
        "DOCKERFILE",
        "CONFIG.JSON",
        "SERVER.PEM",
    ],
)
def test_get_tier_classifies_tier_1_correctly(file_path_str: str):
    prioritizer = RiskPrioritizer()
    assert prioritizer.get_tier(Path(file_path_str)) == 1


# ---------------------------------------------------------------------------
# Tier 2 Classification (Parametrized Source & Scripting Patterns)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "file_path_str",
    [
        # Shell and automation scripts
        "entrypoint.sh",
        "deploy.bash",
        "setup.zsh",
        # Backend and Systems Languages
        "main.py",
        "app.go",
        "Server.java",
        "Program.cs",
        "script.rb",
        "index.php",
        "lib.rs",
        "main.c",
        "util.cpp",
        "header.h",
        "App.swift",
        "Main.kt",
        "Service.scala",
        "runner.pl",
        "init.lua",
        # Frontend and Web
        "index.js",
        "component.jsx",
        "service.ts",
        "App.tsx",
        # Case-insensitivity checks
        "MAIN.PY",
        "UTIL.SH",
        "APP.TS",
    ],
)
def test_get_tier_classifies_tier_2_correctly(file_path_str: str):
    prioritizer = RiskPrioritizer()
    assert prioritizer.get_tier(Path(file_path_str)) == 2


# ---------------------------------------------------------------------------
# Tier 3 Classification (Fallback / General Documents)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "file_path_str",
    [
        "README.md",
        "CONTRIBUTING.markdown",
        "LICENSE",
        "notes.txt",
        "document.html",
        "dataset.csv",
        "data.tsv",
        "unrecognized.xyz",
        "changelog.rst",
    ],
)
def test_get_tier_classifies_tier_3_fallback(file_path_str: str):
    prioritizer = RiskPrioritizer()
    assert prioritizer.get_tier(Path(file_path_str)) == 3


# ---------------------------------------------------------------------------
# Prioritization, Saturation & In-Tier Stable Sorting
# ---------------------------------------------------------------------------

def test_risk_prioritizer_saturation_across_all_tiers(tmp_path: Path):
    prioritizer = RiskPrioritizer()

    # Create 5 Tier 1, 10 Tier 2, and 10 Tier 3 files (total 25)
    t1_files = [tmp_path / f".env.{i}" for i in range(5)]
    t2_files = [tmp_path / f"source_{i}.py" for i in range(10)]
    t3_files = [tmp_path / f"doc_{i}.txt" for i in range(10)]

    # Provide mixed order: Tier 3 first, then Tier 2, then Tier 1
    mixed_input = t3_files + t2_files + t1_files

    # Request allocation capped at 12 files
    prioritized, t1_count, t2_count = prioritizer.prioritize(mixed_input, max_allocation=12)

    assert len(prioritized) == 12
    # All 5 Tier 1 files must be included
    assert t1_count == 5
    # The remaining 7 slots must be filled with Tier 2 files
    assert t2_count == 7

    # Validate strict tier sequence: Tier 1 first, then Tier 2
    for f in prioritized[:5]:
        assert prioritizer.get_tier(f) == 1
    for f in prioritized[5:12]:
        assert prioritizer.get_tier(f) == 2


def test_risk_prioritizer_in_tier_stable_sort(tmp_path: Path):
    """Files within the same tier should be sorted by path depth (parts length), then alphabetically."""
    deep_dir = tmp_path / "deep" / "nested" / "sub"
    deep_dir.mkdir(parents=True)
    shallow_dir = tmp_path / "shallow"
    shallow_dir.mkdir()

    # Three Tier 1 files at different depths and names
    f_deep = deep_dir / "config.json"
    f_shallow_b = shallow_dir / "b_config.json"
    f_shallow_a = shallow_dir / "a_config.json"
    f_root = tmp_path / "config.json"

    for f in (f_deep, f_shallow_b, f_shallow_a, f_root):
        f.write_text("{}", encoding="utf-8")

    prioritizer = RiskPrioritizer()
    prioritized, t1_count, _ = prioritizer.prioritize(
        [f_deep, f_shallow_b, f_shallow_a, f_root],
        max_allocation=10,
    )

    assert t1_count == 4
    # Root (fewest parts) should come first
    assert prioritized[0] == f_root
    # Shallow A before Shallow B alphabetically
    assert prioritized[1] == f_shallow_a
    assert prioritized[2] == f_shallow_b
    # Deep (most parts) should come last
    assert prioritized[3] == f_deep


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

def test_risk_prioritizer_empty_list():
    prioritizer = RiskPrioritizer()
    prioritized, t1_count, t2_count = prioritizer.prioritize([], max_allocation=50)
    assert prioritized == []
    assert t1_count == 0
    assert t2_count == 0


def test_risk_prioritizer_zero_allocation(tmp_path: Path):
    prioritizer = RiskPrioritizer()
    f = tmp_path / ".env"
    prioritized, t1_count, t2_count = prioritizer.prioritize([f], max_allocation=0)
    assert prioritized == []
    assert t1_count == 0
    assert t2_count == 0


def test_risk_prioritizer_candidates_less_than_max_allocation(tmp_path: Path):
    prioritizer = RiskPrioritizer()
    f1 = tmp_path / ".env"
    f2 = tmp_path / "main.py"
    prioritized, t1_count, t2_count = prioritizer.prioritize([f1, f2], max_allocation=50)
    assert len(prioritized) == 2
    assert t1_count == 1
    assert t2_count == 1

