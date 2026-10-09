"""
Integration tests for hooks/discovery_engine.py
Validates the end-to-end 4-stage discovery pipeline:
Archetype detection, filesystem pruning, risk prioritization, and 5D capacity gating.
"""
from pathlib import Path

import pytest

from hooks.discovery_engine import DiscoveryEngine, execute_discovery
from hooks.hook_contract import CapacityLimits, CapacityStatus, Decision

# ---------------------------------------------------------------------------
# Happy Path: Multi-Ecosystem End-to-End Pipeline
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "marker_file, source_file, expected_archetype",
    [
        ("pyproject.toml", "main.py", "Python"),
        ("package.json", "index.js", "Node.js"),
        ("go.mod", "main.go", "Go"),
        ("Cargo.toml", "main.rs", "Rust"),
    ],
)
def test_discovery_engine_ecosystem_pipeline(
    tmp_path: Path,
    marker_file: str,
    source_file: str,
    expected_archetype: str,
):
    """Verifies complete discovery pipeline across varied project ecosystems."""
    (tmp_path / marker_file).write_text("{}", encoding="utf-8")
    (tmp_path / source_file).write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / ".env").write_text("SECRET=123\n", encoding="utf-8")

    # Excluded dependency directory to confirm pruning integration
    dep_dir = tmp_path / "node_modules" / "pkg"
    dep_dir.mkdir(parents=True)
    (dep_dir / "index.js").write_text("module.exports = {};", encoding="utf-8")

    hook_result, report = execute_discovery(tmp_path)

    assert hook_result.decision == Decision.ALLOW
    assert report.capacity_status == CapacityStatus.APPROVED
    assert report.project_archetype == expected_archetype
    assert report.total_files_enumerated >= 3
    assert report.files_excluded_dependencies_build >= 1

    # Tier 1 and 2 files should be eligible with relative path formatting
    assert ".env" in report.eligible_files
    assert source_file in report.eligible_files
    assert not any("node_modules" in f for f in report.eligible_files)


def test_discovery_engine_full_run_with_mock_workspace(mock_workspace: Path):
    """Verifies end-to-end discovery on realistic complex mock workspace."""
    engine = DiscoveryEngine(workspace_root=mock_workspace)
    hook_result, report = engine.run_discovery()

    assert hook_result.decision == Decision.ALLOW
    assert report.capacity_status == CapacityStatus.APPROVED
    assert "Polyglot" in report.project_archetype
    assert report.total_files_enumerated > 0
    assert report.files_excluded_dependencies_build > 0

    # Verify Tier 1 critical files are prioritized in eligible files
    assert any(f.endswith(".env") for f in report.eligible_files)
    assert any("deploy.yml" in f for f in report.eligible_files)
    assert not any("node_modules" in f for f in report.eligible_files)
    assert not any("bundle.min.js" in f for f in report.eligible_files)

    # Verify oversized file was captured in report
    assert len(report.oversized_files_excluded) == 1
    assert "large_dump.sql" in report.oversized_files_excluded[0].path


@pytest.mark.parametrize("path_converter", [str, Path])
def test_discovery_engine_workspace_root_type_handling(tmp_path: Path, path_converter):
    """Verifies DiscoveryEngine accepts both str and Path instances for workspace_root."""
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    engine = DiscoveryEngine(workspace_root=path_converter(tmp_path))
    hook_result, report = engine.run_discovery()

    assert hook_result.decision == Decision.ALLOW
    assert report.workspace_root == str(tmp_path.resolve())


# ---------------------------------------------------------------------------
# Capacity Bounding Gates (Parametrized Capacity Gate Invariants)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "max_files, max_aggregate_mb, expected_status, expected_decision",
    [
        (50, 2.0, CapacityStatus.APPROVED, Decision.ALLOW),
        (2, 2.0, CapacityStatus.CAPACITY_EXCEEDED, Decision.FORCE_ASK),
        (50, 0.005, CapacityStatus.SIZE_EXCEEDED, Decision.FORCE_ASK),
    ],
)
def test_discovery_engine_capacity_gates(
    tmp_path: Path,
    max_files: int,
    max_aggregate_mb: float,
    expected_status: CapacityStatus,
    expected_decision: Decision,
):
    """Verifies capacity boundaries trigger appropriate gate decisions deterministically."""
    # Create 4 files of ~3 KB each (total ~12 KB)
    for i in range(4):
        f = tmp_path / f"source_{i}.py"
        f.write_text("data = '" + "A" * 3000 + "'\n", encoding="utf-8")

    limits = CapacityLimits(max_files=max_files, max_aggregate_mb=max_aggregate_mb)
    hook_result, report = execute_discovery(tmp_path, limits=limits)

    assert hook_result.decision == expected_decision
    assert report.capacity_status == expected_status
    assert report.capacity_limits.max_files == max_files
    assert report.capacity_limits.max_aggregate_mb == max_aggregate_mb


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

def test_discovery_engine_empty_workspace(tmp_path: Path):
    """Verifies discovery on empty workspace executes cleanly without errors."""
    hook_result, report = execute_discovery(tmp_path)

    assert hook_result.decision == Decision.ALLOW
    assert report.capacity_status == CapacityStatus.APPROVED
    assert report.project_archetype == "Generic"
    assert report.total_files_enumerated == 0
    assert report.eligible_candidates_count == 0
    assert report.eligible_files == []


def test_discovery_engine_workspace_with_only_excluded_assets(tmp_path: Path):
    """Verifies workspace containing exclusively non-auditable assets produces zero candidates."""
    (tmp_path / "bundle.min.js").write_text("var a=1;", encoding="utf-8")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")

    hook_result, report = execute_discovery(tmp_path)

    assert hook_result.decision == Decision.ALLOW
    assert report.capacity_status == CapacityStatus.APPROVED
    assert report.files_excluded_dependencies_build == 3
    assert report.eligible_candidates_count == 0
    assert report.eligible_files == []


# ---------------------------------------------------------------------------
# Negative Tests
# ---------------------------------------------------------------------------

def test_negative_discovery_engine_non_existent_workspace(tmp_path: Path):
    """Verifies that running discovery on a non-existent directory raises FileNotFoundError."""
    missing_dir = tmp_path / "missing_folder"

    with pytest.raises(FileNotFoundError, match="Workspace root does not exist"):
        execute_discovery(missing_dir)

