"""
Unit tests for hooks/components/capacity_evaluator.py
Validates 5-dimensional resource bounding, sampling boundaries,
line length auditing, fail-safe degradation, and negative thresholds.
"""
from pathlib import Path

import pytest

from hooks.components.capacity_evaluator import (
    CapacityEvaluationResult,
    CapacityEvaluator,
)
from hooks.hook_contract import (
    CapacityLimits,
    CapacityStatus,
    Decision,
    OversizedFile,
)

# ---------------------------------------------------------------------------
# check_line_lengths Method Validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "line_content, max_allowed, expected_violation, expected_max_len",
    [
        ("short line\n", 100, False, 11),
        ("x" * 50 + "\n", 51, False, 51),
        ("x" * 50 + "\n", 50, True, 51),
        ("x" * 100 + "\n", 80, True, 101),
    ],
)
def test_check_line_lengths_boundaries(
    tmp_path: Path,
    line_content: str,
    max_allowed: int,
    expected_violation: bool,
    expected_max_len: int,
):
    f = tmp_path / "sample.txt"
    f.write_text(line_content, encoding="utf-8")
    evaluator = CapacityEvaluator()
    has_long_lines, max_seen = evaluator.check_line_lengths(f, max_allowed)
    assert has_long_lines is expected_violation
    assert max_seen == expected_max_len


def test_check_line_lengths_500_line_sampling_cap(tmp_path: Path):
    """Lines beyond the 500-line sample limit should not be inspected."""
    f = tmp_path / "large_sampled.txt"
    # First 501 lines short, 502nd line is huge
    lines = ["short\n"] * 501 + ["X" * 2000 + "\n"]
    f.write_text("".join(lines), encoding="utf-8")

    evaluator = CapacityEvaluator()
    # max_length=100. Because 502nd line is never inspected (cutoff at idx >= 500), no violation
    has_long_lines, max_seen = evaluator.check_line_lengths(f, max_length=100)
    assert has_long_lines is False
    assert max_seen == 6  # length of "short\n"


def test_negative_capacity_check_line_lengths_os_error(tmp_path: Path):
    """When a file cannot be opened (e.g. non-existent), check_line_lengths handles OSError gracefully."""
    non_existent = tmp_path / "does_not_exist.txt"
    evaluator = CapacityEvaluator()
    has_long_lines, max_seen = evaluator.check_line_lengths(non_existent, max_length=100)
    assert has_long_lines is False
    assert max_seen == 0


# ---------------------------------------------------------------------------
# Positive Capacity Evaluation Scenarios
# ---------------------------------------------------------------------------

def test_capacity_evaluator_approved_defaults(tmp_path: Path):
    f1 = tmp_path / "app.py"
    f1.write_text("print('hello world')\n", encoding="utf-8")

    evaluator = CapacityEvaluator()
    result = evaluator.evaluate([f1], raw_candidate_count=1)

    assert isinstance(result, CapacityEvaluationResult)
    assert result.status == CapacityStatus.APPROVED
    assert result.decision == Decision.ALLOW
    assert result.total_bytes == f1.stat().st_size
    assert result.total_kb == round(f1.stat().st_size / 1024, 2)
    assert result.eligible_files == [f1]
    assert result.line_length_warnings == []
    assert result.oversized_files == []
    assert "Within all 5-dimensional" in result.reason


def test_capacity_evaluator_empty_candidates():
    evaluator = CapacityEvaluator()
    result = evaluator.evaluate([])

    assert result.status == CapacityStatus.APPROVED
    assert result.decision == Decision.ALLOW
    assert result.total_bytes == 0
    assert result.total_kb == 0.0
    assert result.eligible_files == []


def test_capacity_evaluator_raw_candidate_count_fallback(tmp_path: Path):
    f = tmp_path / "sample.py"
    f.write_text("test = True\n", encoding="utf-8")

    evaluator = CapacityEvaluator()
    # raw_candidate_count is None -> falls back to len(candidate_files)
    result = evaluator.evaluate([f], raw_candidate_count=None)
    assert result.status == CapacityStatus.APPROVED
    assert len(result.eligible_files) == 1


def test_capacity_evaluator_preserves_oversized_files_list(tmp_path: Path):
    f = tmp_path / "valid.py"
    f.write_text("x = 1\n", encoding="utf-8")
    oversized = [OversizedFile(path="dump.bin", size_bytes=500000, size_kb=488.28)]

    evaluator = CapacityEvaluator()
    result = evaluator.evaluate([f], oversized_files=oversized)

    assert result.oversized_files == oversized
    assert len(result.oversized_files) == 1


# ---------------------------------------------------------------------------
# Boundary & Parametrized Threshold Tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw_count, max_files, expected_status, expected_decision",
    [
        (50, 50, CapacityStatus.APPROVED, Decision.ALLOW),
        (51, 50, CapacityStatus.CAPACITY_EXCEEDED, Decision.FORCE_ASK),
        (10, 10, CapacityStatus.APPROVED, Decision.ALLOW),
        (11, 10, CapacityStatus.CAPACITY_EXCEEDED, Decision.FORCE_ASK),
    ],
)
def test_capacity_evaluator_file_count_boundaries(
    tmp_path: Path,
    raw_count: int,
    max_files: int,
    expected_status: CapacityStatus,
    expected_decision: Decision,
):
    f = tmp_path / "single.py"
    f.write_text("x = 1\n", encoding="utf-8")

    limits = CapacityLimits(max_files=max_files)
    evaluator = CapacityEvaluator(limits=limits)
    result = evaluator.evaluate([f], raw_candidate_count=raw_count)

    assert result.status == expected_status
    assert result.decision == expected_decision


# ---------------------------------------------------------------------------
# Negative Tests
# ---------------------------------------------------------------------------

def test_negative_capacity_unreadable_candidate_skipped(tmp_path: Path):
    """If a candidate file raises OSError on stat (e.g. deleted/inaccessible), it is omitted cleanly."""
    valid_file = tmp_path / "exists.py"
    valid_file.write_text("valid\n", encoding="utf-8")
    ghost_file = tmp_path / "deleted.py"  # Does not exist on disk

    evaluator = CapacityEvaluator()
    result = evaluator.evaluate([valid_file, ghost_file])

    assert result.status == CapacityStatus.APPROVED
    assert result.eligible_files == [valid_file]
    assert result.total_bytes == valid_file.stat().st_size


def test_negative_capacity_aggregate_size_exceeded(tmp_path: Path):
    """Aggregate volume exceeding max_aggregate_mb triggers SIZE_EXCEEDED and FORCE_ASK."""
    # Set max limit to 0.05 MB (~51,200 bytes)
    limits = CapacityLimits(max_aggregate_mb=0.05)
    evaluator = CapacityEvaluator(limits=limits)

    f = tmp_path / "medium_data.bin"
    f.write_bytes(b"A" * 60000)

    result = evaluator.evaluate([f], raw_candidate_count=1)

    assert result.status == CapacityStatus.SIZE_EXCEEDED
    assert result.decision == Decision.FORCE_ASK
    assert "MAX_AGGREGATE_SCAN_SIZE_MB" in result.reason
    assert "User confirmation required" in result.reason


def test_negative_capacity_file_count_exceeded(tmp_path: Path):
    """Eligible file count exceeding max_files triggers CAPACITY_EXCEEDED and FORCE_ASK."""
    files = []
    for i in range(5):
        f = tmp_path / f"file_{i}.py"
        f.write_text("pass\n", encoding="utf-8")
        files.append(f)

    limits = CapacityLimits(max_files=4)
    evaluator = CapacityEvaluator(limits=limits)
    result = evaluator.evaluate(files, raw_candidate_count=5)

    assert result.status == CapacityStatus.CAPACITY_EXCEEDED
    assert result.decision == Decision.FORCE_ASK
    assert "exceeded MAX_FILES_TO_SCAN" in result.reason


def test_negative_capacity_precedence_size_over_count(tmp_path: Path):
    """When both aggregate size and file count are breached, aggregate size check takes precedence."""
    limits = CapacityLimits(max_files=2, max_aggregate_mb=0.01)  # ~10 KB
    evaluator = CapacityEvaluator(limits=limits)

    f1 = tmp_path / "big1.txt"
    f1.write_bytes(b"A" * 8000)
    f2 = tmp_path / "big2.txt"
    f2.write_bytes(b"B" * 8000)  # Total 16,000 bytes > 10,240 bytes

    # Both count (5 > 2) and size (16 KB > 10 KB) are exceeded
    result = evaluator.evaluate([f1, f2], raw_candidate_count=5)

    assert result.status == CapacityStatus.SIZE_EXCEEDED
    assert result.decision == Decision.FORCE_ASK


def test_negative_capacity_excessive_line_length_warning(tmp_path: Path):
    """Lines exceeding max_line_length accumulate warnings in line_length_warnings."""
    limits = CapacityLimits(max_line_length=80)
    evaluator = CapacityEvaluator(limits=limits)

    f = tmp_path / "minified.js"
    f.write_text("var token = '" + "A" * 150 + "';\n", encoding="utf-8")

    result = evaluator.evaluate([f], raw_candidate_count=1)

    assert result.status == CapacityStatus.APPROVED
    assert result.decision == Decision.ALLOW
    assert len(result.line_length_warnings) == 1
    assert "exceeds 80 chars" in result.line_length_warnings[0]
    assert "potential minified asset" in result.line_length_warnings[0]

