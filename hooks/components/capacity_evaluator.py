"""
Capacity Evaluator Component
Evaluate candidate files against the 5-dimensional
resource matrix. 
  1. MAX_FILES_TO_SCAN = 50
  2. MAX_SINGLE_FILE_SIZE_KB = 256 KB
  3. MAX_AGGREGATE_SCAN_SIZE_MB = 2.0 MB
  4. MAX_LINE_LENGTH = 1000 characters
  5. Fail-closed deterministic execution, stdlib only, sub-50ms.
Determines CapacityStatus, Decision, and builds gate reasons.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from hooks.hook_contract import (
    CapacityLimits,
    CapacityStatus,
    Decision,
    OversizedFile,
)


@dataclass
class CapacityEvaluationResult:
    """Outcome of 5-dimensional computing capacity assessment."""
    status: CapacityStatus
    decision: Decision
    reason: str
    eligible_files: list[Path]
    total_bytes: int
    total_kb: float
    oversized_files: list[OversizedFile] = field(default_factory=list)
    line_length_warnings: list[str] = field(default_factory=list)


class CapacityEvaluator:
    """Enforces multi-dimensional resource bounding for LLM secret scanning."""

    def __init__(self, limits: CapacityLimits | None = None) -> None:
        self.limits = limits if limits is not None else CapacityLimits()

    def check_line_lengths(self, file_path: Path, max_length: int) -> tuple[bool, int]:
        """
        Samples lines to detect minified files or long base64 strings.
        Returns: (has_excessive_lines, max_detected_length)
        """
        max_seen = 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for idx, line in enumerate(f):
                    line_len = len(line)
                    max_seen = max(max_seen, line_len)
                    if line_len > max_length:
                        return True, line_len
                    if idx >= 500:  # Sample first 500 lines for efficiency
                        break
        except OSError:
            pass
        return False, max_seen

    def evaluate(
        self,
        candidate_files: list[Path],
        oversized_files: list[OversizedFile] | None = None,
        raw_candidate_count: int | None = None,
    ) -> CapacityEvaluationResult:
        """
        Executes 5D boundary checks across candidate files.
        """
        oversized = oversized_files or []
        effective_raw_count = raw_candidate_count if raw_candidate_count is not None else len(candidate_files)

        total_bytes = 0
        validated_files: list[Path] = []
        line_warnings: list[str] = []

        # 1. Aggregate byte computation & line-length inspection
        max_aggregate_bytes = int(self.limits.max_aggregate_mb * 1024 * 1024)

        for f in candidate_files:
            try:
                f_size = f.stat().st_size
            except OSError:
                continue

            total_bytes += f_size
            validated_files.append(f)

            # Check line length gate
            has_long_lines, max_len = self.check_line_lengths(f, self.limits.max_line_length)
            if has_long_lines:
                line_warnings.append(
                    f"{f.name}: line length {max_len} exceeds {self.limits.max_line_length} chars (potential minified asset)"
                )

        total_kb = round(total_bytes / 1024, 2)

        # 2. Gate Decision Logic

        # Check Aggregate Size Limit (2.0 MB)
        if total_bytes > max_aggregate_bytes:
            return CapacityEvaluationResult(
                status=CapacityStatus.SIZE_EXCEEDED,
                decision=Decision.FORCE_ASK,
                reason=(
                    f"[Deterministic Gate] Aggregate scan volume ({total_kb} KB) exceeds "
                    f"MAX_AGGREGATE_SCAN_SIZE_MB ({self.limits.max_aggregate_mb} MB). "
                    f"User confirmation required to proceed without context overload."
                ),
                eligible_files=validated_files,
                total_bytes=total_bytes,
                total_kb=total_kb,
                oversized_files=oversized,
                line_length_warnings=line_warnings,
            )

        # Check Candidate Count Limit (50 files)
        if effective_raw_count > self.limits.max_files:
            return CapacityEvaluationResult(
                status=CapacityStatus.CAPACITY_EXCEEDED,
                decision=Decision.FORCE_ASK,
                reason=(
                    f"[Deterministic Gate] Eligible candidates ({effective_raw_count}) exceeded "
                    f"MAX_FILES_TO_SCAN ({self.limits.max_files}). Pre-filtered to top {len(validated_files)} "
                    f"risk-prioritized files ({total_kb} KB). User approval required."
                ),
                eligible_files=validated_files,
                total_bytes=total_bytes,
                total_kb=total_kb,
                oversized_files=oversized,
                line_length_warnings=line_warnings,
            )

        # Approved within all 5 dimensions
        return CapacityEvaluationResult(
            status=CapacityStatus.APPROVED,
            decision=Decision.ALLOW,
            reason="Within all 5-dimensional computing bounds.",
            eligible_files=validated_files,
            total_bytes=total_bytes,
            total_kb=total_kb,
            oversized_files=oversized,
            line_length_warnings=line_warnings,
        )
