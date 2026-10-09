"""
Consolidated Discovery Engine
Single Responsibility: Consolidates the 4 discrete discovery components
(ArchetypeDetector, ExclusionFilter, RiskPrioritizer, CapacityEvaluator) into
a unified, deterministic discovery execution and generates the canonical
DiscoveryReport matching the retired secret-scope-discovery specification.
Coordinates native filesystem discovery, pruning, risk ranking, and 5D capacity evaluation.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure plugin root is in sys.path when executed directly or via hook runner
_plugin_root = str(Path(__file__).resolve().parent.parent)
if _plugin_root not in sys.path:
    sys.path.insert(0, _plugin_root)


from hooks.components.archetype_detector import ArchetypeDetector
from hooks.components.capacity_evaluator import CapacityEvaluator
from hooks.components.exclusion_filter import ExclusionFilter
from hooks.components.risk_prioritizer import RiskPrioritizer
from hooks.hook_contract import (
    CapacityLimits,
    DiscoveryReport,
    HookResult,
)


class DiscoveryEngine:
    def __init__(
        self,
        workspace_root: str | Path,
        limits: CapacityLimits | None = None,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.limits = limits if limits is not None else CapacityLimits()

        # Instantiate decomposed components
        self.archetype_detector = ArchetypeDetector(self.workspace_root)
        self.exclusion_filter = ExclusionFilter(
            max_single_file_bytes=self.limits.max_single_file_kb * 1024
        )
        self.risk_prioritizer = RiskPrioritizer()
        self.capacity_evaluator = CapacityEvaluator(limits=self.limits)

    def run_discovery(self) -> tuple[HookResult, DiscoveryReport]:
        """
        Executes the 4-stage discovery pipeline:
        Returns: Tuple of (HookResult, DiscoveryReport)
        """
        # Stage 1: Detect project Archetype
        project_archetype = self.archetype_detector.detect()

        # Stage 2: Native Exclusion Pruning
        (
            total_enumerated,
            excluded_count,
            eligible_files_raw,
            oversized_files,
        ) = self.exclusion_filter.scan(self.workspace_root)

        #  Stage 3: Risk tiering and saturated prioritization (max 50)
        prioritized_files, _t1_count, _t2_count = self.risk_prioritizer.prioritize(
            eligible_files_raw, max_allocation=self.limits.max_files
        )

        # Stage 4: 5D Capacity Evaluation
        eval_result = self.capacity_evaluator.evaluate(
            candidate_files=prioritized_files,
            oversized_files=oversized_files,
            raw_candidate_count=len(eligible_files_raw),
        )

        # Convert paths to relative paths for clean output schema
        relative_eligible: list[str] = []
        for f in eval_result.eligible_files:
            try:
                relative_eligible.append(str(f.relative_to(self.workspace_root)))
            except ValueError:
                relative_eligible.append(str(f))

        # Build Canonical DiscoveryReport
        report = DiscoveryReport(
            workspace_root=str(self.workspace_root),
            project_archetype=project_archetype,
            total_files_enumerated=total_enumerated,
            files_excluded_dependencies_build=excluded_count,
            eligible_candidates_count=len(relative_eligible),
            total_eligible_bytes=eval_result.total_bytes,
            total_eligible_kb=eval_result.total_kb,
            capacity_status=eval_result.status,
            capacity_limits=self.limits,
            eligible_files=relative_eligible,
            oversized_files_excluded=oversized_files,
        )

        # Build Standard HookResult
        hook_result = HookResult(
            decision=eval_result.decision,
            reason=eval_result.reason,
            discovery_report=report,
        )

        return hook_result, report


def execute_discovery(
    workspace_root: str | Path,
    limits: CapacityLimits | None = None,
) -> tuple[HookResult, DiscoveryReport]:
    """Convenience functional interface for running discovery."""
    engine = DiscoveryEngine(workspace_root=workspace_root, limits=limits)
    return engine.run_discovery()


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    res, rep = execute_discovery(target)
    print(json.dumps(rep.to_dict(), indent=2))
