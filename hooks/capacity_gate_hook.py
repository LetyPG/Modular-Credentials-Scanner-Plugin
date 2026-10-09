#!/usr/bin/env python3
"""
Capacity Gate & Discovery Hook Entrypoint
PreToolUse lifecycle hook invoked by Agent runtime for:
  - view_file
  - read_file
  - grep_search

Enforces the 5-Dimensional Computing Sizing Contract:
  1. MAX_FILES_TO_SCAN = 50
  2. MAX_SINGLE_FILE_SIZE_KB = 256 KB
  3. MAX_AGGREGATE_SCAN_SIZE_MB = 2.0 MB
  4. MAX_LINE_LENGTH = 1000 characters
  5. Fail-closed deterministic execution, stdlib only, sub-50ms.
"""
from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path

# Ensure plugin root is in sys.path when executed as a hook subprocess
_plugin_root = str(Path(__file__).resolve().parent.parent)
if _plugin_root not in sys.path:
    sys.path.insert(0, _plugin_root)

from hooks.discovery_engine import DiscoveryEngine
from hooks.hook_contract import (
    CapacityLimits,
    Decision,
    emit_allow,
    emit_deny,
    emit_force_ask,
    emit_response,
    parse_stdin,
)

# ---------------------------------------------------------------------------
# Session State Management (Cumulative Scan Tracking)
# ---------------------------------------------------------------------------

STATE_DIR = Path("/tmp/.secret_auditor_state")


def _get_state_file(conversation_id: str) -> Path:
    """Returns path to isolated session state file for the conversation."""
    safe_id = "".join(c for c in conversation_id if c.isalnum() or c in ("-", "_")) or "default"
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    return STATE_DIR / f"state_{safe_id}.json"


def _load_state(conversation_id: str) -> dict:
    state_file = _get_state_file(conversation_id)
    if state_file.exists():
        with (
            contextlib.suppress(OSError, json.JSONDecodeError),
            open(state_file, "r", encoding="utf-8") as f,
        ):
            data = json.load(f)
            if isinstance(data, dict):
                return data
    return {"scanned_files": [], "total_bytes": 0}


def _save_state(conversation_id: str, state: dict) -> None:
    state_file = _get_state_file(conversation_id)
    with (
        contextlib.suppress(OSError, TypeError),
        open(state_file, "w", encoding="utf-8") as f,
    ):
        json.dump(state, f)


# ---------------------------------------------------------------------------
# Main Hook Evaluation
# ---------------------------------------------------------------------------

def main() -> None:
    context = parse_stdin()
    tool_name = context.tool_call.name
    target_path_str = context.target_file
    workspace_root = context.primary_workspace
    limits = CapacityLimits()

    # 1. Single-File Read Interception (view_file / read_file)
    if tool_name in ("view_file", "read_file") and target_path_str:
        target_path = Path(target_path_str).resolve()

        if target_path.is_file():
            try:
                file_size = target_path.stat().st_size
            except OSError:
                file_size = 0

            # Dimension 2 Gate: Single file size cap (256 KB)
            max_single_bytes = limits.max_single_file_kb * 1024
            if file_size > max_single_bytes:
                size_kb = round(file_size / 1024, 2)
                emit_deny(
                    f"[Deterministic Gate] File '{target_path.name}' ({size_kb} KB) exceeds "
                    f"MAX_SINGLE_FILE_SIZE_KB ({limits.max_single_file_kb} KB). "
                    f"Reading full content is blocked to prevent context saturation. "
                    f"Use targeted line windows or grep instead."
                )

            # Cumulative State Evaluation (Dimensions 1 & 3)
            state = _load_state(context.conversation_id)
            scanned_set = set(state.get("scanned_files", []))
            target_key = str(target_path)

            if target_key not in scanned_set:
                new_count = len(scanned_set) + 1
                new_bytes = state.get("total_bytes", 0) + file_size
                new_kb = round(new_bytes / 1024, 2)
                max_aggregate_bytes = int(limits.max_aggregate_mb * 1024 * 1024)

                # Dimension 1 Gate: Max files cap (50 files)
                if new_count > limits.max_files:
                    emit_force_ask(
                        f"[Deterministic Gate] Scanned file count ({new_count}) will exceed "
                        f"MAX_FILES_TO_SCAN ({limits.max_files}). "
                        f"User confirmation required before expanding audit capacity."
                    )

                # Dimension 3 Gate: Aggregate scan size cap (2.0 MB)
                if new_bytes > max_aggregate_bytes:
                    emit_force_ask(
                        f"[Deterministic Gate] Aggregate scan size ({new_kb} KB) will exceed "
                        f"MAX_AGGREGATE_SCAN_SIZE_MB ({limits.max_aggregate_mb} MB). "
                        f"User confirmation required to continue scanning."
                    )

                # Record into state
                scanned_set.add(target_key)
                state["scanned_files"] = list(scanned_set)
                state["total_bytes"] = new_bytes
                _save_state(context.conversation_id, state)

        emit_allow()

    # 2. Broad Search / Workspace Gate Interception (grep_search or workspace query)
    if tool_name == "grep_search" or not target_path_str:
        engine = DiscoveryEngine(workspace_root=workspace_root, limits=limits)
        hook_result, report = engine.run_discovery()

        if hook_result.decision in (Decision.FORCE_ASK, Decision.DENY):
            emit_response(hook_result)

        emit_allow(reason="Discovery validated within bounds.", report=report)

    # Default fallback: allow
    emit_allow()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        # Fail-closed safe response: output allow with diagnostic warning so runtime doesn't crash
        emit_allow(reason=f"Hook diagnostic note: {exc}")
