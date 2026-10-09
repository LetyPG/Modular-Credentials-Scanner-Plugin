"""
Integration tests for hooks/capacity_gate_hook.py lifecycle hook entrypoint.
Validates CLI execution, tool aliases, 5D capacity gates, cumulative state tracking,
session isolation, idempotency, and fail-safe degradation.
"""
from __future__ import annotations

import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

HOOK_SCRIPT = Path(__file__).resolve().parent.parent.parent.parent / "hooks" / "capacity_gate_hook.py"
STATE_DIR = Path("/tmp/.secret_auditor_state")


def run_hook_subprocess(payload: dict) -> tuple[int, dict, str]:
    """Helper to execute capacity_gate_hook.py with a JSON payload on stdin."""
    proc = subprocess.Popen(
        [sys.executable, str(HOOK_SCRIPT)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = proc.communicate(input=json.dumps(payload))
    parsed: dict = {}
    if stdout.strip():
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            pass
    return proc.returncode, parsed, stderr


@pytest.fixture
def unique_conversation_id() -> str:
    """Provides an isolated conversation ID and ensures its state file is cleaned up."""
    conv_id = f"test-conv-{uuid.uuid4().hex[:8]}"
    state_file = STATE_DIR / f"state_{conv_id}.json"
    yield conv_id
    if state_file.exists():
        state_file.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Happy Path & Tool Routing Integration
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tool_name", ["view_file", "read_file"])
@pytest.mark.parametrize("arg_key", ["AbsolutePath", "file_path", "TargetFile"])
def test_hook_allows_normal_file_with_tool_aliases(
    mock_workspace: Path,
    unique_conversation_id: str,
    tool_name: str,
    arg_key: str,
):
    """Verifies that normal files are allowed across both view_file/read_file and argument aliases."""
    target = mock_workspace / "main.py"
    payload = {
        "toolCall": {"name": tool_name, "args": {arg_key: str(target)}},
        "conversationId": unique_conversation_id,
        "workspacePaths": [str(mock_workspace)],
    }
    code, output, _err = run_hook_subprocess(payload)

    assert code == 0
    assert output.get("decision") == "allow"


def test_hook_discovery_on_grep_search(mock_workspace: Path, unique_conversation_id: str):
    """Verifies that grep_search triggers workspace discovery reporting."""
    payload = {
        "toolCall": {"name": "grep_search", "args": {"Query": "API_KEY"}},
        "conversationId": unique_conversation_id,
        "workspacePaths": [str(mock_workspace)],
    }
    code, output, _err = run_hook_subprocess(payload)

    assert code == 0
    assert output.get("decision") == "allow"
    report = output.get("discoveryReport", {})
    assert report.get("capacity_status") == "APPROVED"
    assert report.get("eligible_candidates_count", 0) > 0


@pytest.mark.parametrize("tool_name", ["list_dir", "run_command", "browser_navigate"])
def test_hook_allows_unrelated_tools(mock_workspace: Path, unique_conversation_id: str, tool_name: str):
    """Tools outside single-file read and discovery are allowed immediately by default."""
    payload = {
        "toolCall": {"name": tool_name, "args": {"CommandLine": "git status"}},
        "conversationId": unique_conversation_id,
        "workspacePaths": [str(mock_workspace)],
    }
    code, output, _err = run_hook_subprocess(payload)

    assert code == 0
    assert output.get("decision") == "allow"


# ---------------------------------------------------------------------------
# Dimension 2: Single-File Size Gate (DENY)
# ---------------------------------------------------------------------------

def test_hook_denies_oversized_file(mock_workspace: Path, unique_conversation_id: str):
    """Reading a file larger than 256 KB is denied to prevent context flooding."""
    target = mock_workspace / "large_dump.sql"
    payload = {
        "toolCall": {"name": "view_file", "args": {"AbsolutePath": str(target)}},
        "conversationId": unique_conversation_id,
        "workspacePaths": [str(mock_workspace)],
    }
    code, output, _err = run_hook_subprocess(payload)

    assert code == 0
    assert output.get("decision") == "deny"
    assert "MAX_SINGLE_FILE_SIZE_KB" in output.get("reason", "")


# ---------------------------------------------------------------------------
# Cumulative Session State & Gate Enforcement (Dimensions 1 & 3)
# ---------------------------------------------------------------------------

def test_hook_cumulative_count_gate_triggers_force_ask(mock_workspace: Path, unique_conversation_id: str):
    """When a session cumulatively reaches 50 scanned files, the 51st file triggers FORCE_ASK."""
    state_file = STATE_DIR / f"state_{unique_conversation_id}.json"
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    # Pre-populate session state with 50 files
    preloaded_state = {
        "scanned_files": [f"/mock/fake_file_{i}.py" for i in range(50)],
        "total_bytes": 5000,
    }
    state_file.write_text(json.dumps(preloaded_state), encoding="utf-8")

    target = mock_workspace / "main.py"
    payload = {
        "toolCall": {"name": "view_file", "args": {"AbsolutePath": str(target)}},
        "conversationId": unique_conversation_id,
        "workspacePaths": [str(mock_workspace)],
    }
    code, output, _err = run_hook_subprocess(payload)

    assert code == 0
    assert output.get("decision") == "force_ask"
    assert "MAX_FILES_TO_SCAN" in output.get("reason", "")


def test_hook_cumulative_aggregate_size_gate_triggers_force_ask(
    mock_workspace: Path,
    unique_conversation_id: str,
):
    """When a session's cumulative volume exceeds 2.0 MB, the next file triggers FORCE_ASK."""
    state_file = STATE_DIR / f"state_{unique_conversation_id}.json"
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    # Pre-populate session state with aggregate volume just over 2.0 MB (2,100,000 bytes)
    preloaded_state = {
        "scanned_files": ["/mock/large_existing.py"],
        "total_bytes": 2_100_000,
    }
    state_file.write_text(json.dumps(preloaded_state), encoding="utf-8")

    target = mock_workspace / "main.py"
    payload = {
        "toolCall": {"name": "view_file", "args": {"AbsolutePath": str(target)}},
        "conversationId": unique_conversation_id,
        "workspacePaths": [str(mock_workspace)],
    }
    code, output, _err = run_hook_subprocess(payload)

    assert code == 0
    assert output.get("decision") == "force_ask"
    assert "MAX_AGGREGATE_SCAN_SIZE_MB" in output.get("reason", "")


def test_hook_idempotent_read_same_file(mock_workspace: Path, unique_conversation_id: str):
    """Re-reading the same file within a conversation does not increment cumulative count or bytes."""
    target = mock_workspace / "main.py"
    payload = {
        "toolCall": {"name": "view_file", "args": {"AbsolutePath": str(target)}},
        "conversationId": unique_conversation_id,
        "workspacePaths": [str(mock_workspace)],
    }

    # First read
    code1, output1, _ = run_hook_subprocess(payload)
    assert code1 == 0
    assert output1.get("decision") == "allow"

    state_file = STATE_DIR / f"state_{unique_conversation_id}.json"
    state_after_first = json.loads(state_file.read_text(encoding="utf-8"))
    assert len(state_after_first["scanned_files"]) == 1

    # Second read of exact same file
    code2, output2, _ = run_hook_subprocess(payload)
    assert code2 == 0
    assert output2.get("decision") == "allow"

    state_after_second = json.loads(state_file.read_text(encoding="utf-8"))
    assert len(state_after_second["scanned_files"]) == 1
    assert state_after_second["total_bytes"] == state_after_first["total_bytes"]


def test_hook_session_state_isolation(mock_workspace: Path):
    """Distinct conversations maintain independent state files and limits."""
    conv_a = f"test-conv-iso-a-{uuid.uuid4().hex[:6]}"
    conv_b = f"test-conv-iso-b-{uuid.uuid4().hex[:6]}"

    state_file_a = STATE_DIR / f"state_{conv_a}.json"
    state_file_b = STATE_DIR / f"state_{conv_b}.json"
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    try:
        # Pre-fill Conversation A with 50 files (at capacity)
        state_file_a.write_text(
            json.dumps({"scanned_files": [f"/file_{i}" for i in range(50)], "total_bytes": 1000}),
            encoding="utf-8",
        )

        target = mock_workspace / "main.py"

        # Conversation B should still be allowed cleanly
        payload_b = {
            "toolCall": {"name": "view_file", "args": {"AbsolutePath": str(target)}},
            "conversationId": conv_b,
            "workspacePaths": [str(mock_workspace)],
        }
        code_b, output_b, _ = run_hook_subprocess(payload_b)
        assert code_b == 0
        assert output_b.get("decision") == "allow"
    finally:
        state_file_a.unlink(missing_ok=True)
        state_file_b.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Edge Cases & Fail-Safe Execution
# ---------------------------------------------------------------------------

def test_hook_non_existent_target_file_allows(mock_workspace: Path, unique_conversation_id: str):
    """If the target file does not exist, the hook delegates error handling to the tool."""
    missing_file = mock_workspace / "does_not_exist_on_disk.py"
    payload = {
        "toolCall": {"name": "view_file", "args": {"AbsolutePath": str(missing_file)}},
        "conversationId": unique_conversation_id,
        "workspacePaths": [str(mock_workspace)],
    }
    code, output, _err = run_hook_subprocess(payload)

    assert code == 0
    assert output.get("decision") == "allow"


def test_hook_empty_or_corrupt_stdin_fails_closed_safe():
    """Empty or unparseable input executes safely without non-zero crash exits."""
    proc = subprocess.Popen(
        [sys.executable, str(HOOK_SCRIPT)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, _stderr = proc.communicate(input="{corrupt_json: true}")

    assert proc.returncode == 0
    parsed = json.loads(stdout)
    assert parsed.get("decision") in ("allow", "deny", "force_ask")

