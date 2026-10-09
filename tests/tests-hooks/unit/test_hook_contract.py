"""
Unit tests for hooks/hook_contract.py
Comprehensive validation of hook data contracts, serialization,
stdin parsing edge cases, and protocol emitter functions.
"""
import io
import json
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from hooks.hook_contract import (
    CapacityLimits,
    CapacityStatus,
    Decision,
    DiscoveryReport,
    HookContext,
    HookResult,
    OversizedFile,
    ToolCall,
    emit_allow,
    emit_deny,
    emit_force_ask,
    emit_response,
    parse_stdin,
)

# ---------------------------------------------------------------------------
# Enums and Constants
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "decision, expected_value",
    [
        (Decision.ALLOW, "allow"),
        (Decision.DENY, "deny"),
        (Decision.ASK, "ask"),
        (Decision.FORCE_ASK, "force_ask"),
    ],
)
def test_decision_enum_values(decision: Decision, expected_value: str):
    assert decision.value == expected_value
    assert isinstance(decision, str)


@pytest.mark.parametrize(
    "status, expected_value",
    [
        (CapacityStatus.APPROVED, "APPROVED"),
        (CapacityStatus.CAPACITY_EXCEEDED, "CAPACITY_EXCEEDED"),
        (CapacityStatus.SIZE_EXCEEDED, "SIZE_EXCEEDED"),
        (CapacityStatus.VIOLATION, "VIOLATION"),
    ],
)
def test_capacity_status_enum_values(status: CapacityStatus, expected_value: str):
    assert status.value == expected_value
    assert isinstance(status, str)


# ---------------------------------------------------------------------------
# Data Models: CapacityLimits & OversizedFile
# ---------------------------------------------------------------------------

def test_capacity_limits_defaults_and_dict():
    limits = CapacityLimits()
    assert limits.max_files == 50
    assert limits.max_single_file_kb == 256
    assert limits.max_aggregate_mb == 2.0
    assert limits.max_line_length == 1000
    assert limits.max_snippet_kb == 50

    d = limits.to_dict()
    assert d == {
        "max_files": 50,
        "max_single_file_kb": 256,
        "max_aggregate_mb": 2.0,
        "max_line_length": 1000,
        "max_snippet_kb": 50,
    }


def test_capacity_limits_immutability():
    limits = CapacityLimits()
    with pytest.raises(FrozenInstanceError):
        limits.max_files = 100


def test_oversized_file_to_dict():
    of = OversizedFile(path="data/big.json", size_bytes=300000, size_kb=292.97)
    d = of.to_dict()
    assert d == {
        "path": "data/big.json",
        "size_bytes": 300000,
        "size_kb": 292.97,
    }


# ---------------------------------------------------------------------------
# Data Models: ToolCall, DiscoveryReport & HookResult
# ---------------------------------------------------------------------------

def test_tool_call_defaults():
    tc = ToolCall(name="view_file")
    assert tc.name == "view_file"
    assert tc.args == {}


def test_discovery_report_to_dict_with_nested_objects():
    limits = CapacityLimits(max_files=10)
    oversized = [
        OversizedFile(path="big1.bin", size_bytes=500000, size_kb=488.28),
        OversizedFile(path="big2.bin", size_bytes=600000, size_kb=585.94),
    ]
    report = DiscoveryReport(
        workspace_root="/mock/root",
        project_archetype="Node.js",
        total_files_enumerated=20,
        files_excluded_dependencies_build=5,
        eligible_candidates_count=13,
        total_eligible_bytes=45000,
        total_eligible_kb=43.95,
        capacity_status=CapacityStatus.APPROVED,
        capacity_limits=limits,
        eligible_files=["index.js", ".env"],
        oversized_files_excluded=oversized,
    )

    d = report.to_dict()
    assert d["workspace_root"] == "/mock/root"
    assert d["project_archetype"] == "Node.js"
    assert d["capacity_status"] == "APPROVED"
    assert d["capacity_limits"]["max_files"] == 10
    assert len(d["oversized_files_excluded"]) == 2
    assert d["oversized_files_excluded"][0]["path"] == "big1.bin"
    assert d["oversized_files_excluded"][1]["size_bytes"] == 600000


def test_hook_result_minimal_serialization():
    result = HookResult(decision=Decision.DENY)
    json_dict = result.to_json_dict()
    assert json_dict == {"decision": "deny"}
    assert "reason" not in json_dict
    assert "permissionOverrides" not in json_dict
    assert "overwrite" not in json_dict
    assert "discoveryReport" not in json_dict

    parsed = json.loads(result.to_json_str())
    assert parsed == {"decision": "deny"}


def test_hook_result_full_serialization():
    report = DiscoveryReport(
        workspace_root="/mock/root",
        project_archetype="Python",
        total_files_enumerated=10,
        files_excluded_dependencies_build=2,
        eligible_candidates_count=8,
        total_eligible_bytes=2048,
        total_eligible_kb=2.0,
        capacity_status=CapacityStatus.APPROVED,
    )
    result = HookResult(
        decision=Decision.ALLOW,
        reason="Passed all policies",
        discovery_report=report,
        permission_overrides=["read", "execute"],
        overwrite={"suggested_tool": "view_file"},
    )
    json_dict = result.to_json_dict()
    assert json_dict["decision"] == "allow"
    assert json_dict["reason"] == "Passed all policies"
    assert json_dict["permissionOverrides"] == ["read", "execute"]
    assert json_dict["overwrite"] == {"suggested_tool": "view_file"}
    assert json_dict["discoveryReport"]["project_archetype"] == "Python"

    parsed = json.loads(result.to_json_str())
    assert parsed["permissionOverrides"] == ["read", "execute"]
    assert parsed["overwrite"] == {"suggested_tool": "view_file"}


# ---------------------------------------------------------------------------
# HookContext Properties
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "arg_key, arg_val",
    [
        ("AbsolutePath", "/test/abs/path.py"),
        ("TargetFile", "/test/target/file.py"),
        ("file_path", "/test/file_path.py"),
        ("FilePath", "/test/FilePath.py"),
        ("SearchPath", "/test/SearchPath.py"),
        ("DirectoryPath", "/test/DirectoryPath/"),
    ],
)
def test_hook_context_target_file_resolution(arg_key: str, arg_val: str):
    ctx = HookContext(tool_call=ToolCall(name="view_file", args={arg_key: arg_val}))
    assert ctx.target_file == arg_val


def test_hook_context_target_file_none():
    ctx = HookContext(tool_call=ToolCall(name="unrelated_tool", args={"unrelated_arg": 123}))
    assert ctx.target_file is None


def test_hook_context_primary_workspace():
    # Workspace provided
    ctx = HookContext(
        tool_call=ToolCall(name="view_file"),
        workspace_paths=["/custom/workspace", "/secondary/workspace"],
    )
    assert ctx.primary_workspace == Path("/custom/workspace").resolve()

    # Workspace empty -> fallback to Path.cwd()
    ctx_empty = HookContext(
        tool_call=ToolCall(name="view_file"),
        workspace_paths=[],
    )
    assert ctx_empty.primary_workspace == Path.cwd().resolve()


# ---------------------------------------------------------------------------
# parse_stdin Function
# ---------------------------------------------------------------------------

def test_parse_stdin_with_full_valid_payload(monkeypatch):
    payload = {
        "toolCall": {"name": "run_command", "args": {"CommandLine": "ls -la"}},
        "stepIdx": 5,
        "conversationId": "conv-999",
        "workspacePaths": ["/workspace/proj"],
        "transcriptPath": "/logs/transcript.jsonl",
        "artifactDirectoryPath": "/artifacts/run1",
        "modelName": "gemini-3.8-flash",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    ctx = parse_stdin()

    assert ctx.tool_call.name == "run_command"
    assert ctx.tool_call.args == {"CommandLine": "ls -la"}
    assert ctx.step_idx == 5
    assert ctx.conversation_id == "conv-999"
    assert ctx.workspace_paths == ["/workspace/proj"]
    assert ctx.transcript_path == "/logs/transcript.jsonl"
    assert ctx.artifact_directory_path == "/artifacts/run1"
    assert ctx.model_name == "gemini-3.8-flash"
    assert ctx.raw_payload == payload


@pytest.mark.parametrize(
    "raw_input",
    [
        "",
        "   \n  \t ",
        "NOT_A_VALID_JSON",
        "{invalid_json: true}",
    ],
)
def test_parse_stdin_fail_closed_on_invalid_or_empty(monkeypatch, raw_input: str):
    monkeypatch.setattr(sys, "stdin", io.StringIO(raw_input))
    ctx = parse_stdin()
    assert ctx.tool_call.name == ""
    assert ctx.tool_call.args == {}
    assert ctx.step_idx == 0
    assert ctx.workspace_paths == []


def test_parse_stdin_partial_json(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"conversationId": "only-id"})))
    ctx = parse_stdin()
    assert ctx.tool_call.name == ""
    assert ctx.tool_call.args == {}
    assert ctx.conversation_id == "only-id"


# ---------------------------------------------------------------------------
# Protocol Emitters
# ---------------------------------------------------------------------------

def test_emit_response(capsys):
    result = HookResult(decision=Decision.ALLOW, reason="Test ok")
    with pytest.raises(SystemExit) as exc:
        emit_response(result, exit_code=0)

    assert exc.value.code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["decision"] == "allow"
    assert payload["reason"] == "Test ok"


def test_emit_response_custom_exit_code(capsys):
    result = HookResult(decision=Decision.DENY, reason="Failed policy")
    with pytest.raises(SystemExit) as exc:
        emit_response(result, exit_code=2)

    assert exc.value.code == 2
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["decision"] == "deny"


def test_emit_allow(capsys):
    with pytest.raises(SystemExit) as exc:
        emit_allow(reason="Allowed by contract")

    assert exc.value.code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"] == "allow"
    assert payload["reason"] == "Allowed by contract"


def test_emit_deny(capsys):
    with pytest.raises(SystemExit) as exc:
        emit_deny(reason="Denied by bounds")

    assert exc.value.code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"] == "deny"
    assert payload["reason"] == "Denied by bounds"


def test_emit_force_ask(capsys):
    with pytest.raises(SystemExit) as exc:
        emit_force_ask(reason="Confirmation required")

    assert exc.value.code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"] == "force_ask"
    assert payload["reason"] == "Confirmation required"

