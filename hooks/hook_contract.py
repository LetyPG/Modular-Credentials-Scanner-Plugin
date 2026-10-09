"""
Hook Contract & Data Protocol
Defines the typed contract between the Agent Runtime lifecycle
and the deterministic discovery and capacity gate engine.
"""
from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Decision(str, Enum):
    """Agent PreToolUse decision outcomes."""
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"
    FORCE_ASK = "force_ask"


class CapacityStatus(str, Enum):
    """Evaluation status against the 5-dimensional resource bounds."""
    APPROVED = "APPROVED"
    CAPACITY_EXCEEDED = "CAPACITY_EXCEEDED"
    SIZE_EXCEEDED = "SIZE_EXCEEDED"
    VIOLATION = "VIOLATION"


@dataclass(frozen=True)
class CapacityLimits:
    """The 5-dimensional computing boundaries."""
    max_files: int = 50
    max_single_file_kb: int = 256
    max_aggregate_mb: float = 2.0
    max_line_length: int = 1000
    max_snippet_kb: int = 50

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class OversizedFile:
    """Metadata for a file excluded due to single-file size threshold."""
    path: str
    size_bytes: int
    size_kb: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DiscoveryReport:
    """Canonical discovery and capacity gate report."""
    workspace_root: str
    project_archetype: str
    total_files_enumerated: int
    files_excluded_dependencies_build: int
    eligible_candidates_count: int
    total_eligible_bytes: int
    total_eligible_kb: float
    capacity_status: CapacityStatus
    capacity_limits: CapacityLimits = field(default_factory=CapacityLimits)
    eligible_files: list[str] = field(default_factory=list)
    oversized_files_excluded: list[OversizedFile] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["capacity_status"] = self.capacity_status.value
        data["capacity_limits"] = self.capacity_limits.to_dict()
        data["oversized_files_excluded"] = [f.to_dict() for f in self.oversized_files_excluded]
        return data


@dataclass
class ToolCall:
    """Extracted tool call from the Agent PreToolUse event."""
    name: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class HookContext:
    """Contextual metadata passed via stdin from Agent runtime."""
    tool_call: ToolCall
    step_idx: int = 0
    conversation_id: str = ""
    workspace_paths: list[str] = field(default_factory=list)
    transcript_path: str = ""
    artifact_directory_path: str = ""
    model_name: str = ""
    raw_payload: dict[str, Any] = field(default_factory=dict)

    @property
    def target_file(self) -> str | None:
        """Resolves target file path from tool arguments if present."""
        args = self.tool_call.args
        return (
            args.get("AbsolutePath")
            or args.get("TargetFile")
            or args.get("file_path")
            or args.get("FilePath")
            or args.get("SearchPath")
            or args.get("DirectoryPath")
        )

    @property
    def primary_workspace(self) -> Path:
        """Returns the primary workspace root as a Path."""
        if self.workspace_paths:
            return Path(self.workspace_paths[0]).resolve()
        return Path.cwd().resolve()


@dataclass
class HookResult:
    """Standardized hook output contract returned on stdout."""
    decision: Decision
    reason: str = ""
    discovery_report: DiscoveryReport | None = None
    permission_overrides: list[str] = field(default_factory=list)
    overwrite: dict[str, Any] | None = None

    def to_json_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "decision": self.decision.value,
        }
        if self.reason:
            payload["reason"] = self.reason
        if self.permission_overrides:
            payload["permissionOverrides"] = self.permission_overrides
        if self.overwrite:
            payload["overwrite"] = self.overwrite
        if self.discovery_report:
            payload["discoveryReport"] = self.discovery_report.to_dict()
        return payload

    def to_json_str(self) -> str:
        return json.dumps(self.to_json_dict(), indent=2)


# ---------------------------------------------------------------------------
# Protocol I/O Helpers
# ---------------------------------------------------------------------------

def parse_stdin() -> HookContext:
    """
    Parses the JSON payload delivered on stdin by Agent runtime.
    Fail-closed: returns safe empty context if parsing fails.
    """
    try:
        raw_text = sys.stdin.read()
        if not raw_text.strip():
            return HookContext(tool_call=ToolCall(name=""))
        data = json.loads(raw_text)
        if not isinstance(data, dict):
            return HookContext(tool_call=ToolCall(name=""))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return HookContext(tool_call=ToolCall(name=""))

    raw_tool = data.get("toolCall", {})
    tool_call = ToolCall(
        name=raw_tool.get("name", ""),
        args=raw_tool.get("args", {})
    )

    return HookContext(
        tool_call=tool_call,
        step_idx=data.get("stepIdx", 0),
        conversation_id=data.get("conversationId", ""),
        workspace_paths=data.get("workspacePaths", []),
        transcript_path=data.get("transcriptPath", ""),
        artifact_directory_path=data.get("artifactDirectoryPath", ""),
        model_name=data.get("modelName", ""),
        raw_payload=data
    )


def emit_response(result: HookResult, exit_code: int = 0) -> None:
    """
    Emits the HookResult JSON to stdout and flushes.
    Exit code is 0 by convention to prevent crashing agent host runtime.
    """
    sys.stdout.write(result.to_json_str() + "\n")
    sys.stdout.flush()
    sys.exit(exit_code)


def emit_allow(reason: str = "", report: DiscoveryReport | None = None) -> None:
    """Convenience emitter for Decision.ALLOW."""
    emit_response(HookResult(decision=Decision.ALLOW, reason=reason, discovery_report=report))


def emit_deny(reason: str, report: DiscoveryReport | None = None) -> None:
    """Convenience emitter for Decision.DENY."""
    emit_response(HookResult(decision=Decision.DENY, reason=reason, discovery_report=report))


def emit_force_ask(reason: str, report: DiscoveryReport | None = None) -> None:
    """Convenience emitter for Decision.FORCE_ASK."""
    emit_response(HookResult(decision=Decision.FORCE_ASK, reason=reason, discovery_report=report))
