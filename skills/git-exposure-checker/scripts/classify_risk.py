"""
Deterministic Risk Classifier for Git Exposure State Taxonomy.
Maps identified Git exposure states to standardized risk tiers and assessments
"""
from __future__ import annotations

import argparse
import json
import sys
from enum import Enum
from typing import Any


class ExposureState(str, Enum):
    """Enumeration of all valid Git exposure states."""

    LOCAL_ONLY = "LOCAL_ONLY"
    LOCAL_IGNORED = "LOCAL_IGNORED"
    UNTRACKED_UNIGNORED = "UNTRACKED_UNIGNORED"
    TRACKED_DESPITE_IGNORE = "TRACKED_DESPITE_IGNORE"
    TRACKED_ACTIVE = "TRACKED_ACTIVE"
    COMMITTED_HISTORICAL = "COMMITTED_HISTORICAL"


class RiskLevel(str, Enum):
    """Standard risk levels assigned to exposure states."""

    LOW = "Low"
    HIGH = "High"
    CRITICAL = "Critical"


TAXONOMY_RULES: dict[ExposureState, dict[str, str]] = {
    ExposureState.LOCAL_ONLY: {
        "risk_level": RiskLevel.LOW.value,
        "description": "Target directory is not a Git repository. Exists only on local disk.",
        "risk_assessment": "LOW - Target directory is not a Git repository. Exists only on local disk.",
    },
    ExposureState.LOCAL_IGNORED: {
        "risk_level": RiskLevel.LOW.value,
        "description": "File is untracked and covered by .gitignore.",
        "risk_assessment": "LOW - File is untracked and covered by .gitignore.",
    },
    ExposureState.UNTRACKED_UNIGNORED: {
        "risk_level": RiskLevel.HIGH.value,
        "description": "File is untracked and NOT covered by .gitignore. Prone to accidental 'git add .'.",
        "risk_assessment": "HIGH - File is untracked and NOT covered by .gitignore. Prone to accidental 'git add .'.",
    },
    ExposureState.TRACKED_DESPITE_IGNORE: {
        "risk_level": RiskLevel.CRITICAL.value,
        "description": "File matches a .gitignore rule but is already tracked in the Git index.",
        "risk_assessment": "CRITICAL - File is tracked in Git index even though .gitignore specifies ignoring it.",
    },
    ExposureState.TRACKED_ACTIVE: {
        "risk_level": RiskLevel.CRITICAL.value,
        "description": "File is tracked in the Git index and part of the current tree.",
        "risk_assessment": "CRITICAL - File is tracked in the Git index and part of the current tree.",
    },
    ExposureState.COMMITTED_HISTORICAL: {
        "risk_level": RiskLevel.CRITICAL.value,
        "description": "File or secret pattern was confirmed present in one or more past commits.",
        "risk_assessment": "CRITICAL - File or secret pattern was confirmed present in one or more past commits.",
    },
}


def determine_state(
    is_git_repo: bool,
    is_tracked: bool,
    is_ignored: bool,
    in_history: bool = False,
) -> ExposureState:
    # Deterministically resolves the exposure state from exploratory git flags.
    if not is_git_repo:
        return ExposureState.LOCAL_ONLY

    if in_history:
        return ExposureState.COMMITTED_HISTORICAL

    if is_tracked:
        if is_ignored:
            return ExposureState.TRACKED_DESPITE_IGNORE
        return ExposureState.TRACKED_ACTIVE

    if is_ignored:
        return ExposureState.LOCAL_IGNORED

    return ExposureState.UNTRACKED_UNIGNORED


def classify_state(state_name: str) -> dict[str, str]:
    # Retrieves deterministic taxonomy information for a given exposure state.
    try:
        state = ExposureState(state_name.strip())
    except (ValueError, AttributeError) as err:
        valid_states = [s.value for s in ExposureState]
        msg = f"Unknown exposure state '{state_name}'. Valid states: {valid_states}"
        raise ValueError(msg) from err

    entry = TAXONOMY_RULES[state]
    return {
        "exposure_state": state.value,
        "risk_level": entry["risk_level"],
        "description": entry["description"],
        "risk_assessment": entry["risk_assessment"],
    }


def enrich_payload(payload: dict[str, Any]) -> dict[str, Any]:
    # Enriches an exploratory finding payload with deterministic risk classification.

    state_str = payload.get("exposure_state")
    if not state_str:
        if "is_git_repo" in payload and "is_tracked" in payload and "is_ignored" in payload:
            state = determine_state(
                is_git_repo=bool(payload["is_git_repo"]),
                is_tracked=bool(payload["is_tracked"]),
                is_ignored=bool(payload["is_ignored"]),
                in_history=bool(payload.get("in_history", False)),
            )
            state_str = state.value
        else:
            msg = "Payload must provide 'exposure_state' or ('is_git_repo', 'is_tracked', 'is_ignored')."
            raise ValueError(msg)

    classification = classify_state(state_str)
    enriched = dict(payload)
    enriched["exposure_state"] = classification["exposure_state"]
    enriched["risk_level"] = classification["risk_level"]
    enriched["risk_assessment"] = classification["risk_assessment"]
    return enriched


def _parse_bool(value: str) -> bool:
    val = value.strip().lower()
    if val in ("true", "1", "yes", "y"):
        return True
    if val in ("false", "0", "no", "n"):
        return False
    msg = f"Cannot parse boolean from '{value}'"
    raise argparse.ArgumentTypeError(msg)


def build_parser() -> argparse.ArgumentParser:
    """Creates argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        description="Deterministic Risk Classifier for Git Exposure State Taxonomy."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--state",
        "-s",
        type=str,
        help="Exposure state name (e.g. TRACKED_DESPITE_IGNORE)",
    )
    group.add_argument(
        "--enrich",
        "-e",
        type=str,
        help="JSON string payload to enrich with risk classification",
    )
    group.add_argument(
        "--stdin",
        action="store_true",
        help="Read JSON payload from standard input to enrich",
    )
    group.add_argument(
        "--list",
        "-l",
        action="store_true",
        help="Print complete taxonomy mapping as JSON",
    )

    # Optional boolean flags for direct state resolution
    parser.add_argument("--is-repo", type=_parse_bool, default=None, help="Is inside a git repository")
    parser.add_argument("--is-tracked", type=_parse_bool, default=None, help="Is tracked in git index")
    parser.add_argument("--is-ignored", type=_parse_bool, default=None, help="Is ignored by .gitignore")
    parser.add_argument(
        "--in-history",
        type=_parse_bool,
        default=False,
        help="Was confirmed present in past commits",
    )
    parser.add_argument(
        "--path",
        type=str,
        default=None,
        help="Optional file path to include in generated payload",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.list:
            output = {
                state.value: {
                    "risk_level": info["risk_level"],
                    "description": info["description"],
                    "risk_assessment": info["risk_assessment"],
                }
                for state, info in TAXONOMY_RULES.items()
            }
            print(json.dumps(output, indent=2))
            return 0

        if args.state:
            result = classify_state(args.state)
            print(json.dumps(result, indent=2))
            return 0

        if args.enrich:
            payload = json.loads(args.enrich)
            result = enrich_payload(payload)
            print(json.dumps(result, indent=2))
            return 0

        if args.stdin:
            raw_input = sys.stdin.read().strip()
            if not raw_input:
                sys.stderr.write("Error: Stdin was empty.\n")
                return 1
            payload = json.loads(raw_input)
            result = enrich_payload(payload)
            print(json.dumps(result, indent=2))
            return 0

        if args.is_repo is not None and args.is_tracked is not None and args.is_ignored is not None:
            state = determine_state(
                is_git_repo=args.is_repo,
                is_tracked=args.is_tracked,
                is_ignored=args.is_ignored,
                in_history=args.in_history,
            )
            payload: dict[str, Any] = {
                "is_git_repo": args.is_repo,
                "is_tracked": args.is_tracked,
                "is_ignored": args.is_ignored,
                "in_history": args.in_history,
                "exposure_state": state.value,
            }
            if args.path:
                payload["path"] = args.path
            result = enrich_payload(payload)
            print(json.dumps(result, indent=2))
            return 0

        parser.print_help(sys.stderr)
        return 1

    except (ValueError, json.JSONDecodeError, argparse.ArgumentTypeError) as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
