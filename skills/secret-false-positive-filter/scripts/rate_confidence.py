"""Deterministic Confidence Rating and False-Positive Filter for candidate secrets.

Evaluates candidate credentials against known false-positive rules and assigns
standardized confidence levels (HIGH, MEDIUM, LOW) deterministically.
"""
from __future__ import annotations

import argparse
import base64
import json
import math
import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePath
from typing import Any, NamedTuple


class ConfidenceLevel(str, Enum):
    """Standardized confidence levels for candidate secret findings."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class DiscardCategory(str, Enum):
    """Categories for false-positive candidate discards."""

    DOCUMENTATION_PLACEHOLDER = "Category 1: Documentation & Placeholder Tokens"
    TEMPLATING_DYNAMIC_REFERENCE = "Category 2: Templating & Dynamic References"
    TEST_FIXTURE_MOCK = "Category 3: Test Fixtures & Local Mocking"
    METRIC_COUNTER_SCHEMA = "Category 4: Metric & Counter Names"


# ---------------------------------------------------------------------------
# Thresholds & Configuration Constants
# ---------------------------------------------------------------------------

MIN_ASSIGNMENT_LEN = 8
STRONG_CREDENTIAL_LEN = 16
ENTROPY_MEDIUM_THRESHOLD = 3.0
ENTROPY_HIGH_THRESHOLD = 3.5
MIN_HEX_SECRET_LEN = 32
MIN_BASE64_SECRET_LEN = 40

TEST_DIRECTORY_NAMES = frozenset({"test", "tests", "__tests__", "fixtures", "spec", "mocks"})

PLACEHOLDER_WORDS = frozenset({
    "your_api_key",
    "<insert-key-here>",
    "changeme",
    "replace_me",
    "example",
    "sample",
    "dummy",
    "placeholder",
    "akiaiosfodnn7example",
})

MOCK_CREDENTIALS = frozenset({
    "admin:admin",
    "admin:password",
    "user:test",
    "foo:bar",
    "test:test",
    "guest:guest",
})

MOCK_HOST_INDICATORS = frozenset({"localhost", "127.0.0.1"})

METRIC_INDICATORS = frozenset({
    "total_tokens",
    "input_tokens",
    "prompt_tokens",
    "output_tokens",
    "token_count",
})


# ---------------------------------------------------------------------------
# Vendor Signature & Pattern Definitions
# ---------------------------------------------------------------------------

class VendorPatternRule(NamedTuple):
    """Structured rule definition for vendor token signatures."""

    name: str
    pattern: re.Pattern[str]
    description: str


VENDOR_PATTERNS: list[VendorPatternRule] = [
    VendorPatternRule(
        name="AWS Access Key",
        pattern=re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
        description="Unambiguous AWS Access Key ID prefix and valid character format",
    ),
    VendorPatternRule(
        name="Google Cloud / Gemini API Key",
        pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        description="Unambiguous Google Cloud / Gemini API key prefix and length",
    ),
    VendorPatternRule(
        name="GitHub Token",
        pattern=re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b"),
        description="Unambiguous GitHub token prefix (ghp_/gho_/etc.) and length",
    ),
    VendorPatternRule(
        name="GitHub Fine-Grained PAT",
        pattern=re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{82}\b"),
        description="Unambiguous GitHub fine-grained PAT prefix and format",
    ),
    VendorPatternRule(
        name="Slack Token",
        pattern=re.compile(r"\bxox[bpar]-[0-9a-zA-Z-]{10,}\b"),
        description="Unambiguous Slack token prefix (xoxb/xoxp/xoxa/xoxr)",
    ),
    VendorPatternRule(
        name="Stripe Secret Key",
        pattern=re.compile(r"\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,}\b"),
        description="Unambiguous Stripe secret/restricted key prefix and format",
    ),
    VendorPatternRule(
        name="OpenAI API Key",
        pattern=re.compile(r"\bsk-(proj-)?[a-zA-Z0-9_\-]{32,}\b"),
        description="Unambiguous OpenAI API key prefix and length",
    ),
    VendorPatternRule(
        name="Hugging Face Token",
        pattern=re.compile(r"\bhf_[a-zA-Z0-9]{34,}\b"),
        description="Unambiguous Hugging Face user access token prefix",
    ),
    VendorPatternRule(
        name="Private Cryptographic Key",
        pattern=re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
        description="Verified private cryptographic key header block",
    ),
    VendorPatternRule(
        name="PuTTY Private Key",
        pattern=re.compile(r"PuTTY-User-Key-File-[0-9]+"),
        description="Verified PuTTY private key block",
    ),
]

DATABASE_URI_PATTERN = re.compile(
    r"\b(postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:]+:[^\s@]+@[^\s/:]+",
    re.IGNORECASE,
)

BASIC_AUTH_PATTERN = re.compile(
    r"\bhttps?://[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+",
    re.IGNORECASE,
)

GENERIC_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(api_key|apikey|secret|password|passwd|auth_token|access_token|private_key|client_secret|bearer)\s*[:=]\s*['\"]([^'\"]+)['\"]"
)

JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b"
)

HEX_STRING_PATTERN = re.compile(rf"\b[0-9a-fA-F]{{{MIN_HEX_SECRET_LEN},64}}\b")
BASE64_STRING_PATTERN = re.compile(rf"\b[A-Za-z0-9+/=]{{{MIN_BASE64_SECRET_LEN},}}\b")

TEMPLATE_PATTERNS = [
    re.compile(r"\{\{.*\}\}"),
    re.compile(r"\$\{[^}]+\}"),
    re.compile(r"\{[a-zA-Z0-9_]+\}"),
    re.compile(r"<[A-Z0-9_-]+>"),
    re.compile(r"process\.env\.[A-Z0-9_]+"),
    re.compile(r"os\.environ(?:\.get)?\([\"'][^\"']+[\"']\)"),
    re.compile(r"System\.getenv\([\"'][^\"']+[\"']\)"),
]

UUID_PATTERN = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Candidate Context Data Model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CandidateContext:
    """Normalized, immutable context representing an audited candidate secret."""

    file_path: str
    line_number: int
    snippet: str
    raw_context: str
    secret_type: str
    finding_id: str

    @property
    def combined_text(self) -> str:
        """Surrounding context merged with candidate snippet for inspection."""
        return f"{self.raw_context} {self.snippet}".strip()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CandidateContext:
        """Instantiates normalized CandidateContext from arbitrary dictionary inputs."""
        return cls(
            file_path=str(data.get("file_path", "")).strip(),
            line_number=int(data.get("line_number") or 0),
            snippet=str(data.get("candidate_snippet") or data.get("masked_sample") or ""),
            raw_context=str(data.get("raw_context") or data.get("surrounding_context") or ""),
            secret_type=str(data.get("secret_type") or data.get("signature_name") or ""),
            finding_id=str(data.get("id") or data.get("signature_id") or "SEC-000"),
        )


def _ensure_candidate_context(candidate: dict[str, Any] | CandidateContext) -> CandidateContext:
    """Coerces candidate dict or instance into CandidateContext."""
    if isinstance(candidate, CandidateContext):
        return candidate
    return CandidateContext.from_dict(candidate)


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def calculate_shannon_entropy(data: str) -> float:
    """Compute the Shannon entropy of a given string."""
    if not data:
        return 0.0
    length = len(data)
    frequencies: dict[str, int] = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    entropy = 0.0
    for count in frequencies.values():
        p_x = count / length
        entropy += -p_x * math.log2(p_x)
    return entropy


def is_valid_jwt_header(token: str) -> bool:
    """Verifies that the first segment of a suspected JWT decodes to valid JSON with 'alg'."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    header_b64 = parts[0]
    remainder = len(header_b64) % 4
    if remainder:
        header_b64 += "=" * (4 - remainder)
    try:
        header_bytes = base64.urlsafe_b64decode(header_b64)
        header_json = json.loads(header_bytes.decode("utf-8", errors="ignore"))
        return isinstance(header_json, dict) and "alg" in header_json
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return False


def is_in_test_directory(file_path: str) -> bool:
    """Deterministically checks if a path resides inside test or fixture suites."""
    if not file_path:
        return False
    parts = PurePath(file_path.replace("\\", "/")).parts
    return any(part in TEST_DIRECTORY_NAMES for part in parts)


# ---------------------------------------------------------------------------
# False-Positive Detection Logic
# ---------------------------------------------------------------------------

def check_false_positive(candidate: dict[str, Any] | CandidateContext) -> tuple[bool, str | None]:
    """Deterministically screens candidate against Category 1 to 4 discard rules.

    Returns:
        (is_false_positive, discard_reason)
    """
    ctx = _ensure_candidate_context(candidate)
    combined_lower = ctx.combined_text.lower()

    # Category 1: Documentation & Placeholder Tokens
    for placeholder in PLACEHOLDER_WORDS:
        if placeholder in combined_lower:
            return True, f"Documentation placeholder token matching '{placeholder}'"

    # Category 2: Templating & Dynamic References
    for template_re in TEMPLATE_PATTERNS:
        if template_re.search(ctx.combined_text):
            return True, f"Templating or dynamic code reference ({template_re.pattern})"

    # Category 3: Test Fixtures & Local Mocking
    if is_in_test_directory(ctx.file_path):
        return True, "Hardcoded candidate situated in test/fixture directory"

    for mock_cred in MOCK_CREDENTIALS:
        if mock_cred in combined_lower:
            return True, f"Well-known mock credential pattern '{mock_cred}'"

    snippet_lower = ctx.snippet.lower()
    for host in MOCK_HOST_INDICATORS:
        if snippet_lower == host:
            return True, f"Local loopback/mock host indicator '{host}'"
        if host in snippet_lower and not (
            DATABASE_URI_PATTERN.search(ctx.combined_text)
            or BASIC_AUTH_PATTERN.search(ctx.combined_text)
        ):
            return True, f"Local loopback/mock host indicator '{host}'"

    # Category 4: Metric & Counter Names, UUIDs, SVG/CSS
    for metric in METRIC_INDICATORS:
        if metric in combined_lower:
            return True, f"Code metric or counter schema reference '{metric}'"

    if ctx.snippet and UUID_PATTERN.search(ctx.snippet):
        return True, "Non-secret identifier matching standard UUID format"

    if 'd="M' in ctx.combined_text or "d='M" in ctx.combined_text:
        return True, "SVG vector path coordinate data"

    if (
        'class="' in ctx.combined_text or "className=" in ctx.combined_text
    ) and not re.search(r"(?i)(api_key|secret|password|token)", ctx.combined_text):
        return True, "CSS selector or UI class name hash"

    return False, None


# ---------------------------------------------------------------------------
# Confidence Rating Matrix Evaluation
# ---------------------------------------------------------------------------

def rate_confidence(candidate: dict[str, Any] | CandidateContext) -> tuple[ConfidenceLevel, str]:
    """Deterministically maps a candidate finding to HIGH, MEDIUM, or LOW confidence.

    Rules:
    - HIGH: Unambiguous vendor prefix, valid length & charset, or private crypto key header.
    - MEDIUM: Generic variable assignment with long random string, valid DB URI with password, or verified JWT.
    - LOW: High-entropy string in generic source code without explicit credential variable name.
    """
    ctx = _ensure_candidate_context(candidate)

    # --- Check for HIGH Confidence ---
    for rule in VENDOR_PATTERNS:
        if rule.pattern.search(ctx.combined_text) or (
            ctx.secret_type and rule.name.lower() in ctx.secret_type.lower()
        ):
            return ConfidenceLevel.HIGH, rule.description

    # --- Check for MEDIUM Confidence ---
    # 1. Database Connection String with embedded password
    if DATABASE_URI_PATTERN.search(ctx.combined_text):
        return ConfidenceLevel.MEDIUM, "Valid database connection URI with embedded credentials"

    # 2. Basic Auth URL
    if BASIC_AUTH_PATTERN.search(ctx.combined_text):
        return ConfidenceLevel.MEDIUM, "Valid URL with embedded basic authentication credentials"

    # 3. Verified JWT Token
    jwt_match = JWT_PATTERN.search(ctx.combined_text)
    if jwt_match:
        token_str = jwt_match.group(0)
        if is_valid_jwt_header(token_str):
            return ConfidenceLevel.MEDIUM, "Verified JSON Web Token (JWT) with valid header and signature segment"
        return ConfidenceLevel.MEDIUM, "Structured token matching 3-segment JWT syntax"

    # 4. Generic Variable Assignment
    assignment_match = GENERIC_ASSIGNMENT_PATTERN.search(ctx.combined_text)
    if assignment_match:
        val = assignment_match.group(2)
        entropy = calculate_shannon_entropy(val)
        if len(val) >= STRONG_CREDENTIAL_LEN or (
            len(val) >= MIN_ASSIGNMENT_LEN and entropy >= ENTROPY_MEDIUM_THRESHOLD
        ):
            return (
                ConfidenceLevel.MEDIUM,
                f"Generic credential variable assignment with high-entropy literal (entropy={entropy:.2f}, length={len(val)})",
            )

    # --- Check for LOW Confidence ---
    hex_match = HEX_STRING_PATTERN.search(ctx.combined_text)
    if hex_match:
        val = hex_match.group(0)
        return (
            ConfidenceLevel.LOW,
            f"High-entropy continuous hexadecimal literal ({len(val)} chars) without credential assignment",
        )

    b64_match = BASE64_STRING_PATTERN.search(ctx.combined_text)
    if b64_match:
        val = b64_match.group(0)
        return (
            ConfidenceLevel.LOW,
            f"High-entropy continuous base64 literal ({len(val)} chars) without credential assignment",
        )

    if ctx.snippet:
        entropy = calculate_shannon_entropy(ctx.snippet)
        if len(ctx.snippet) >= STRONG_CREDENTIAL_LEN and entropy >= ENTROPY_HIGH_THRESHOLD:
            return (
                ConfidenceLevel.LOW,
                f"High-entropy literal string (entropy={entropy:.2f}) without explicit credential variable name",
            )

    # Default fallback when surviving filtering
    return (
        ConfidenceLevel.LOW,
        "Uncategorized candidate surviving false-positive filter with minimal credential indicators",
    )


# ---------------------------------------------------------------------------
# Candidate & Pipeline Evaluation
# ---------------------------------------------------------------------------

def evaluate_candidate(candidate: dict[str, Any], score_only: bool = False) -> dict[str, Any]:
    """Evaluates a single candidate finding and returns standardized classification."""
    ctx = CandidateContext.from_dict(candidate)

    if not score_only:
        is_fp, discard_reason = check_false_positive(ctx)
        if is_fp:
            return {
                "status": "DISCARDED",
                "file_path": ctx.file_path,
                "line_number": ctx.line_number,
                "candidate_snippet": ctx.snippet,
                "discard_reason": discard_reason,
            }

    confidence, reason = rate_confidence(ctx)
    secret_type = ctx.secret_type or "Generic Secret"

    return {
        "status": "CREDIBLE",
        "id": ctx.finding_id,
        "file_path": ctx.file_path,
        "line_number": ctx.line_number,
        "secret_type": secret_type,
        "confidence": confidence.value,
        "confidence_reason": reason,
        "masked_sample": ctx.snippet,
        "surrounding_context": ctx.raw_context,
    }


def evaluate_payload(
    payload: dict[str, Any] | list[dict[str, Any]],
    score_only: bool = False,
) -> dict[str, list[dict[str, Any]]]:
    """Processes a batch payload or list of candidate findings into credible and discarded sets."""
    candidates: list[dict[str, Any]] = []

    if isinstance(payload, list):
        candidates = payload
    elif isinstance(payload, dict):
        for key in ("candidates", "matches", "findings", "credible_findings"):
            if key in payload and isinstance(payload[key], list):
                candidates = payload[key]
                break
        else:
            candidates = [payload]

    credible_findings: list[dict[str, Any]] = []
    discarded_candidates: list[dict[str, Any]] = []

    for item in candidates:
        result = evaluate_candidate(item, score_only=score_only)
        status = result.pop("status", None)
        if status == "DISCARDED":
            discarded_candidates.append(result)
        else:
            credible_findings.append(result)

    return {
        "credible_findings": credible_findings,
        "discarded_candidates": discarded_candidates,
    }


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """CLI entry point for deterministic confidence rating."""
    parser = argparse.ArgumentParser(
        description="Deterministic Confidence Rating and False-Positive Filter for Candidate Secrets"
    )
    parser.add_argument(
        "--candidate",
        type=str,
        help="JSON string of a single candidate finding to evaluate",
    )
    parser.add_argument(
        "--file",
        type=Path,
        help="Path to JSON file containing findings or candidates list",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read JSON findings payload from standard input",
    )
    parser.add_argument(
        "--score-only",
        action="store_true",
        help="Skip false-positive filtering and only evaluate confidence score",
    )

    args = parser.parse_args(argv)

    try:
        raw_input: Any = None
        if args.candidate:
            raw_input = json.loads(args.candidate)
        elif args.file:
            if not args.file.exists():
                sys.stderr.write(f"Error: File '{args.file}' does not exist.\n")
                return 1
            raw_input = json.loads(args.file.read_text(encoding="utf-8"))
        elif args.stdin:
            raw_input = json.loads(sys.stdin.read())
        else:
            parser.print_help()
            return 1

        output = evaluate_payload(raw_input, score_only=args.score_only)
        sys.stdout.write(json.dumps(output, indent=2) + "\n")
        return 0

    except json.JSONDecodeError as err:
        sys.stderr.write(f"JSON Parsing Error: {err}\n")
        return 2
    except Exception as err:  # noqa: BLE001
        sys.stderr.write(f"Evaluation Error: {err}\n")
        return 3


if __name__ == "__main__":
    sys.exit(main())
