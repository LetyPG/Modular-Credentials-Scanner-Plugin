"""
Deterministic Risk Scorer & Metric Consolidator for Safe Audit Reporter.
Cross-references Git exposure states with credential impact taxonomy to assign
standardized 1-10 scores, severity tiers, and executive metrics.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class ImpactTier(str, Enum):
    """Impact tier classifications based on blast radius."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FinalRiskTier(str, Enum):
    """Standard final risk tiers matching executive audit report."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class CredentialImpactDef:
    """Definition for a credential type category and its consequences."""

    category: str
    impact_tier: ImpactTier
    technical_impact: str
    escalation_consequence: str


CREDENTIAL_IMPACT_TAXONOMY: dict[str, CredentialImpactDef] = {
    "cloud_keys": CredentialImpactDef(
        category="Cloud Provider Keys (AWS, GCP, Azure)",
        impact_tier=ImpactTier.CRITICAL,
        technical_impact="Unauthorized cloud resource access, compute hijacking",
        escalation_consequence="Tenant takeover, infrastructure destruction, crypto-mining fraud",
    ),
    "database": CredentialImpactDef(
        category="Database Credentials",
        impact_tier=ImpactTier.CRITICAL,
        technical_impact="Read/write access to application databases",
        escalation_consequence="Customer PII leak, ransomware encryption, compliance violation",
    ),
    "private_keys": CredentialImpactDef(
        category="Private Keys (SSH, RSA, EC)",
        impact_tier=ImpactTier.CRITICAL,
        technical_impact="Host shell access, server SSH authentication",
        escalation_consequence="Lateral network movement, encrypted communication interception",
    ),
    "payment": CredentialImpactDef(
        category="Payment Gateways (Stripe, PayPal)",
        impact_tier=ImpactTier.CRITICAL,
        technical_impact="Financial ledger inspection, transaction execution",
        escalation_consequence="Fraudulent refunds, unauthorized charges, merchant fine",
    ),
    "vcs_tokens": CredentialImpactDef(
        category="VCS Tokens (GitHub, GitLab)",
        impact_tier=ImpactTier.HIGH,
        technical_impact="Source code exfiltration, branch protection bypass",
        escalation_consequence="Supply chain poisoning, malicious binary release",
    ),
    "internal_auth": CredentialImpactDef(
        category="Internal Auth / JWT Secrets",
        impact_tier=ImpactTier.MEDIUM,
        technical_impact="Forgery of user sessions and admin claims",
        escalation_consequence="Authentication bypass, administrative privilege escalation",
    ),
    "generic": CredentialImpactDef(
        category="Generic API Key / Webhook Token",
        impact_tier=ImpactTier.LOW,
        technical_impact="Unauthorized peripheral service API calls",
        escalation_consequence="Rate-limiting denial of service, telemetry spoofing",
    ),
}

# (Exposure Group, ImpactTier) -> (Score 1-10, FinalRiskTier)
RISK_DECISION_MATRIX: dict[tuple[str, ImpactTier], tuple[int, FinalRiskTier]] = {
    # Critical Exposure (Tracked in index or committed to history)
    ("CRITICAL_EXPOSURE", ImpactTier.CRITICAL): (10, FinalRiskTier.HIGH),
    ("CRITICAL_EXPOSURE", ImpactTier.HIGH): (9, FinalRiskTier.HIGH),
    ("CRITICAL_EXPOSURE", ImpactTier.MEDIUM): (7, FinalRiskTier.HIGH),
    ("CRITICAL_EXPOSURE", ImpactTier.LOW): (5, FinalRiskTier.MEDIUM),
    # High Exposure (Untracked, unignored in repository)
    ("HIGH_EXPOSURE", ImpactTier.CRITICAL): (8, FinalRiskTier.HIGH),
    ("HIGH_EXPOSURE", ImpactTier.HIGH): (7, FinalRiskTier.HIGH),
    ("HIGH_EXPOSURE", ImpactTier.MEDIUM): (5, FinalRiskTier.MEDIUM),
    ("HIGH_EXPOSURE", ImpactTier.LOW): (4, FinalRiskTier.MEDIUM),
    # Low Exposure (Local only or ignored by .gitignore)
    ("LOW_EXPOSURE", ImpactTier.CRITICAL): (5, FinalRiskTier.MEDIUM),
    ("LOW_EXPOSURE", ImpactTier.HIGH): (4, FinalRiskTier.MEDIUM),
    ("LOW_EXPOSURE", ImpactTier.MEDIUM): (3, FinalRiskTier.LOW),
    ("LOW_EXPOSURE", ImpactTier.LOW): (1, FinalRiskTier.LOW),
}

VALID_EXPOSURE_STATES = frozenset({
    "TRACKED_ACTIVE",
    "TRACKED_DESPITE_IGNORE",
    "COMMITTED_HISTORICAL",
    "UNTRACKED_UNIGNORED",
    "LOCAL_IGNORED",
    "LOCAL_ONLY",
})


def get_exposure_group(state: str) -> str:
    """Maps a raw exposure state to its exposure risk tier."""
    if state in ("TRACKED_ACTIVE", "TRACKED_DESPITE_IGNORE", "COMMITTED_HISTORICAL"):
        return "CRITICAL_EXPOSURE"
    if state == "UNTRACKED_UNIGNORED":
        return "HIGH_EXPOSURE"
    if state in ("LOCAL_IGNORED", "LOCAL_ONLY"):
        return "LOW_EXPOSURE"
    msg = f"Unknown exposure state '{state}'. Valid states: {sorted(VALID_EXPOSURE_STATES)}"
    raise ValueError(msg)


def classify_credential_type(secret_type: str) -> CredentialImpactDef:
    """Deterministically identifies the impact category of a secret type."""
    st = secret_type.lower()
    if any(k in st for k in ("aws", "gcp", "azure", "cloud", "amazon")):
        return CREDENTIAL_IMPACT_TAXONOMY["cloud_keys"]
    if any(k in st for k in ("postgres", "mysql", "mongodb", "database", "redis", "db_password")):
        return CREDENTIAL_IMPACT_TAXONOMY["database"]
    if any(k in st for k in ("ssh", "rsa", "private key", "id_rsa", "pkcs", "ed25519", "pgp")):
        return CREDENTIAL_IMPACT_TAXONOMY["private_keys"]
    if any(k in st for k in ("stripe", "paypal", "payment", "square", "braintree")):
        return CREDENTIAL_IMPACT_TAXONOMY["payment"]
    if any(k in st for k in ("github", "gitlab", "bitbucket", "vcs", "git token")):
        return CREDENTIAL_IMPACT_TAXONOMY["vcs_tokens"]
    if any(k in st for k in ("jwt", "session", "auth_token", "bearer", "cookie", "secret_key")):
        return CREDENTIAL_IMPACT_TAXONOMY["internal_auth"]
    return CREDENTIAL_IMPACT_TAXONOMY["generic"]


def score_finding(exposure_state: str, secret_type: str) -> dict[str, Any]:
    """
    Cross-references Git exposure state with Credential Impact to assign
    a deterministic 1-10 risk score and executive risk tier (HIGH, MEDIUM, LOW).
    """
    state_normalized = exposure_state.strip().upper()
    exp_group = get_exposure_group(state_normalized)
    impact_def = classify_credential_type(secret_type)

    final_score, risk_tier = RISK_DECISION_MATRIX[(exp_group, impact_def.impact_tier)]

    return {
        "exposure_state": state_normalized,
        "credential_impact_category": impact_def.category,
        "credential_impact_tier": impact_def.impact_tier.value,
        "final_risk_score": final_score,
        "final_risk_tier": risk_tier.value,
        "technical_impact": impact_def.technical_impact,
        "potential_escalation": impact_def.escalation_consequence,
    }


def consolidate_payload(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Consolidates a list of raw candidate findings into an enriched findings list
    alongside aggregated executive metrics.
    """
    enriched_findings: list[dict[str, Any]] = []
    high_count = 0
    medium_count = 0
    low_count = 0
    tracked_count = 0
    untracked_count = 0
    local_count = 0

    for finding in findings:
        exp_state = finding.get("exposure_state", "LOCAL_ONLY")
        sec_type = finding.get("secret_type", "Generic API Key")
        score_data = score_finding(exp_state, sec_type)

        enriched = {**finding, **score_data}
        enriched_findings.append(enriched)

        tier = score_data["final_risk_tier"]
        if tier == FinalRiskTier.HIGH.value:
            high_count += 1
        elif tier == FinalRiskTier.MEDIUM.value:
            medium_count += 1
        else:
            low_count += 1

        state = score_data["exposure_state"]
        if state in ("TRACKED_ACTIVE", "TRACKED_DESPITE_IGNORE", "COMMITTED_HISTORICAL"):
            tracked_count += 1
        elif state == "UNTRACKED_UNIGNORED":
            untracked_count += 1
        else:
            local_count += 1

    total = len(findings)
    if tracked_count > 0 or (total > 0 and high_count > 0):
        overall = "CONFIRMED EXPOSURE DETECTED"
    elif total > 0:
        overall = "POTENTIAL SECRETS DETECTED"
    else:
        overall = "CLEAN"

    return {
        "metrics": {
            "total_findings": total,
            "high_risk_count": high_count,
            "medium_risk_count": medium_count,
            "low_risk_count": low_count,
            "tracked_count": tracked_count,
            "untracked_count": untracked_count,
            "local_count": local_count,
            "overall_assessment": overall,
        },
        "findings": enriched_findings,
    }


def build_parser() -> argparse.ArgumentParser:
    """Builds CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Deterministic Risk Scorer & Metric Consolidator for Safe Audit Reporter."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--finding",
        "-s",
        type=str,
        help="JSON string of a single finding to score",
    )
    group.add_argument(
        "--file",
        "-f",
        type=Path,
        help="Path to JSON file containing finding(s) or findings array",
    )
    group.add_argument(
        "--stdin",
        action="store_true",
        help="Read JSON findings payload from standard input",
    )
    group.add_argument(
        "--list",
        "-l",
        action="store_true",
        help="Print impact taxonomy and risk matrix table as JSON",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.list:
            matrix_repr = {
                f"{group}:{tier.value}": {
                    "score": score,
                    "tier": final_tier.value,
                }
                for (group, tier), (score, final_tier) in RISK_DECISION_MATRIX.items()
            }
            output = {
                "credential_impacts": {
                    k: {
                        "category": v.category,
                        "impact_tier": v.impact_tier.value,
                        "technical_impact": v.technical_impact,
                        "escalation_consequence": v.escalation_consequence,
                    }
                    for k, v in CREDENTIAL_IMPACT_TAXONOMY.items()
                },
                "risk_matrix": matrix_repr,
            }
            sys.stdout.write(json.dumps(output, indent=2) + "\n")
            return 0

        if args.finding:
            raw = json.loads(args.finding)
            exp_state = raw.get("exposure_state", "LOCAL_ONLY")
            sec_type = raw.get("secret_type", "Generic API Key")
            result = score_finding(exp_state, sec_type)
            enriched = {**raw, **result}
            sys.stdout.write(json.dumps(enriched, indent=2) + "\n")
            return 0

        raw_payload: Any = None
        if args.file:
            if not args.file.exists():
                sys.stderr.write(f"Error: File '{args.file}' does not exist.\n")
                return 1
            raw_payload = json.loads(args.file.read_text(encoding="utf-8"))
        elif args.stdin:
            raw_input = sys.stdin.read().strip()
            if not raw_input:
                sys.stderr.write("Error: Stdin was empty.\n")
                return 1
            raw_payload = json.loads(raw_input)

        if raw_payload is not None:
            if isinstance(raw_payload, list):
                findings = raw_payload
            elif isinstance(raw_payload, dict) and "findings" in raw_payload:
                findings = raw_payload["findings"]
            elif isinstance(raw_payload, dict):
                # Single finding wrapped in dict
                exp_state = raw_payload.get("exposure_state", "LOCAL_ONLY")
                sec_type = raw_payload.get("secret_type", "Generic API Key")
                result = score_finding(exp_state, sec_type)
                enriched = {**raw_payload, **result}
                sys.stdout.write(json.dumps(enriched, indent=2) + "\n")
                return 0
            else:
                sys.stderr.write("Error: Expected JSON list or object with 'findings' key.\n")
                return 1

            consolidated = consolidate_payload(findings)
            sys.stdout.write(json.dumps(consolidated, indent=2) + "\n")
            return 0

        parser.print_help(sys.stderr)
        return 1

    except (ValueError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
