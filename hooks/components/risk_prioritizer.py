"""
Risk Prioritizer Component
Categorize candidate files into deterministic risk tiers
(Tier 1 Critical Configs/Keys/CI-CD vs Tier 2 General Source) and prioritize
the top allocation (MAX_FILES_TO_SCAN = 50) without losing high-risk targets.
"""
from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import ClassVar


class RiskPrioritizer:
    """Categorizes and ranks candidate files by credential exposure risk."""

    TIER1_PATTERNS: ClassVar[list[str]] = [
        # Cryptographic keys and certificates
        "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*", "*.pkcs12", "*.crt", "*.cer",
        # Environment and secret configs
        ".env*", "*.env", "*.env.*",
        # Configuration file formats
        "*.yaml", "*.yml", "*.json", "*.toml", "*.ini", "*.xml", "*.properties", "*.conf", "*.cfg",
        # CI/CD and deployment configs
        "Dockerfile*", "docker-compose*.yml", "docker-compose*.yaml",
        "Jenkinsfile*", "*.tf", "*.tfvars",
    ]

    TIER2_PATTERNS: ClassVar[list[str]] = [
        # Scripting and source code
        "*.sh", "*.bash", "*.zsh", "*.py", "*.js", "*.jsx", "*.ts", "*.tsx",
        "*.go", "*.java", "*.cs", "*.rb", "*.php", "*.rs", "*.c", "*.cpp", "*.h",
        "*.swift", "*.kt", "*.scala", "*.pl", "*.lua",
    ]

    @classmethod
    def get_tier(cls, file_path: Path) -> int:
        """Determines the risk tier (1 = Critical, 2 = Source, 3 = General text)."""
        fname = file_path.name.lower()
        rel_str = str(file_path).lower()

        # CI/CD path matching
        if ".github/workflows" in rel_str or ".gitlab-ci" in rel_str or "azure-pipelines" in rel_str:
            return 1

        for pat in cls.TIER1_PATTERNS:
            if fnmatch.fnmatch(fname, pat.lower()):
                return 1

        for pat in cls.TIER2_PATTERNS:
            if fnmatch.fnmatch(fname, pat.lower()):
                return 2

        return 3

    def prioritize(
        self, files: list[Path], max_allocation: int = 50
    ) -> tuple[list[Path], int, int]:
        """
        Sorts candidates by risk tier and returns the prioritized top allocation.
        Returns:
            prioritized_files: Files capped to max_allocation
            tier1_count: Count of Tier 1 files in result
            tier2_count: Count of Tier 2 files in result
        """
        tier1: list[Path] = []
        tier2: list[Path] = []
        tier3: list[Path] = []

        for f in files:
            tier = self.get_tier(f)
            if tier == 1:
                tier1.append(f)
            elif tier == 2:
                tier2.append(f)
            else:
                tier3.append(f)

        # Stable sort within each tier by path length / alphabet
        tier1.sort(key=lambda p: (len(p.parts), str(p)))
        tier2.sort(key=lambda p: (len(p.parts), str(p)))
        tier3.sort(key=lambda p: (len(p.parts), str(p)))

        # Saturated allocation: fill with Tier 1 first, then Tier 2, then Tier 3
        combined: list[Path] = tier1 + tier2 + tier3
        capped = combined[:max_allocation]

        t1_in_capped = sum(1 for f in capped if self.get_tier(f) == 1)
        t2_in_capped = sum(1 for f in capped if self.get_tier(f) == 2)

        return capped, t1_in_capped, t2_in_capped
