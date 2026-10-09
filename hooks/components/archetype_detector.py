"""
Archetype Detector Component
Resolve workspace root and detect project archetype(s)
from root metadata indicators without reading full project source trees.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import ClassVar


class ArchetypeDetector:
    """Detects software project archetype from workspace root markers."""

    # Archetype markers mapped to primary ecosystem
    ARCHETYPE_MARKERS: ClassVar[dict[str, list[str]]] = {
        "Node.js": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        "Python": ["pyproject.toml", "requirements.txt", "Pipfile", "setup.py", "poetry.lock"],
        "Go": ["go.mod", "go.sum"],
        "Rust": ["Cargo.toml", "Cargo.lock"],
        "Java / Kotlin": ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"],
        "Ruby": ["Gemfile", "Gemfile.lock"],
        ".NET / C#": ["*.csproj", "*.sln", "*.fsproj", "Directory.Build.props"],
        "PHP": ["composer.json", "composer.lock"],
        "Terraform / Infrastructure": ["main.tf", "versions.tf", "*.tf"],
        "Docker / Container": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
    }

    def __init__(self, workspace_root: str | Path) -> None:
        self.workspace_root = Path(workspace_root).resolve()

    def resolve_root(self) -> Path:
        """Returns the canonical absolute workspace root path."""
        if not self.workspace_root.exists():
            raise FileNotFoundError(f"Workspace root does not exist: {self.workspace_root}")
        if not self.workspace_root.is_dir():
            raise NotADirectoryError(f"Workspace root is not a directory: {self.workspace_root}")
        return self.workspace_root

    def detect(self) -> str:
        """
        Evaluates presence of ecosystem marker files at workspace root.
        Returns a single archetype string or polyglot summary.
        """
        root = self.resolve_root()
        matched_archetypes: list[str] = []

        try:
            root_entries = set(os.listdir(root))
        except OSError:
            return "Undetermined"

        for archetype, markers in self.ARCHETYPE_MARKERS.items():
            for marker in markers:
                if "*" in marker:
                    # Glob pattern check
                    extension = marker.replace("*", "")
                    if any(entry.endswith(extension) for entry in root_entries):
                        matched_archetypes.append(archetype)
                        break
                else:
                    if marker in root_entries:
                        matched_archetypes.append(archetype)
                        break

        if not matched_archetypes:
            return "Generic"

        if len(matched_archetypes) == 1:
            return matched_archetypes[0]

        # Prioritize core language over container/infra if multiple match
        core_languages = [a for a in matched_archetypes if a not in ("Docker / Container", "Terraform / Infrastructure")]
        if core_languages:
            if len(core_languages) == 1:
                return core_languages[0]
            return f"Polyglot ({', '.join(core_languages[:2])})"

        return matched_archetypes[0]
