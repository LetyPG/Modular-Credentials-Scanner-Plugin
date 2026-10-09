"""
Exclusion Filter Component
Execute fast, native filesystem pruning. Filters out
dependencies, VCS trees, build artifacts, caches, media, binary assets, and
oversized files (> 256 KB) without recursive LLM overhead.
"""
from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import ClassVar

from hooks.hook_contract import OversizedFile


class ExclusionFilter:
    """Prunes non-auditable directories and files using native OS traversal."""

    DEFAULT_EXCLUDED_DIRS: ClassVar[set[str]] = {
        # Dependencies
        "node_modules", "vendor", "target", ".venv", "venv", "packages", "Pods",
        "bower_components", "jspm_packages",
        # VCS Metadata
        ".git", ".svn", ".hg", ".bzr",
        # Build & Distribution Outputs
        "dist", "build", "out", "bin", "obj", "_build", "coverage", ".next", ".nuxt",
        # Caches & Temporary Directories
        ".cache", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
        "tmp", "temp", ".idea", ".vscode",
    }

    DEFAULT_EXCLUDED_FILE_PATTERNS: ClassVar[list[str]] = [
        # Build & Minified
        "*.min.js", "*.min.css", "*.bundle.js", "*.map", "*.chunk.js",
        # Lockfiles (High entropy noise)
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock",
        "composer.lock", "poetry.lock", "Gemfile.lock",
        # Media & Documents
        "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg", "*.webp",
        "*.pdf", "*.doc", "*.docx", "*.xls", "*.xlsx", "*.ppt", "*.pptx",
        # Archives & Binaries
        "*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.tar.bz2", "*.7z", "*.rar",
        "*.wasm", "*.exe", "*.so", "*.dylib", "*.dll", "*.class", "*.pyc",
        "*.bin", "*.iso", "*.dmg", "*.deb", "*.rpm",
        # Fonts
        "*.woff", "*.woff2", "*.ttf", "*.eot", "*.otf",
        # Database & Raw data dumps
        "*.sqlite", "*.sqlite3", "*.db", "*.parquet", "*.arrow", "*.dump",
    ]

    def __init__(
        self,
        max_single_file_bytes: int = 256 * 1024,  # 256 KB default
        excluded_dirs: set[str] | None = None,
        excluded_patterns: list[str] | None = None,
    ) -> None:
        self.max_single_file_bytes = max_single_file_bytes
        self.excluded_dirs = set(excluded_dirs) if excluded_dirs else self.DEFAULT_EXCLUDED_DIRS
        self.excluded_patterns = list(excluded_patterns) if excluded_patterns else self.DEFAULT_EXCLUDED_FILE_PATTERNS

    def is_file_excluded_by_pattern(self, filename: str) -> bool:
        """Checks if a filename matches exclusion glob patterns."""
        for pattern in self.excluded_patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True
        return False

    def scan(
        self, workspace_root: str | Path
    ) -> tuple[int, int, list[Path], list[OversizedFile]]:
        """
        Walks workspace root with in-place directory pruning.
        Returns:
            total_enumerated: Count of all entries discovered
            excluded_count: Count of entries pruned by rules
            eligible_files: Filtered candidate file paths
            oversized_files: List of OversizedFile objects exceeding size threshold
        """
        root_path = Path(workspace_root).resolve()
        total_enumerated = 0
        excluded_count = 0
        eligible_files: list[Path] = []
        oversized_files: list[OversizedFile] = []

        for current_dir, dirnames, filenames in os.walk(root_path, followlinks=False):
            # In-place directory pruning to prevent descending into dependencies/build trees
            pruned_dirs: list[str] = []
            for d in list(dirnames):
                if d in self.excluded_dirs or d.startswith("."):
                    # Keep .github, prune other dot-folders unless specific
                    if d == ".github":
                        continue
                    pruned_dirs.append(d)
                    dirnames.remove(d)

            excluded_count += len(pruned_dirs)
            total_enumerated += len(dirnames) + len(filenames)

            for fname in filenames:
                file_path = Path(current_dir) / fname

                # Pattern check
                if self.is_file_excluded_by_pattern(fname):
                    excluded_count += 1
                    continue

                try:
                    stat_info = file_path.stat()
                    file_size = stat_info.st_size
                except OSError:
                    excluded_count += 1
                    continue

                # Single-file size gate check
                if file_size > self.max_single_file_bytes:
                    oversized_files.append(
                        OversizedFile(
                            path=str(file_path.relative_to(root_path)),
                            size_bytes=file_size,
                            size_kb=round(file_size / 1024, 2),
                        )
                    )
                    excluded_count += 1
                    continue

                eligible_files.append(file_path)

        return total_enumerated, excluded_count, eligible_files, oversized_files
