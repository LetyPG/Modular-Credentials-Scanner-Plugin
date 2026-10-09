"""
Unit tests for hooks/components/exclusion_filter.py
Validates native filesystem pruning, glob exclusion pattern matching,
special dot-folder rules (.github allowance), size thresholds, and error handling.
"""
from pathlib import Path

import pytest

from hooks.components.exclusion_filter import ExclusionFilter

# ---------------------------------------------------------------------------
# Pattern Matching: is_file_excluded_by_pattern
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "filename",
    [
        # Minified and bundle assets
        "bundle.min.js",
        "styles.min.css",
        "vendor.bundle.js",
        "main.map",
        "chunk.123.chunk.js",
        # Lockfiles
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Cargo.lock",
        "composer.lock",
        "poetry.lock",
        "Gemfile.lock",
        # Media & documents
        "logo.png",
        "avatar.jpg",
        "hero.jpeg",
        "spinner.gif",
        "favicon.ico",
        "vector.svg",
        "banner.webp",
        "doc.pdf",
        "sheet.xlsx",
        # Archives & Binaries
        "archive.zip",
        "data.tar.gz",
        "backup.tgz",
        "lib.so",
        "program.exe",
        "binary.bin",
        "compiled.pyc",
        "module.wasm",
        # Fonts
        "font.woff2",
        "font.ttf",
        # Database & dumps
        "records.sqlite3",
        "analytics.parquet",
        "export.dump",
    ],
)
def test_is_file_excluded_by_pattern_matches_default_patterns(filename: str):
    filter = ExclusionFilter()
    assert filter.is_file_excluded_by_pattern(filename) is True


@pytest.mark.parametrize(
    "filename",
    [
        "main.py",
        "index.ts",
        ".env",
        ".env.production",
        "config.json",
        "deploy.yml",
        "id_rsa",
        "Dockerfile",
        "Makefile",
        "credentials.ini",
        "secret_token.txt",
    ],
)
def test_is_file_excluded_by_pattern_allows_auditable_files(filename: str):
    filter = ExclusionFilter()
    assert filter.is_file_excluded_by_pattern(filename) is False


# ---------------------------------------------------------------------------
# Directory Pruning & Dot-Folder Rules
# ---------------------------------------------------------------------------

def test_exclusion_filter_prunes_directories(mock_workspace: Path):
    filter = ExclusionFilter()
    total_enum, excluded_cnt, eligible, _oversized = filter.scan(mock_workspace)

    eligible_names = {f.name for f in eligible}

    # Should include general source and configs
    assert "package.json" in eligible_names
    assert ".env" in eligible_names
    assert "main.py" in eligible_names
    assert "deploy.yml" in eligible_names

    # Should prune contents inside node_modules and dist
    assert "some_pkg" not in eligible_names
    assert "bundle.min.js" not in eligible_names
    assert total_enum > 0
    assert excluded_cnt > 0


def test_exclusion_filter_dot_folders_pruned_except_github(tmp_path: Path):
    """Dot-directories must be pruned, but .github must be kept and scanned."""
    # Dot-directory to prune
    hidden_dir = tmp_path / ".custom_hidden"
    hidden_dir.mkdir()
    (hidden_dir / "hidden_secret.txt").write_text("should_be_pruned", encoding="utf-8")

    # .github directory to keep
    github_dir = tmp_path / ".github" / "workflows"
    github_dir.mkdir(parents=True)
    (github_dir / "ci.yml").write_text("name: CI\n", encoding="utf-8")

    # Normal directory
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "app.py").write_text("print(1)\n", encoding="utf-8")

    filter = ExclusionFilter()
    _, excluded_cnt, eligible, _ = filter.scan(tmp_path)
    eligible_names = {f.name for f in eligible}

    assert "app.py" in eligible_names
    assert "ci.yml" in eligible_names
    assert "hidden_secret.txt" not in eligible_names
    assert excluded_cnt >= 1


# ---------------------------------------------------------------------------
# Single-File Size Boundaries & Oversized Tracking
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "file_bytes, threshold_bytes, should_be_oversized",
    [
        (1000, 1000, False),      # Exact limit -> eligible
        (1001, 1000, True),       # 1 byte over -> oversized
        (500, 1000, False),       # Below limit -> eligible
    ],
)
def test_exclusion_filter_size_boundary(
    tmp_path: Path,
    file_bytes: int,
    threshold_bytes: int,
    should_be_oversized: bool,
):
    f = tmp_path / "boundary_file.txt"
    f.write_bytes(b"A" * file_bytes)

    filter = ExclusionFilter(max_single_file_bytes=threshold_bytes)
    _, _, eligible, oversized = filter.scan(tmp_path)

    if should_be_oversized:
        assert len(eligible) == 0
        assert len(oversized) == 1
        assert oversized[0].path == "boundary_file.txt"
        assert oversized[0].size_bytes == file_bytes
    else:
        assert len(eligible) == 1
        assert len(oversized) == 0


def test_exclusion_filter_oversized_file(mock_workspace: Path):
    filter = ExclusionFilter(max_single_file_bytes=256 * 1024)
    _total_enum, _excluded_cnt, eligible, oversized = filter.scan(mock_workspace)

    eligible_names = {f.name for f in eligible}
    # 300KB file must be excluded from eligible
    assert "large_dump.sql" not in eligible_names

    # 300KB file must be recorded in oversized with correct relative path
    oversized_paths = [o.path for o in oversized]
    assert any("large_dump.sql" in p for p in oversized_paths)
    assert oversized[0].size_kb >= 256.0


# ---------------------------------------------------------------------------
# Custom Configurations & Overrides
# ---------------------------------------------------------------------------

def test_exclusion_filter_custom_dirs_and_patterns(tmp_path: Path):
    """Custom excluded dirs and patterns override or replace default sets."""
    custom_dir = tmp_path / "custom_excluded_dir"
    custom_dir.mkdir()
    (custom_dir / "valid.py").write_text("x = 1\n", encoding="utf-8")

    (tmp_path / "ignored.custom").write_text("data", encoding="utf-8")
    (tmp_path / "kept.py").write_text("print('ok')", encoding="utf-8")

    filter = ExclusionFilter(
        excluded_dirs={"custom_excluded_dir"},
        excluded_patterns=["*.custom"],
    )
    _, excluded_cnt, eligible, _ = filter.scan(tmp_path)
    eligible_names = {f.name for f in eligible}

    assert "kept.py" in eligible_names
    assert "valid.py" not in eligible_names
    assert "ignored.custom" not in eligible_names
    assert excluded_cnt == 2


def test_exclusion_filter_empty_workspace(tmp_path: Path):
    filter = ExclusionFilter()
    total_enum, excluded_cnt, eligible, oversized = filter.scan(tmp_path)
    assert total_enum == 0
    assert excluded_cnt == 0
    assert eligible == []
    assert oversized == []


# ---------------------------------------------------------------------------
# Negative Tests (Error handling)
# ---------------------------------------------------------------------------

def test_negative_exclusion_unreadable_file_stat_error(tmp_path: Path, monkeypatch):
    """When stat() raises OSError on a candidate file, it increments excluded_count and skips the file."""
    target_file = tmp_path / "ghost.py"
    target_file.write_text("will fail stat\n", encoding="utf-8")

    real_stat = Path.stat

    def mock_stat(self, *args, **kwargs):
        if self.name == "ghost.py":
            raise OSError("Permission denied or missing inode")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", mock_stat)

    filter = ExclusionFilter()
    _, excluded_cnt, eligible, oversized = filter.scan(tmp_path)

    assert target_file not in eligible
    assert len(oversized) == 0
    assert excluded_cnt == 1

