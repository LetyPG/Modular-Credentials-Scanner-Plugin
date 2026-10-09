"""
Unit tests for hooks/components/archetype_detector.py
Validates workspace root resolution, ecosystem archetype detection,
glob pattern matching, core language precedence, and negative error conditions.
"""
import os
from pathlib import Path

import pytest

from hooks.components.archetype_detector import ArchetypeDetector

# ---------------------------------------------------------------------------
# Workspace Root Resolution (Positive)
# ---------------------------------------------------------------------------

def test_resolve_root_valid_directory(tmp_path: Path):
    detector = ArchetypeDetector(tmp_path)
    resolved = detector.resolve_root()
    assert resolved == tmp_path.resolve()
    assert isinstance(resolved, Path)


# ---------------------------------------------------------------------------
# Archetype Detection (Parametrized Ecosystems)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "marker_filename, expected_archetype",
    [
        ("package.json", "Node.js"),
        ("package-lock.json", "Node.js"),
        ("pyproject.toml", "Python"),
        ("requirements.txt", "Python"),
        ("go.mod", "Go"),
        ("Cargo.toml", "Rust"),
        ("pom.xml", "Java / Kotlin"),
        ("build.gradle.kts", "Java / Kotlin"),
        ("Gemfile", "Ruby"),
        ("composer.json", "PHP"),
        ("Dockerfile", "Docker / Container"),
        ("main.tf", "Terraform / Infrastructure"),
        ("App.csproj", ".NET / C#"),  # Wildcard *.csproj check
        ("infra.tf", "Terraform / Infrastructure"),  # Wildcard *.tf check
    ],
)
def test_archetype_detector_single_ecosystem(tmp_path: Path, marker_filename: str, expected_archetype: str):
    (tmp_path / marker_filename).write_text("dummy", encoding="utf-8")
    detector = ArchetypeDetector(tmp_path)
    assert detector.detect() == expected_archetype


def test_archetype_detector_generic_when_no_markers(tmp_path: Path):
    (tmp_path / "notes.txt").write_text("just text", encoding="utf-8")
    detector = ArchetypeDetector(tmp_path)
    assert detector.detect() == "Generic"


def test_archetype_detector_core_language_precedence_over_container(tmp_path: Path):
    """Core language should be preferred over container or infra markers when only one core language exists."""
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12", encoding="utf-8")
    (tmp_path / "main.tf").write_text("", encoding="utf-8")
    detector = ArchetypeDetector(tmp_path)
    assert detector.detect() == "Python"


def test_archetype_detector_polyglot(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    detector = ArchetypeDetector(tmp_path)
    arch = detector.detect()
    assert arch.startswith("Polyglot")
    assert "Node.js" in arch
    assert "Python" in arch


# ---------------------------------------------------------------------------
# Negative Tests 
# ---------------------------------------------------------------------------

def test_negative_archetype_non_existent_workspace_root(tmp_path: Path):
    """Validates that a non-existent path raises FileNotFoundError on resolve_root and detect."""
    non_existent = tmp_path / "does_not_exist_dir"
    detector = ArchetypeDetector(non_existent)

    with pytest.raises(FileNotFoundError, match="Workspace root does not exist"):
        detector.resolve_root()

    with pytest.raises(FileNotFoundError, match="Workspace root does not exist"):
        detector.detect()


def test_negative_archetype_file_instead_of_directory(tmp_path: Path):
    """Validates that pointing workspace_root to a file raises NotADirectoryError."""
    file_path = tmp_path / "regular_file.txt"
    file_path.write_text("not a directory", encoding="utf-8")
    detector = ArchetypeDetector(file_path)

    with pytest.raises(NotADirectoryError, match="Workspace root is not a directory"):
        detector.resolve_root()

    with pytest.raises(NotADirectoryError, match="Workspace root is not a directory"):
        detector.detect()


def test_negative_archetype_unreadable_directory_os_error(tmp_path: Path, monkeypatch):
    """Validates that an unexpected OSError during os.listdir gracefully returns 'Undetermined'."""
    detector = ArchetypeDetector(tmp_path)

    def mock_listdir(_path):
        raise OSError("Permission denied or I/O error")

    monkeypatch.setattr(os, "listdir", mock_listdir)
    assert detector.detect() == "Undetermined"

