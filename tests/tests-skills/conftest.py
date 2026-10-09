"""
Shared pytest fixtures and path configuration for skills tests.
"""
import sys
from pathlib import Path

# Ensure skills script directories are in sys.path
SKILLS_ROOT = Path(__file__).resolve().parent.parent.parent / "skills"
for skill_dir in [
    SKILLS_ROOT / "git-exposure-checker" / "scripts",
    SKILLS_ROOT / "secret-false-positive-filter" / "scripts",
    SKILLS_ROOT / "safe-audit-reporter" / "scripts",
]:
    if str(skill_dir) not in sys.path:
        sys.path.insert(0, str(skill_dir))

