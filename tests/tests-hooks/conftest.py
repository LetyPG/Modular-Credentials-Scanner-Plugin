"""
Shared pytest fixtures and test doubles for hook tests.
"""
import sys
from pathlib import Path

import pytest

# Ensure plugin root is in sys.path
PLUGIN_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))


@pytest.fixture
def mock_workspace(tmp_path: Path) -> Path:
    """
    Creates a realistic mock project workspace:
    - Root indicators (package.json, pyproject.toml)
    - Pruned directories (node_modules, dist, .git, .cache)
    - Tier 1 files (.env, config.json, .github/workflows/deploy.yml, id_rsa.key)
    - Tier 2 files (main.py, index.js, util.sh)
    - Oversized file (> 256 KB)
    - File with long line (> 1000 chars)
    """
    ws = tmp_path / "mock_project"
    ws.mkdir()

    # Archetype markers
    (ws / "package.json").write_text('{"name": "mock-app"}', encoding="utf-8")
    (ws / "pyproject.toml").write_text('[project]\nname = "mock"', encoding="utf-8")

    # Tier 1 Critical files
    (ws / ".env").write_text("API_KEY=dummy_secret\n", encoding="utf-8")
    (ws / "config.json").write_text('{"db_url": "postgres://localhost"}', encoding="utf-8")
    (ws / "id_rsa.key").write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n", encoding="utf-8")
    
    ci_dir = ws / ".github" / "workflows"
    ci_dir.mkdir(parents=True)
    (ci_dir / "deploy.yml").write_text("name: Deploy\non: push\n", encoding="utf-8")

    # Tier 2 Source files
    (ws / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (ws / "index.js").write_text("console.log('hi');\n", encoding="utf-8")
    (ws / "util.sh").write_text("#!/bin/bash\necho ok\n", encoding="utf-8")

    # Tier 3 Doc files
    (ws / "README.md").write_text("# Readme\n", encoding="utf-8")

    # Excluded directories and patterns
    nm = ws / "node_modules" / "some_pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("module.exports = {};", encoding="utf-8")

    dist = ws / "dist"
    dist.mkdir()
    (dist / "bundle.min.js").write_text("var a=1;", encoding="utf-8")

    # Oversized file (> 256 KB)
    oversized = ws / "large_dump.sql"
    oversized.write_bytes(b"SELECT 1;\n" * 30000)  # ~300 KB

    # File with very long line (> 1000 chars)
    long_file = ws / "minified_line.txt"
    long_file.write_text("x" * 1500 + "\n", encoding="utf-8")

    return ws
