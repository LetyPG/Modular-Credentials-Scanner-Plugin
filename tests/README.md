## Testing Strategy
The development environment uses a virtual environment to isolate development dependencies, including `pytest` and `ruff`, as specified by the project configuration.

Install and activate the development environment before running the test suite and lint checks.

The current startegy allocate the separated test folders for `hooks` and `skills`, see the folder structure below:

```text
tests/
├── tests-hooks/
│   ├── conftest.py                             # Shared fixtures and mock workspaces
│   ├── unit/                                   # Component-level unit test suite
│   │   ├── test_hook_contract.py               # Protocol contracts, serialization, decision states
│   │   ├── test_archetype_detector.py          # Project boundary and marker detection
│   │   ├── test_exclusion_filter.py            # Pattern exclusions, binaries, 256 KB limit
│   │   ├── test_risk_prioritizer.py            # Tier 1 and Tier 2 categorization
│   │   └── test_capacity_evaluator.py          # 5D limit enforcement and decision thresholds
│   ├── integration/                            # End-to-end integration test suite
│   │   ├── test_discovery_engine.py            # Discovery workflow on mock file trees
│   │   └── test_capacity_gate_hook.py          # CLI stdin/stdout lifecycle and session state
└──tests-skills/
    ├── test_classify_risk_exposure_git.py    # Risk classification for git exposure checker skill
    └── test_evaluate_confidence.py           # Deterministic false-positive and confidence rating
```

### Test Commands

#### Install testing dependencies

From the plugin root directory modular-credentials-scanner-plugin.

**Recommended use Virtual Environment**
Execute test in a Python virtual environment to isolate the dependencies.
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

**If no virtual environment is used run only:**

```bash
pip install -e ".[dev]"
```

#### Run linter for code quality issues via `ruff` or `poe`:

```bash
ruff check .
ruff check . --fix
```

```bash
poe lint
poe lint:fix
```


#### Run tests using `pytest` or task shortcuts via `poe`:

**For `hooks` tests:**

```bash
# Run tests using pytest
# Run the full hook test suite (unit and integration).
pytest tests/tests-hooks

# Run all component-level unit tests.
pytest tests/tests-hooks/unit

# Run discovery and capacity gate integration tests.
pytest tests/tests-hooks/integration

# Run specific component tests
pytest tests/tests-hooks/unit/test_capacity_evaluator.py
pytest tests/tests-hooks/integration/test_capacity_gate_hook.py
```

```bash
# Run via Poe task runner

poe test:hook
poe test:hook-unit
poe test:hook-integration
poe test:capacity-gate
# For more poe commands task options see `../pyproject.toml` file
```

**For `skills` tests:**

```bash
# Run via pytest
# all tests in skills
pytest tests/tests-skills

# specific skill test
pytest tests/tests-skills/test_classify_risk_exposure_git.py
pytest tests/tests-skills/test_evaluate_confidence.py
```

```bash
# Run via Poe task runner
# all tests in skills
poe test:skills
# specific skill test
poe test:git-exposure-risk
poe test:confidence-rating
```
