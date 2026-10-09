# Capacity Gate and Discovery Hook

Deterministic, OS-level pre-tool execution gate designed to enforce strict computing boundaries before files are ingested into LLM context.

---

## Overview

The Capacity Gate Hook operates as an air-gap boundary and sizing guardrail for secret audit workflows. When an agent attempts to inspect files using tools such as `view_file`, `read_file`, or `grep_search`, the hook evaluates candidate targets against a 5-Dimensional Computing Sizing Contract before any file content reaches the model context window.

### 5-Dimensional Computing Sizing Contract

1. **Candidate File Count Limit:** `MAX_FILES_TO_SCAN = 50` files maximum per scan.
2. **Single File Size Limit:** `MAX_SINGLE_FILE_SIZE_KB = 256 KB`. Files larger than 256 KB are pruned or blocked from raw ingestion.
3. **Aggregate Scan Size Limit:** `MAX_AGGREGATE_SCAN_SIZE_MB = 2.0 MB` cumulative payload across the session.
4. **Line Length Limit:** `MAX_LINE_LENGTH = 1000` characters. Lines exceeding this limit are skipped to prevent minified file regex blowouts.
5. **Execution Latency and Reliability:** Sub-50ms execution overhead, fail-closed deterministic policy, and standard library only.

---

## Architecture

The hook architecture is organized into modular components adhering to the Single Responsibility Principle:

* `capacity_gate_hook.py`: PreToolUse hook entrypoint. Reads invocation payloads from stdin, tracks cumulative session state in `/tmp/.secret_auditor_state`, and outputs allow/deny/ask decisions to stdout.
* `discovery_engine.py`: Unified discovery orchestrator that scans workspaces, determines archetypes, excludes non-relevant files, and applies risk tiering.
* `hook_contract.py`: Typed contracts, data classes (`PreToolUseInput`, `PreToolUseOutput`, `CapacityLimits`), and JSON serialization helpers.
* `components/archetype_detector.py`: Analyzes project roots and markers (Python, Node.js, Go, Rust, monorepos) to determine scan context.
* `components/exclusion_filter.py`: Prunes lockfiles, binary files, build artifacts, package directories (`node_modules`, `.venv`, `vendor`), and enforces the 256 KB single-file cap.
* `components/risk_prioritizer.py`: Categorizes files into Tier 1 (high-risk configurations, `.env`, keys) and Tier 2 (source code, templates).
* `components/capacity_evaluator.py`: Evaluates candidate lists against the 5D bounds and returns structured decisions.

---

## Hook Allocation and Enforcement

The hook is integrated and enforced across the plugin via two configuration points (this example assumes the hook is in the root directory of the project):

1. **PreToolUse Hook Configuration (`settings-addition.json`):**
   Allocated in `settings-hook.json` to intercept tool calls matching `view_file|read_file|grep_search`:
```json
{
  "plugins": {
    "modular-credentials-scanner-plugin": {
      "enabled": true,
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "view_file|read_file|grep_search",
            "hooks": [
              {
                "type": "command",
                "command": "python3 <absolute/path/to/repo>/modular-credentials-scanner-plugin>/hooks/capacity_gate_hook.py"
              }
            ]
          }
        ]
      }
    }
  }
}
```

2. **Agent Metadata Enforcement (`agents/secret-exposure-auditor.md`):**
   Declared directly in the orchestrator agent YAML frontmatter metadata to mandate gate execution prior to any tool access:
   ```yaml
   hook: python3 hooks/capacity_gate_hook.py
   ```

---

## Dependencies and Installation

### Runtime Dependencies
* **Python >= 3.10**
* **Zero external runtime dependencies:** Built strictly with Python standard library modules (`sys`, `os`, `json`, `pathlib`, `dataclasses`, `contextlib`) for minimal latency and maximum portability.

### Development Dependencies
Development tools for testing and linting:
* `pytest >= 8.0.0`
* `pytest-mock >= 3.12.0`
* `poethepoet >= 0.25.0`
* `ruff >= 0.12.0`

### Installation
From the plugin root directory (`modular-credentials-scanner-plugin`):

```bash
# Install development dependencies in editable mode
pip install -e ".[dev]"
```

---

## Commands and Usage

### Standalone Discovery Engine Command
Run the discovery engine directly against a workspace to inspect detected archetypes, pruned paths, and capacity bounds:

```bash
# Scan current directory
python3 hooks/discovery_engine.py .

# Scan specific target path
python3 hooks/discovery_engine.py /path/to/target/project
```

### Direct Hook CLI Simulation
Simulate a PreToolUse invocation via standard input:

```bash
# Allow case: safe file under limits
echo '{"tool_name": "view_file", "tool_args": {"AbsolutePath": "config/settings.py"}}' | python3 hooks/capacity_gate_hook.py

# Gate decision output example
# {"decision": "allow", "reason": "Target file passed capacity gate"}
```

### Test 

All the hook components are tested independetnly, so each one has its own test files in the `tests/tests-hooks` directory, for more information on how to run the tests, see the [`tests-hooks` information](../tests/README.md).

