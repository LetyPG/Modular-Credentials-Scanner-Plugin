# Modular Credentials and Secrets Scanner Suite

A modular, decomposed security audit suite for detecting exposed credentials, API keys, tokens, private keys, and sensitive configuration in local repositories to prevent the exposure of security credentials and secrets through AI agent tool use.

This plugin is intended to provide a security guardrail, considering that this issue has become in a security vulnerability pattern of AI-native software development, as it scales with faster software delivery.


---

## INDEX
- [Architecture Overview](#architecture-overview)
- [Dependencies](#dependencies)
- [Installation and Setup](#installation-and-setup)
- [How to Use the plugin - Dual Execution Modes](#how-to-use-the-plugin)
- [Hook Allocation and Enforcement](#hook-allocation-and-enforcement)
- [Invariant Rules](#invariant-rules)


## Architecture Overview

```text
modular-credentials-scanner-plugin/
├── .agent-plugin/                              # plugin standard metadata
├── agents/                                     # orchestrator agent, security auditor
├── hooks/                                      # plugin hooks, components called by orchestrator agent
├── skills/                                     # plugin skills, the different tasks; there are 5 skills
├── tests/                                      # plugin tests for hooks, and for skills script
├── .pyproject.toml/                            # dependencies for test execution   
└──settings-addition.json/                     # plugin settings reference, to add in your  custom agent or global agent settings
```

```mermaid
flowchart TD
    Request["Audit Request / Target Scope"] --> Auditor["Secret Exposure Auditor (Orchestrator Agent)"]

    subgraph Gate["PreToolUse Hook Guardrail"]
        Hook["Capacity Gate Hook (Token Conservation & Scope Boundary Gate)"]
    end

    Auditor -->|Gated Tool Calls: view_file, read_file, grep_search| Hook

    subgraph Skills["Modular Security Micro-Skills"]
        direction TB
        Sig["Secret Signature Detector (Known Vendor & API Key Patterns)"]
        Entropy["Secret Entropy Scanner (High-Entropy Token Detection)"]
        GitCheck["Git Exposure Checker (VCS Tracking & Exposure Audit)"]
        FPFilter["Secret False Positive Filter (Mock & Template Data Scrubbing)"]
        Reporter["Safe Audit Reporter (Zero-Raw-Secret Masked Reporting)"]

        Sig --> FPFilter
        Entropy --> FPFilter
        GitCheck --> FPFilter
        FPFilter --> Reporter
    end

    Hook -->|Permitted Bounded Targets| Sig
    Hook -->|Permitted Bounded Targets| Entropy
    Hook -->|Permitted Bounded Targets| GitCheck
    Reporter --> Report["Masked Security Audit Report"]
```

[BACK TO INDEX](#index)

---

## Dependencies

| Runtime          | Version       | Notes                          |
| ---------------- | ------------- | ------------------------------ |
| Python  (mandatory)         | >= 3.10       | Standard library only          |
| Development (optional)      | `pytest>=8.0.0`, `pytest-mock>=3.12.0`, `poethepoet>=0.25.0`, `ruff>=0.12.0` | Install with `pip install -e ".[dev]"`; you can find more info in [pyproject.toml](./pyproject.toml) |
---

## Installation and Setup

This plugin can be installed globally or locally, depending on the configuration and plugin-discovery mechanisms supported by your AI agent, such as the ones listed below:
*Some examples*
- `.agentic-system-name/.config/plugins/<add-plugin-here>`
- `agentic-system-name/plugin/<add-plugin-here>`
- `agentic-system-name/.config/plugins/marketplace/<add-plugin-here>`

**Note:** This project uses `git clone` instead of `npx`, consistent with building a security plugin for AI agents that is host-agent agnostic, transparent in its installation, and user-controlled.

### 1. Clone the repository

You can choose between global installation or project-local installation.
The paths mentioned below are examples, not universal standards. Check your agent's documentation before choosing an installation location.

|Installation Type|Description|Example|
|-------------------|-------------|-------|
|Global installation|Clone the repository into a directory supported by your agent's plugin configuration, custom plugin directory, or local marketplace location, as mentioned above.|`.agentic-system-name/.config/plugins/git clone <repository-url>`|
|Project-local installation|Clone the repository into the project's supported plugin directory if your agent supports this convention.|`my-project/.agent/plugins/git clone <repository-url>`|

### 2. Check the runtime prerequisites
The hook requires Python 3.10 or later and uses only the Python standard library.
Check your installed version:

```bash
python3 --version
```
If Python is missing or the installed version is incompatible, install a supported version before enabling the hook. 

### 3. Configure the plugin

Add the plugin to the appropriate agent settings file and enable it according to the configuration format supported by your agent. You can use the snippet in [settings-addition.json](./settings-addition.json) and add it to your agent configuration settings file.

Configure the `PreToolUse` hook to invoke `capacity_gate_hook.py` using a valid path to the cloned repository.

Ensure that:

* The plugin identifier matches the metadata and settings configuration.
* The configured command resolves the correct Python interpreter and hook file.
* The hook is registered only once in the effective configuration.
* The selected tools and event matchers are supported by your agent.

Refer to your agent's documentation for the exact settings location, hook syntax, and activation procedure.

### 4. Verify the installation

After enabling the plugin:

[x] Confirm that Python meets the minimum version requirement.
[x] Check that the hook file exists at the configured path.
[x] Verify that the agent recognizes the hook configuration.
[x] Perform a functional check using the documented hook behavior.

Do not assume that a successful repository clone means the hook is active.

[BACK TO INDEX](#index)

## How to Use the plugin 

**Dual Execution Modes**

Currently, the  [secret-exposure-auditor](./agents/secret-exposure-auditor.md)  is the sub-agent, which operates as a plugin orchestrator, so it triggers specific skills or the full audit pipeline; this method is designed to eliminate unnecessary token ingestion. 

Below, you can check the 2 modes. The plugin always needs to be ** Enabled: True **, and you should **provide the path to the target scan**; preferably use an **absolute path** to avoid any issues with the hook execution or plugin discovery:

### Mode 1: Targeted Single-Skill Execution (Token & Time Efficient)
When the user's intent maps to a narrow task, *User* prompt example:

```txt
Use /modular-credentials-sacanner-plugin to check if .env is git tracked <absolute/path/to/project/>
```
```txt
Use /modular-credentials-sacanner-plugin to run a regex for AWS keys in the/src directory <absolute/path/to/project/>
```
In this case, the  sub-agent identifies the specific matcher and can prompt the user with an informative decision:
* **Option A (Targeted Execution):** Runs ONLY `<specific-selected-skill>` with targeted arguments (e.g. `git-exposure-checker` on `.env`), skipping all other stages and saving thousands of tokens.
* **Option B (Comprehensive Audit):** Runs the full audit across the entire workspace.

- First, the sub-agent executes the `hooks/capacity_gate_hook.py` with the <absolute/path/to/project/> target.
- Then execute the specific skill with the <absolute/path/to/project/> target.

[BACK TO INDEX](#index)

### Mode 2: Full End-to-End Audit Pipeline
When a broad audit is requested or selected for the *User* prompt, for example:
```txt
Use /modular-credentials-sacanner-plugin to run a full audit <absolute/path/to/project/>
```
```txt
Use /modular-credentials-sacanner-plugin to scan for secrets in the entire workspace <absolute/path/to/project/>
```
The sub-agent sequentially executes:
`hooks/capacity_gate_hook.py` (Deterministic Discovery) -> `secret-signature-detector` -> `secret-entropy-scanner` -> `git-exposure-checker` -> `secret-false-positive-filter` -> `safe-audit-reporter`.

>[!NOTE]
>If you already use an `AGENT.md` file or other work memory for your agents, you can indicate the registry access to the plugin path, or you can enable it in your marketplace to use it in automatic full audit mode.

>[!NOTE]
> Test the plugin before using it; add some credentials or hardcode strings in your codebase to verify it works as expected. For example: `OPENAI_API_KEY=sk-1234567890` or `DB_PASSWORD=admin123`. Test the plugin as much as you need; preserve the *Zero Trust* Principle, it means constant verification and auditable evidence over trust in the code or in ourselves. This principle is the foundation of secure systems.

**Example of a plugin runtime made with Antigravity Agent**

![agent plugin runtime example](agent_plugin_runtime.png)

[BACK TO INDEX](#index)

## Hook Allocation and Enforcement
This project use a PreToolUse hook to gate tool usage; it intercepts the tool calls `view_file|read_file|grep_search` before execution. 
The goal is to make the tool call deterministic and efficient, while preventing the use of large files from the context window and reducing token consumption; it also prioritizes the relevant files for the scan considering patterns and risk tier, prioritizing the high-risk files first.

**The `hook` can be invoked in 2 forms:**
- By adding it within an existing `agent.setting.json` or `agent.setting.yaml` file (this was explained in the section **3. Configure the plugin** )
- By adding `hook: python3 hooks/capacity_gate_hook.py` to the agent's YAML frontmatter metadata.

Currently, the project already includes both forms, so you can select the desired form to use as your agent's custom workflow preference (this could also be changed in the mode that you set up the plugin, if it is local or global use).

**Current project `hooks` allocation:**

- **PreToolUse Allocation:** The hook is allocated in [`settings-addition.json`](settings-addition.json).
- **Agent Metadata Enforcement:** The hook is allocated in [`agents/secret-exposure-auditor.md`](agents/secret-exposure-auditor.md) as part of the YAML frontmatter metadata (`hook: python3 hooks/capacity_gate_hook.py`) to enforce capacity gating on agent operations.

[BACK TO INDEX](#index)

---

## Invariant Rules
1. **Strictly Non-Destructive:** No files are created, edited, deleted, or committed in the scanned workspace.
2. **Zero Network Egress:** No remote endpoints or APIs are contacted. Secrets are never tested live.
3. **Evidence Masking Invariant:** Raw secrets are NEVER outputted to logs, terminal, or final reports. All keys are masked (e.g., `AKIA************7E2A`).

### Development and Testing

Development dependencies are optional and are not required to use the plugin.

If you want to run tests or contribute to the project, follow the testing instructions in [Testing Strategy](./tests/README.md) and review `pyproject.toml`.

[BACK TO INDEX](#index)

[!IMPORTANT]
>This project uses deterministic features in some parts to combine regex logical detection with other engines and LLM classification for more effective detection. You can fine some of them as a coupled monolithic; this was intentional, because each of them was considered a unique tool. Now, as a complete src deterministic application, but if you consider a better approach, you can modularize it as much as you want. 

## License
Copyright 2026 Leticia Perez Gainza. Licensed under the Apache License 2.0.
See [LICENSE](./LICENSE) for details.

[BACK TO INDEX](#index)

