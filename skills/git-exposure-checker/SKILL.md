---
name: git-exposure-checker
description: Performs read-only Git repository queries to determine whether candidate files are tracked, untracked, ignored by .gitignore, or exposed in commit history. Use during credential audits or pre-commit checks to categorize exposure states without altering Git state.
type: skill
alowed_tools:
  - run_command (strictly read-only git queries and deterministic classifier):
      - python3 skills/git-exposure-checker/scripts/classify_risk.py --state "<EXPOSURE_STATE>"
      - python3 skills/git-exposure-checker/scripts/classify_risk.py --enrich "<json-payload>"
      - git rev-parse --is-inside-work-tree
      - git check-ignore -v -- "<relative-path>"
      - git ls-files --error-unmatch -- "<relative-path>"
      - git status --porcelain -- "<relative-path>"
      - git log -n 50 --oneline -- "<relative-path>"
denied_commands:
  - git add
  - git rm
  - git push
  - git checkout
  - git reset
  - git rebase
  - git cherry-pick
temperature: 0.1
---

# Git Exposure State Checker

A specialized, strictly read-only Git auditing skill. Determines whether sensitive files are tracked in the Git index, ignored by `.gitignore`, or leaked in historical commits.

---

## Safety Boundary: Read-Only Git Invariant

> [!CAUTION]
> This skill is strictly read-only. Never run `git add`, `git commit`, `git rm`, `git push`, `git reset`, or `git checkout`. If an operation would alter the index, working tree, or Git config, halt immediately.

---

## Exposure State Taxonomy

Every evaluated file is mapped to exactly one exposure state and a risk level:

**Exposure State Definitions:**

- `LOCAL_ONLY`: Target directory is not a Git repository. Exists only on local disk.
- `LOCAL_IGNORED`: Target directory is a Git repository, but the file is ignored by `.gitignore`.
- `UNTRACKED_UNIGNORED`: Target directory is a Git repository, but the file is untracked and NOT covered by `.gitignore`. Prone to accidental `git add .`.
- `TRACKED_DESPITE_IGNORE`: Target directory is a Git repository, but the file matches a `.gitignore` rule but is already tracked in the Git index.
- `TRACKED_ACTIVE`: Target directory is a Git repository, but the file is tracked in the Git index and part of the current tree.
- `COMMITTED_HISTORICAL`: Target directory is a Git repository, but the file or secret pattern was confirmed present in one or more past commits.

**NOTE**
For each exposure state, you **MUST execute `scripts/classify_risk.py`** to get the risk level and risk assessments rather than relying on prompt engineering, ensuring reproducible and verifiable audits.

---

## Decision Logic & Steps (Read-Only Commands)

1. Check if the target directory is a Git repository:
   ```bash
   git rev-parse --is-inside-work-tree
   ```
   - If NO, the exposure state is `LOCAL_ONLY`.
   - If YES, continue to Step 2.

2. Check if the target file is ignored by `.gitignore`:
   ```bash
   git check-ignore -v --no-index -- "<relative-path>"
   ```
   - If the command returns an exit code of 0, the file is IGNORED. Record the ignore rule file and line.
   - If the command returns a non-zero exit code, the file is NOT IGNORED.

3. Check if the target file is tracked in the Git index:
   ```bash
   git ls-files --error-unmatch -- "<relative-path>"
   ```
   - If the command returns an exit code of 0, the file is TRACKED in the index.
     - If IGNORED ──> `TRACKED_DESPITE_IGNORE`
     - If NOT IGNORED ──> `TRACKED_ACTIVE`
   - If the command returns a non-zero exit code, the file is UNTRACKED.
     - If IGNORED ──> `LOCAL_IGNORED`
     - If NOT IGNORED ──> `UNTRACKED_UNIGNORED`

4. Check if the target file or secret pattern was confirmed present in one or more past commits (bounded history inspection, limit 50 commits):
   ```bash
   git log -n 50 --oneline -- "<relative-path>"
   ```
   - If commits are returned and historical leak is confirmed ──> `COMMITTED_HISTORICAL`.

5. Obtain Deterministic Risk Classification:
   Pass the identified `exposure_state` (or verification payload) to the deterministic script:
   ```bash
   python3 skills/git-exposure-checker/scripts/classify_risk.py --state "<EXPOSURE_STATE>"
   ```
   or enrich the full JSON payload:
   ```bash
   python3 skills/git-exposure-checker/scripts/classify_risk.py --enrich '{"path": "<relative-path>", "exposure_state": "<EXPOSURE_STATE>", ...}'
   ```

---

## Execution Commands Reference

1. **Verify Git Repository:**
   ```bash
   git rev-parse --is-inside-work-tree
   ```
2. **Check `.gitignore` Rule (include `--no-index` to catch tracked files):**
   ```bash
   git check-ignore -v --no-index -- "config/deploy.env"
   ```
   *Expected output when ignored:* `.gitignore:14:*.env config/deploy.env`
3. **Verify Index Tracking:**
   ```bash
   git ls-files --error-unmatch -- "config/deploy.env"
   ```
4. **Check Working Tree Dirty Status:**
   ```bash
   git status --porcelain -- "config/deploy.env"
   ```
   *Flags:* `??` (untracked), ` M` (modified unstaged), `M ` (staged).
5. **Bounded Commit Log (Limit 50 Commits):**
   ```bash
   git log -n 50 --oneline -- "config/deploy.env"
   ```
6. **Deterministic Risk Classification:**
   ```bash
   python3 skills/git-exposure-checker/scripts/classify_risk.py --state "TRACKED_DESPITE_IGNORE"
   ```

---

## Output Format

For each input path, return structured verification details enriched with deterministic risk classification:

```json
{
  "path": "config/deploy.env",
  "is_git_repo": true,
  "is_tracked": true,
  "is_ignored": true,
  "ignore_rule": ".gitignore:14:*.env",
  "working_tree_flag": "M ",
  "exposure_state": "TRACKED_DESPITE_IGNORE",
  "risk_level": "Critical",
  "risk_assessment": "CRITICAL - File is tracked in Git index even though .gitignore specifies ignoring it."
}
```
