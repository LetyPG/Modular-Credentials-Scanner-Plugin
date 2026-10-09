# Credential & Secret Exposure Audit Report

## Metadata & Scan Metrics
Plugin version: ${PLUGIN_VERSION}
Scan Timestamp: ${SCAN_TIMESTAMP}
Workspace Root: ${WORKSPACE_ROOT}
Report Path: ${REPORT_PATH}

## 1. Executive Summary
- **Overall Assessment:** [CLEAN | POTENTIAL SECRETS DETECTED | CONFIRMED EXPOSURE DETECTED]
- **Total Findings:** [Count] (High: [X], Medium: [Y], Low: [Z])
- **Exposure Breakdown:** [X] Tracked in Git, [Y] Untracked / Unignored, [Z] Ignored / Local Only
- **Git Context:** [Git repository detected at <root> | No Git repository detected]

---

## 2. Scope & Capacity Metrics
| Metric | Value |
|---|---|
| Workspace Root | `<path>` |
| Configured Limit (`MAX_FILES_TO_SCAN`) | `500` |
| Total Files Enumerated | `[Count]` |
| Files Excluded (Dependencies/Build/Binary) | `[Count]` |
| Files Eligible for Analysis | `[Count]` |
| Files Actually Scanned | `[Count]` |
| Files Skipped Due to Capacity Limit | `[Count]` |

*Exclusion Summary:* [Brief description of excluded directories, e.g., node_modules, dist, .git]

---

## 3. Findings Table
| ID | Secret Type | File Path | Line | Confidence | Git Status | Exposure State | Potential Impact |
|---|---|---|---:|---|---|---|---|
| SEC-001 | AWS Access Key | `config/deploy.env` | 14 | HIGH | Tracked | TRACKED_ACTIVE | Cloud resource takeover |

---

## 4. Detailed Finding Evidence & Analysis

### Finding [ID]: [Secret Type]
- **File:** `path/to/file:line`
- **Confidence:** [HIGH | MEDIUM | LOW]
- **Detection Method:** [Signature Pattern | Variable Assignment | Entropy]
- **Git Tracking Status:** [Tracked | Untracked | Ignored]
- **Ignore Coverage:** [Covered by .gitignore line X | Not covered]
- **Safe Evidence:** `KEY_NAME="AKIA************3F1A"`
- **Surrounding Context:** `export AWS_ACCESS_KEY_ID="AKIA************3F1A"`
- **Why Identified:** Matches vendor format specifications.
- **Potential Security Impact:** Unauthorized API calls against remote infrastructure.
- **Recommended Action for Human Reviewer:** Verify whether key is active; rotate/revoke immediately if valid; move to secret vault.

---

## 5. False Positives & Excluded Candidates
| File Path | Line | Candidate Snippet | Reason Discarded |
|---|---:|---|---|
| `docs/api.md` | 45 | `{{secret_key}}` | Documentation placeholder template |

---

## 6. Recommended Human Actions
1. **Immediate Quarantine:** Do not commit or push untracked files with findings (`UNTRACKED_UNIGNORED`).
2. **Git Remediation for Tracked Findings:** For files with status `TRACKED_ACTIVE` or `TRACKED_DESPITE_IGNORE`, adding to `.gitignore` is insufficient—purge commits using `git-filter-repo` or BFG Repo-Cleaner.
3. **Key Revocation:** Invalidate and rotate any confirmed secrets in their respective provider consoles.
4. **Environment Secret Management:** Transition secrets into environment variables managed by cloud secret vaults (e.g., AWS Secrets Manager, HashiCorp Vault).

---

## 7. Audit Limitations
- **Read-Only Scope:** No active credential verification was performed against external provider endpoints.
- **File Limit:** Audit was bounded to [X] files.
- **Binary/Archive Exclusions:** Compressed archives, binaries, and compiled assets were not unpacked or decompiled.
- **History Scope:** Git commit history was inspected up to [X] commits (or skipped). Older commits were not evaluated.
```
