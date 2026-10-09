---
name: safe-audit-reporter
description: Compiles verified credential findings, Git exposure states, and discarded false positives into a standardized Markdown audit report. Strictly enforces the Zero-Raw-Secret evidence masking invariant.
type: skill
allowed_tools:
  - list_files
  - read_file
  - write_file
  - mask_evidence
  - run_command (strictly read-only deterministic risk consolidator):
      - python3 skills/safe-audit-reporter/scripts/consolidate_risk.py --file "<FINDINGS_JSON_FILE>"
      - python3 skills/safe-audit-reporter/scripts/consolidate_risk.py --finding "<FINDING_JSON>"
inputs:
  skills_findings:
    - secret-entropy-scanner:
        type: object
        description: "Files with the findings from the entropy scanner."
    - secret-signature-scanner:
        type: object
        description: "Files with the findings from the signature scanner."
    - git-exposure-checker:
        type: object
        description: "Files with the findings from the git exposure checker."
    - secret-false-positive-filter:
        type: object
        description: "Files with the findings from the false positive filter."
temperature: 0.0
---

# Safe Audit Reporter

Assembles all findings into a deterministic Markdown report, maps findings to real-world security impact, and guarantees that no raw credentials or secrets appear in terminal outputs or generated artifacts.

---

## Zero-Raw-Secret Masking Invariant

> [!CAUTION]
> **Under no circumstances may full raw credentials or secrets be emitted into logs, chat, or generated report files.**

Apply the following masking transformations before writing:

* **Prefixed Vendor Keys (AWS, GitHub, GCP, Stripe, OpenAI, etc.):**
  * Show up to 4 prefix characters and up to 4 suffix characters, with asterisks filling the middle:
    * `AKIA************7E2A`
    * `ghp_************1A9B`
    * `AIza************zK90`
* **Private Cryptographic Keys:**
  * Preserve headers and mask the key body:
    * `-----BEGIN RSA PRIVATE KEY----- [MASKED PRIVATE KEY BLOCK] -----END RSA PRIVATE KEY-----`
* **Connection Strings with Embedded Passwords:**
  * Mask the password segment only:
    * `postgresql://db_user:********@10.0.1.20:5432/production`
* **Unstructured High-Entropy Strings:**
  * Replace with metadata descriptor:
    * `<masked: length=48, entropy=high>`

---

## Security Impact Matrix

Map each verified secret type to its standard technical and organizational impact:

| Credential Type | Technical Impact | Potential Escalation Consequence |
|---|---|---|
| **Cloud Provider Keys (AWS, GCP, Azure)** | Unauthorized cloud resource access, compute hijacking | Tenant takeover, infrastructure destruction, crypto-mining fraud |
| **VCS Tokens (GitHub, GitLab)** | Source code exfiltration, branch protection bypass | Supply chain poisoning, malicious binary release |
| **Database Credentials** | Read/write access to application databases | Customer PII leak, ransomware encryption, compliance violation |
| **Private Keys (SSH, RSA, EC)** | Host shell access, server SSH authentication | Lateral network movement, encrypted communication interception |
| **Payment Gateways (Stripe, PayPal)** | Financial ledger inspection, transaction execution | Fraudulent refunds, unauthorized charges, merchant fine |
| **Internal Auth / JWT Secrets** | Forgery of user sessions and admin claims | Authentication bypass, administrative privilege escalation |

---

## 3. Decision Logic and Steps

To ensure consistent and mathematically verifiable findings across audit runs, you **MUST execute `scripts/consolidate_risk.py`** to perform cross-referencing and metric aggregation rather than relying on prompt-engineered calculations.

1. **Deterministic Risk Consolidation Execution:**
   Execute the consolidator script by passing the aggregated findings payload or single candidate:
   ```bash
   python3 skills/safe-audit-reporter/scripts/consolidate_risk.py --file "<FINDINGS_JSON_FILE>"
   ```
   Or for a single finding:
   ```bash
   python3 skills/safe-audit-reporter/scripts/consolidate_risk.py --finding '{"exposure_state": "<STATE>", "secret_type": "<TYPE>"}'
   ```

2. **Cross-Referenced Decision Matrix Resolution:**
   The script deterministically cross-references:
   - **Git Exposure State** (`TRACKED_ACTIVE`, `UNTRACKED_UNIGNORED`, `LOCAL_IGNORED`, etc. from `git-exposure-checker`)
   - **Credential Impact Category** (Cloud Provider, Database, Private Keys, Payment Gateways, VCS, Auth)
   
   It outputs:
   - `final_risk_score`: Standardized score on a 1–10 scale:
     - **Low-Risk (1–3):** e.g., `LOCAL_ONLY` / `LOCAL_IGNORED` with lower-impact credentials.
     - **Medium-Risk (4–6):** e.g., `UNTRACKED_UNIGNORED` with lower-impact, or local-only with high-impact keys.
     - **High-Risk (7–10):** e.g., `TRACKED_*` or `COMMITTED_HISTORICAL` or unignored cloud/DB/private keys.
   - `final_risk_tier`: Standardized executive severity (`HIGH`, `MEDIUM`, `LOW`).
   - `technical_impact` & `potential_escalation`: Standard taxonomy descriptions for Section 3 and Section 4 of the report.

3. **Populate Report Metrics from Consolidated Output:**
   Directly inject the deterministic `metrics` block produced by `consolidate_risk.py` into the executive report template:
   - `${TOTAL_COUNT}` ──> `metrics.total_findings`
   - `${HIGH_COUNT}` ──> `metrics.high_risk_count`
   - `${MEDIUM_COUNT}` ──> `metrics.medium_risk_count`
   - `${LOW_COUNT}` ──> `metrics.low_risk_count`
   - `Overall Assessment` ──> `metrics.overall_assessment`
   - `Exposure Breakdown` ──> `metrics.tracked_count`, `metrics.untracked_count`, `metrics.local_count`


---

## Standard Deterministic Output Template

You will generate the final deliverable to be presented to the user in a markdown format.
The final deliverable must adhere to the executive standard report template, for that use the  `assets/standard_output_template.md` as a base and fill it with the findings from the other skills. 
You must store the final report at the root directory within the workspace that you were scanning, named: `security_audit_report_{timestamp}.md`.

Then you will inform user with the following message:

```txt
Report completed. View the full audit at: ${ReportPath}
Total findings: ${TOTAL_COUNT}
High-risk findings: ${HIGH_COUNT}
Medium-risk findings: ${MEDIUM_COUNT}
Low-risk findings: ${LOW_COUNT}
```