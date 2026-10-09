---
name: secret-signature-detector
description: Scans candidate text and configuration files against high-confidence known vendor API key signatures, tokens, and cryptographic private key blocks. Extensible through modular JSON rule definitions without modifying core prompt logic.
type: skill
allowed_tools:
  - grep_search
  - read_file
rules: 
  - path: ./rules/cloud-providers.json
  - path: ./rules/vcs-tokens.json
  - path: ./rules/crypto-keys.json
  - path: ./rules/payment-gateways.json
temperature: 0.1
---

# Secret Signature Detector

Executes high-confidence regex signature matching against candidate files using externalized, pluggable rule definitions.

---

## Detection Procedure

1. **Load Signatures:** Read rule definitions from `rules/*.json`, where you can find the **Signature Catalog Reference**.
2. **Execute Pattern Matching:**
   * For each eligible candidate file from Stage 1, run regex searches against active signatures.
3. **Record Candidate Hit:**
   * Record `file_path`, `line_number`, `signature_id`, `signature_name`, `confidence = "HIGH"`, and `raw_line_context`.
4. **Mandatory Masking Invariant:**
   * Do not persist raw matched values in logs or outputs. Replace intermediate captures with masked tokens (e.g., `AKIA************7E2A`).

---

## Signature Catalog Reference

As a quick guidance reference, here are the current rules that you can find in the `rules/` directory.

|Signature Catalog | Rules File | Specific Signatures |
|---|--|---|
|Cloud Providers|`./rules/cloud-providers.json`| AWS Access Key ID, Google Cloud / Gemini API Key|
|VCS & Collaboration|`./rules/vcs-tokens.json`| GitHub Classic PAT, GitHub Fine-Grained PAT, GitHub OAuth / App Token, Slack Tokens|
|Cryptographic Private Keys|`./rules/crypto-keys.json`| PEM Private Key Header, PuTTY SSH Key|
|Payment & AI Platforms|`./rules/payment-gateways.json`| Stripe Secret / Restricted Key, OpenAI API Key, Hugging Face Token|

---

## Output Schema

```json
{
  "matches": [
    {
      "signature_id": "SIG-AWS-001",
      "signature_name": "AWS Access Key ID",
      "file_path": "config/production.env",
      "line_number": 14,
      "confidence": "HIGH",
      "masked_sample": "AKIA************4B2E",
      "potential_impact": "Cloud resource takeover, infrastructure destruction, unauthorized compute usage"
    }
  ]
}
```
---
## Extensibility Architecture: Pluggable Rule Packs

**Note**: This is for User Reference Only. No action needed from AI agent. Just for user to know how to extend the detection capabilities.

**User Notes**: Rather than hardcoding regular expressions directly into prompt instructions, signatures are maintained in modular rule files under `rules/`:

* `rules/cloud-providers.json` (AWS, Google Cloud)
* `rules/vcs-tokens.json` (GitHub, Slack)
* `rules/crypto-keys.json` (PEM private keys, PuTTY SSH keys)
* `rules/payment-gateways.json` (Stripe, OpenAI, Hugging Face)

> [!TIP]
> **Extending Detection:** To add detection for a new service (e.g. Datadog, Snowflake, Azure, or enterprise internal tokens), add a new entry to the corresponding JSON file in `rules/` or drop a new `*.json` file into `rules/`. No changes to this skill or the orchestrator sub-agent are required.