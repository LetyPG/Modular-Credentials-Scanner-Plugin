---
name: secret-false-positive-filter
description: Evaluates candidate findings to eliminate false positives such as documentation templates, placeholders, mock test fixtures, and metric counters. Assigns final confidence ratings before reporting.
type: skill
inputs:
  skills_findings:
    - secret-entropy-scanner:
        type: object
        description: "Files with the findings from the entropy scanner."
    - secret-signature-scanner:
        type: object
        description: "Files with the findings from the signature scanner."
allowed_tools:
  - read_file
  - run_command (strictly read-only deterministic false-positive filter and confidence scorer):
      - python3 skills/secret-false-positive-filter/scripts/rate_confidence.py --candidate "<CANDIDATE_JSON>"
      - python3 skills/secret-false-positive-filter/scripts/rate_confidence.py --file "<FINDINGS_JSON_FILE>"
temperature: 0.1
---

# Secret False-Positive Filter & Confidence Scorer

Screens all candidate detections from signature and entropy scans against known non-secret patterns and test fixtures, categorizing verified hits vs. discarded candidates.

---

## False-Positive Classification Rules

Examine each candidate hit and discard it if it matches any of the following criteria:

### Category 1: Documentation & Placeholder Tokens
* Literal indicator words: `YOUR_API_KEY`, `<insert-key-here>`, `CHANGEME`, `replace_me`, `example`, `sample`, `dummy`, `placeholder`.
* Example: `AWS_KEY="AKIAIOSFODNN7EXAMPLE"` (Official AWS documentation dummy key).

### Category 2: Templating & Dynamic References
* String templates: `{{secret}}`, `{{API_KEY}}`, `${SECRET_KEY}`, `{token}`, `<AUTH_TOKEN>`.
* Code variable lookups: `process.env.API_KEY`, `os.environ.get("...")`, `System.getenv(...)`.

### Category 3: Test Fixtures & Local Mocking
* Hardcoded test strings situated within test directories: `test/`, `tests/`, `__tests__/`, `fixtures/`, `spec/`, `mocks/`.
* Well-known mock credentials: `admin:admin`, `admin:password`, `user:test`, `foo:bar`, `localhost`, `127.0.0.1`.

### Category 4: Metric & Counter Names
* Code metrics or API response schemas mentioning token counters:
  * `total_tokens: 150`
  * `input_tokens: 0`
  * `prompt_tokens`
  * CSS selector classes, SVG paths, or UI element IDs.

**NEVER Delete or Edit the Information provided vby the other skills, you only Reclassify them as they are identified and give them a confidence score**

---

## Confidence Rating Matrix

Assign confidence to all candidates that survive the false-positive filter as: `HIGH`, `MEDIUM`, `LOW`.
For this task you **MUST execute  `./scripts/rate_confidence.py`** to perform false-positive classification and assign confidence scores.

---

## Output Schema

The skill outputs two distinct collections:

```json
{
  "credible_findings": [
    {
      "id": "SEC-001",
      "file_path": "config/production.env",
      "line_number": 14,
      "secret_type": "AWS Access Key",
      "confidence": "HIGH",
      "masked_sample": "AKIA************4B2E",
      "surrounding_context": "export AWS_ACCESS_KEY_ID=\"AKIA************4B2E\""
    }
  ],
  "discarded_candidates": [
    {
      "file_path": "docs/quickstart.md",
      "line_number": 42,
      "candidate_snippet": "AIzaSyDummyKeyForDocs1234567890123456",
      "discard_reason": "Documentation placeholder key containing 'Dummy'"
    },
    {
      "file_path": "tests/auth.test.js",
      "line_number": 12,
      "candidate_snippet": "admin:password123",
      "discard_reason": "Hardcoded mock fixture in test suite directory"
    }
  ]
}
```
