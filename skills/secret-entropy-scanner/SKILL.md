---
name: secret-entropy-scanner
description: Analyzes candidate files for credential assignments, structured authentication tokens (JWT, database connection strings), and high-entropy unstructured strings. Use during deep credential audits to surface secrets that lack fixed vendor prefixes.
type: skill
allowed_tools:
  - grep_search
  - read_file
temperature: 0.1
---

# Secret Entropy & Assignment Heuristic Scanner

Evaluates files for variable assignment patterns, embedded connection credentials, and high-entropy base64/hex strings where fixed vendor signatures are absent.

---

## Rules
- This skill is organized into three detection heuristic layers: A, B, C. Each layer identify different types of credentials. 
- All secrets are detected using regex patterns in order to ensure the detection of secrets regardless of the case. For example, the regex pattern for API keys uses the (?i) flag, which makes the pattern case-insensitive. This means the pattern will match API_KEY, Api_Key, api_key, and any other combination of uppercase and lowercase letters.

## Detection Heuristics

### Layer A: Structured Auth & Connection Strings (Medium to High Confidence)
* **JSON Web Tokens (JWT):**
  * `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b`
* **Database Connection Strings with Embedded Passwords:**
  * `\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp|mssql):\/\/[^\s:]+:[^\s@]+@[^\s\/:]+`
* **Basic Auth URLs:**
  * `\bhttps?:\/\/[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+`

### Layer B: Variable Assignments (Medium Confidence)
Search for sensitive identifier assignments in configuration and code:
* **Assignment Regex:**
  * `(?i)(api_key|apikey|secret|password|passwd|auth_token|access_token|private_key|client_secret|bearer)\s*[:=]\s*['\"][^\s'\"]{8,}['\"]`
* **Environment Literal Check:**
  * Differentiate between literal values (`password = "supersecret123"`) vs. dynamic references (`password = process.env.DB_PASSWORD` or `${DB_PASS}`).
  * Only flag literal string assignments.

### Layer C: High-Entropy String Heuristics (Low to Medium Confidence)
Evaluate long, random-looking character sequences:
* **Continuous Hexadecimal Strings ($\ge 32$ chars):**
  * `\b[0-9a-fA-F]{32,64}\b`
* **Continuous Base64 Strings ($\ge 40$ chars):**
  * `\b[A-Za-z0-9+/=]{40,}\b`
* **Non-Secret Heuristic Discards:**
  * Discard Git commit SHAs, UUIDs (`[0-9a-f]{8}-[0-9a-f]{4}-...`), SVG vector paths, standard CSS class hashes, and font base64 blocks.

---

## Execution Procedure

1. For each eligible candidate file:
   * Execute regex searches for Layer A (JWTs, DB connection strings).
   * Execute regex searches for Layer B (literal assignments).
2. For configuration files (`.env*`, `*.yaml`, `*.json`, `*.toml`):
   * Run Layer C entropy checks on unmapped long string literals.
3. For all matches, capture:
   * `file_path`, `line_number`, `pattern_type`, `raw_context`.
4. Apply immediate masking:
   * Redact passwords inside URLs: `postgres://admin:********@db.internal:5432/main`
   * Redact raw assignment strings: `API_SECRET="<masked: length=32, entropy=high>"`

---

## Output Schema

```json
{
  "matches": [
    {
      "pattern_type": "Database Connection String",
      "file_path": "src/database/config.js",
      "line_number": 28,
      "confidence": "MEDIUM",
      "masked_sample": "postgresql://app_user:********@10.0.0.5:5432/prod_db",
      "potential_impact": "Unauthorized database read/write access, customer data exfiltration"
    }
  ]
}
```
