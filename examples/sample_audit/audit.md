# ZGuard audit summary

- **Decision:** ALLOW
- **Input:** `sample_input.log` (sha256 `8c77b7121ce6ab55...`)
- **Lines scanned:** 10
- **Policy mode:** standard
- **ML layer:** on
- **Generated:** 2026-10-17T13:13:33+00:00

Raw values are never written here. Fingerprints are truncated HMAC-SHA256 values.

## Counts by type

| Type | Count |
|---|---|
| API_KEY | 2 |
| EMAIL | 1 |
| IPV4 | 2 |
| USER_ID | 2 |

## Findings

| Line | Type | Source | Severity | Action | Preview | Fingerprint |
|---|---|---|---|---|---|---|
| 2 | EMAIL | rule | medium | masked | [REDACTED:EMAIL] | 24f0c5e7e4e1 |
| 3 | IPV4 | rule | low | masked | [REDACTED:IPV4] | ee01f8817a29 |
| 4 | API_KEY | rule | high | masked | [REDACTED:API_KEY] | a3cf84dc4d6d |
| 5 | USER_ID | rule | low | masked | [REDACTED:USER_ID] | 10f00bddbab9 |
| 6 | USER_ID | rule | low | masked | [REDACTED:USER_ID] | 222b3640e6f4 |
| 6 | IPV4 | rule | low | masked | [REDACTED:IPV4] | 22a1148340ee |
| 7 | API_KEY | rule | high | masked | [REDACTED:API_KEY] | 4fbae6420256 |
