# Provenance Statement

This repository is built as a clean-room MVP implementation for `ai-soc-soar-mvp`.

## Source Policy

- All production code in this repository is authored specifically for this MVP.
- External projects may be used for high-level ideas only (architecture patterns, workflow concepts, product framing).
- Direct copy-paste of third-party source code is not allowed unless explicitly licensed, attributed, and approved.
- Sample security alerts are synthetic/demo fixtures for MVP development.

## Reference Usage Rules

- Allowed: design inspiration, endpoint patterns, operational workflows.
- Not allowed: verbatim code transfer from other repositories/tools.
- If any third-party snippet is intentionally reused, it must include:
  - license compatibility check,
  - attribution note,
  - file-level comment and README mention.

## Identity And Data Hygiene

- No personal tokens, private credentials, or unrelated user/account artifacts should be committed.
- `.env.example` contains placeholders only.
- Secrets must be provided at runtime via local environment or secret manager.

## Verification Practice

- Regular static scans for PII/secret patterns.
- Pre-push review for accidental copied license headers or foreign code blocks.
- Commit history kept auditable and scoped to MVP work only.
