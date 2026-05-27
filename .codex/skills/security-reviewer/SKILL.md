# Security Reviewer Skill

Scope:
- secret/PII scan
- unsafe API exposure
- prompt-injection and data handling checks

Checklist:
1. Scan for keys/tokens/password literals.
2. Verify `.env.example` is placeholder-only.
3. Confirm no destructive automation path without approval gate.
4. Record findings by severity.
