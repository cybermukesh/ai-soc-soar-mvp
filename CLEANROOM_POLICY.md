# Clean-Room Development Policy

This project follows a strict clean-room build process.

## 1) Scope

Applies to all code, docs, prompts, workflows, and UI assets in this repository.

## 2) Core Rules

1. Build from scratch inside this repository.
2. Use external systems only as conceptual reference.
3. Do not import/copy proprietary or unknown-license code.
4. Keep implementation SIEM-agnostic and MVP-focused.

## 3) Allowed Inputs

- Product requirements and architecture notes.
- Public documentation for APIs/tools.
- Open-source components through standard dependency managers with compatible licenses.

## 4) Prohibited Inputs

- Copying source files/snippets from prior private tools or unrelated local folders.
- Reusing hidden credentials, internal tokens, or personal account metadata.
- Copying generated outputs without review of license/provenance.

## 5) Pre-Commit Checklist

- No secrets or private keys in tracked files.
- No personal account identifiers unintentionally embedded in code/docs.
- No third-party code blocks without attribution/license check.
- Commit message accurately describes original work done in this repo.

## 6) Pre-Release Checklist

- Run repo-wide secret/PII pattern scan.
- Review license compatibility of dependencies.
- Validate demo data is synthetic/sanitized.
- Confirm README reflects clean-room and provenance commitments.

## 7) Exception Handling

If direct third-party code reuse becomes necessary:

1. Document the source URL and license.
2. Record reason for reuse and modification scope.
3. Add attribution in-file and in README.
4. Re-run compliance scan before merge.
