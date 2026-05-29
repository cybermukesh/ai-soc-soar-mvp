# Secure SDLC + CI/CD Guardrails

This project follows additive, non-destructive delivery rules for MVP development.

## 1) Data and History Protection

- Never remove old day content (`day-1` to `day-7`) from site/docs.
- Never rewrite or drop historical progress records unless explicitly approved.
- Prefer additive commits that extend existing behavior and documentation.

## 2) Branch and Commit Discipline

- Use small, scoped commits with clear messages.
- Keep code, docs, and site updates in the same commit only when logically linked.
- Avoid force-push on `main` except for explicit emergency remediation.

## 3) CI/CD Quality Gates (Minimum)

Before push:
- Frontend build must pass:
  - `npm --prefix frontend run build`
- Backend syntax check must pass:
  - `python3 -m compileall backend/app`

After push:
- Verify GitHub Actions workflow status is successful.
- Verify GitHub Pages reflects expected content.

## 4) Secure SDLC Controls

- RBAC enforcement on write/operations endpoints.
- Input validation and controlled error responses.
- No plaintext secret persistence in app-level storage.
- Connector actions and admin actions tracked in audit logs.
- Health checks and upstream dependency checks exposed as observable endpoints.

## 5) Deployment Consistency

To avoid Pages source mismatch:
- Keep judge site content synchronized in both:
  - `/site/*`
  - repo root (`/index.html`, `/day-*.html`, `/style.css`) when required by active Pages configuration.

## 6) Operational Verification Checklist

- `/health` returns `ok`
- auth login succeeds for admin seed user
- Wazuh connector health returns reachable
- OpenSearch connector health returns cluster status
- recent alert fetch returns normalized records

## 7) Non-Regression Rule

Any UI/feature enhancement must not break:
- login and RBAC flow
- connector health/history visibility
- incident list and timeline behavior
- day-wise documentation navigation
