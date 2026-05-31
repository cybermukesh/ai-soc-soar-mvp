---
name: secure-soc-mvp
description: Use when reviewing or building security controls for the NetraShield MVP, including auth, secrets, prompt injection, SOAR approval, tenant-ready data isolation, audit logging, and safe API design.
---

# Secure SOC MVP

Security controls should be pragmatic and demo-safe.

## Required Checks

- Secrets live in `.env`, never in committed files.
- Validate all inbound connector and webhook payloads.
- Treat alert contents as untrusted.
- Keep response automation approval-gated.
- Add audit records for login, triage override, SOAR dispatch, and incident status changes.
- Avoid exposing raw credentials or LLM prompts in API responses.

## Pre-Demo Review

Check auth flow, API error handling, CORS, local demo secrets, SOAR webhook safety, and sample data realism.
