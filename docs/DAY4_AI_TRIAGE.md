# Day 4 AI Triage

## Status

Complete for MVP mode.

## Implemented

- Structured triage decision model with fields: `verdict`, `confidence`, `risk_score`, `attack_summary`, `evidence`, `mitre`, `recommended_actions`, and `soar_recommendation`.
- Low-token in-memory triage cache keyed by normalized alert signature.
- Single-alert endpoint: `POST /triage/alert`.
- Sample batch endpoint: `GET /triage/sample`.
- Deterministic triage logic suitable for offline demo and safe fallback.

## Output Contract

`TriageDecision` values:

- `verdict`: `false_positive | low_priority | suspicious | true_positive | needs_review`
- `confidence`: float `0..1`
- `risk_score`: integer `0..100`
- `from_cache`: indicates cache replay

## Guardrails

- Keep SOAR recommendation approval-gated.
- Treat alert text as untrusted input.
- Avoid repeated re-triage for duplicate alerts when cache is valid.

## Day 5 Handoff

Use triage decisions as incident grouping inputs (entity keys + time windows + verdict/risk aggregation) and produce noise-reduction metrics.
