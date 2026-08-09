# Validation Modules

This package adds two async validation modules used by Red-Agent to reduce false positives after reconnaissance.

## Active XSS Validator

- Browser-based confirmation using Playwright when installed.
- Observes console events, dialog events, and page JS state.
- Distinguishes reflection from actual execution.

## 401/403 Access-Control Triage

- Baselines a restrictive response.
- Retries with internal-IP header combinations.
- Compares status code, content length, and normalized body structure.

## Orchestration

Use `run_validation_pass(target, findings)` to validate a report or completed job, then `enrich_findings_with_validation(...)` to attach results back to findings.
