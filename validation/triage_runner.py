"""Finding-driven validation runner for Red-Agent reports and jobs."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlparse

from .active_xss import ActiveXSSValidator
from .header_triage import AccessControlTriage
from .models import ValidationResult


def _validation_confidence_percent(result: ValidationResult) -> int:
    """Convert validator confidence (0-1 or 0-100) to bounded percent."""
    try:
        value = float(result.confidence)
    except (TypeError, ValueError):
        return 0

    if value <= 1:
        value *= 100
    return int(max(0, min(100, round(value))))


def _validation_evidence_strength(result: ValidationResult) -> str:
    """Map validation outcomes to a readable evidence-strength label."""
    status = str(result.status or "").lower()
    if result.confirmed:
        return "strong"
    if status in {"reflected_only", "potential", "not_confirmed"}:
        return "moderate"
    return "weak"


def _is_xss_finding(finding: Dict[str, Any]) -> bool:
    finding_type = str(finding.get("type", finding.get("attack", ""))).lower()
    status = str(finding.get("status", "")).lower()
    description = str(finding.get("description", "")).lower()
    return (
        finding_type == "xss"
        or "cross-site scripting" in description
        or ("xss" in finding_type and status in {"confirmed", "potential", "unknown", "reflected"})
    )


def _is_header_injection_finding(finding: Dict[str, Any]) -> bool:
    finding_type = str(finding.get("type", finding.get("attack", ""))).lower()
    status = str(finding.get("status", "")).lower()
    description = str(finding.get("description", "")).lower()
    return (
        finding_type == "header_injection"
        or "header injection" in description
        or (finding_type == "header_injection" and status in {"potential", "unknown", "suspect"})
    )


def _normalize_target_url(target: str, location: str) -> str:
    if location.startswith("http://") or location.startswith("https://"):
        return location
    if location.startswith("/") and target.startswith("http"):
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}{location}"
    return target


async def run_validation_pass(
    target: str,
    findings: Iterable[Dict[str, Any]],
) -> List[ValidationResult]:
    """Run the appropriate validators against findings from a report or job."""

    results: List[ValidationResult] = []
    xss_validator = ActiveXSSValidator()
    header_validator = AccessControlTriage()

    for finding in findings:
        location = str(finding.get("location") or target or "").strip()
        candidate_url = _normalize_target_url(target, location)

        if _is_xss_finding(finding) and candidate_url.startswith(("http://", "https://")):
            result = await xss_validator.validate(
                candidate_url,
                parameter_name=str(finding.get("parameter_name", "q")),
                marker=str(finding.get("marker", "RedAgent_XSS_Confirmed")),
            )
            results.append(result)
            continue

        if _is_header_injection_finding(finding) and candidate_url.startswith(("http://", "https://")):
            result = await header_validator.triage(candidate_url)
            results.append(result)

    return results


def enrich_findings_with_validation(
    findings: List[Dict[str, Any]],
    validation_results: Iterable[ValidationResult],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Attach validation results to matching findings and compute a summary."""

    results_list = list(validation_results)
    enriched = [dict(finding) for finding in findings]

    def _match_key(finding: Dict[str, Any]) -> Tuple[str, str]:
        return (
            str(finding.get("type", finding.get("attack", ""))).lower(),
            str(finding.get("location", "")).strip().lower(),
        )

    by_key = { _match_key(finding): finding for finding in enriched }

    for result in results_list:
        key = (result.finding_type.lower(), result.target.strip().lower())
        if key in by_key:
            finding = by_key[key]
            finding["validation"] = result.to_dict()
            if result.confirmed:
                finding["status"] = "confirmed"
            elif finding.get("status") in {None, "", "potential", "unknown"}:
                finding["status"] = result.status
            finding.setdefault("validation_status", result.status)
            finding.setdefault("validation_confidence", result.confidence)
            finding["confidence_score"] = max(
                int(finding.get("confidence_score", 0) or 0),
                _validation_confidence_percent(result),
            )
            finding["evidence_strength"] = _validation_evidence_strength(result)
        else:
            enriched.append({
                "type": result.finding_type,
                "location": result.target,
                "status": result.status,
                "validation": result.to_dict(),
                "description": result.message,
                "severity": "high" if result.confirmed else "medium",
                "confidence_score": _validation_confidence_percent(result),
                "evidence_strength": _validation_evidence_strength(result),
            })

    summary = {
        "total_validations": len(results_list),
        "confirmed": sum(1 for r in results_list if r.confirmed),
        "not_confirmed": sum(1 for r in results_list if not r.confirmed and r.status not in {"error", "unavailable"}),
        "errors": sum(1 for r in results_list if r.status in {"error", "unavailable"}),
    }

    return enriched, summary
