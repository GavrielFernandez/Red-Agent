"""Async 401/403 auto-triage for access-control bypass validation.

The validator compares baseline 401/403 responses with retries using
internal-IP headers. It flags a bypass only when the follow-up response
materially differs from the baseline.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any, Dict, Iterable, List, Optional

import requests

from .models import ValidationAttempt, ValidationResult


DEFAULT_INTERNAL_IPS = [
    "127.0.0.1",
    "localhost",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.0.1",
    "::1",
]

DEFAULT_BYPASS_HEADERS = [
    "X-Forwarded-For",
    "X-Custom-IP-Authorization",
    "X-Real-IP",
    "X-Originating-IP",
]


@dataclass
class ResponseSnapshot:
    status_code: int
    content_length: int
    normalized_body: str
    raw_excerpt: str


class AccessControlTriage:
    """Attempt safe access-control triage for 401/403 responses."""

    def __init__(
        self,
        *,
        timeout_seconds: int = 12,
        verify_tls: bool = True,
        concurrency: int = 6,
    ):
        self.timeout_seconds = timeout_seconds
        self.verify_tls = verify_tls
        self.concurrency = max(1, concurrency)

    def _normalize_body(self, body: str) -> str:
        body = body or ""
        body = re.sub(r"\s+", " ", body)
        body = re.sub(r"[0-9a-f]{12,}", "", body, flags=re.IGNORECASE)
        body = re.sub(r"[0-9]+", "#", body)
        return body.strip().lower()[:4000]

    def _snapshot(self, response: requests.Response) -> ResponseSnapshot:
        body = response.text or ""
        return ResponseSnapshot(
            status_code=response.status_code,
            content_length=len(response.content or b""),
            normalized_body=self._normalize_body(body),
            raw_excerpt=body[:500],
        )

    def _compare(self, baseline: ResponseSnapshot, candidate: ResponseSnapshot) -> Dict[str, Any]:
        similarity = SequenceMatcher(None, baseline.normalized_body, candidate.normalized_body).ratio()
        content_length_delta = abs(candidate.content_length - baseline.content_length)
        length_delta_ratio = content_length_delta / max(baseline.content_length, 1)
        status_changed = candidate.status_code != baseline.status_code
        bypass_likely = (
            candidate.status_code not in {401, 403}
            and (
                candidate.status_code in {200, 201, 202, 204, 206, 301, 302, 307, 308}
                or status_changed
                or similarity < 0.92
                or length_delta_ratio > 0.15
            )
        )

        return {
            "status_changed": status_changed,
            "similarity": round(similarity, 4),
            "content_length_delta": content_length_delta,
            "length_delta_ratio": round(length_delta_ratio, 4),
            "bypass_likely": bypass_likely,
        }

    async def _fetch(self, url: str, headers: Optional[Dict[str, str]] = None) -> Optional[requests.Response]:
        def _do_request():
            return requests.get(
                url,
                headers=headers or {},
                timeout=self.timeout_seconds,
                allow_redirects=False,
                verify=self.verify_tls,
            )

        try:
            return await asyncio.to_thread(_do_request)
        except Exception:
            return None

    async def triage(
        self,
        url: str,
        *,
        internal_ips: Optional[Iterable[str]] = None,
        bypass_headers: Optional[Iterable[str]] = None,
    ) -> ValidationResult:
        """Run baseline vs bypass-header retries against a protected URL."""

        internal_ips = list(internal_ips or DEFAULT_INTERNAL_IPS)
        bypass_headers = list(bypass_headers or DEFAULT_BYPASS_HEADERS)

        baseline_response = await self._fetch(url)
        if baseline_response is None:
            return ValidationResult(
                validator="access_control_triage",
                target=url,
                finding_type="header_injection",
                confirmed=False,
                status="error",
                confidence=0.0,
                message="Unable to fetch baseline response",
                evidence={"url": url},
                errors=["baseline_request_failed"],
            )

        baseline = self._snapshot(baseline_response)
        attempts: List[ValidationAttempt] = []
        candidate_evidence: List[Dict[str, Any]] = []
        bypass_hit: Optional[Dict[str, Any]] = None

        if baseline.status_code not in {401, 403}:
            return ValidationResult(
                validator="access_control_triage",
                target=url,
                finding_type="header_injection",
                confirmed=False,
                status="not_applicable",
                confidence=0.0,
                message=f"Baseline is {baseline.status_code}, not a restrictive response",
                evidence={
                    "baseline": baseline.__dict__,
                    "note": "triage only runs when the path returns 401/403",
                },
                attempts=[ValidationAttempt(
                    tool="access_control_triage",
                    target=url,
                    ok=False,
                    status="not_applicable",
                    message="Baseline is not 401/403",
                    evidence={"baseline_status": baseline.status_code},
                )],
            )

        sem = asyncio.Semaphore(self.concurrency)

        async def _attempt(header_name: str, ip_value: str) -> Dict[str, Any]:
            async with sem:
                headers = {header_name: ip_value}
                response = await self._fetch(url, headers=headers)
                if response is None:
                    return {
                        "header": header_name,
                        "ip": ip_value,
                        "status": "error",
                        "ok": False,
                        "message": "Request failed",
                        "comparison": {},
                        "snapshot": None,
                    }
                snapshot = self._snapshot(response)
                comparison = self._compare(baseline, snapshot)
                return {
                    "header": header_name,
                    "ip": ip_value,
                    "status": response.status_code,
                    "ok": comparison["bypass_likely"],
                    "message": "bypass candidate" if comparison["bypass_likely"] else "no bypass",
                    "comparison": comparison,
                    "snapshot": snapshot.__dict__,
                }

        tasks = [
            _attempt(header_name, ip_value)
            for header_name in bypass_headers
            for ip_value in internal_ips
        ]
        results = await asyncio.gather(*tasks)

        for item in results:
            evidence = {
                "url": url,
                "baseline": baseline.__dict__,
                **item,
            }
            candidate_evidence.append(evidence)
            attempts.append(ValidationAttempt(
                tool="access_control_triage",
                target=url,
                ok=bool(item.get("ok")),
                status=str(item.get("status")),
                message=str(item.get("message")),
                evidence=evidence,
            ))
            if item.get("ok") and bypass_hit is None:
                bypass_hit = evidence

        confirmed = bypass_hit is not None
        confidence = 0.93 if confirmed else 0.0
        status = "bypass_confirmed" if confirmed else "not_confirmed"
        message = (
            f"Access-control bypass candidate confirmed via {bypass_hit['header']}={bypass_hit['ip']}"
            if confirmed
            else "No material bypass found"
        )

        return ValidationResult(
            validator="access_control_triage",
            target=url,
            finding_type="header_injection",
            confirmed=confirmed,
            status=status,
            confidence=confidence,
            message=message,
            evidence={
                "baseline": baseline.__dict__,
                "attempts": candidate_evidence,
                "bypass_hit": bypass_hit,
            },
            attempts=attempts,
        )
