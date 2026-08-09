"""Shared data models for validation modules."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class ValidationAttempt:
    """One validation attempt against a URL or finding."""

    tool: str
    target: str
    ok: bool
    status: str
    message: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    checked_at: str = field(default_factory=lambda: datetime.now().isoformat())
    duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationResult:
    """Normalized result returned by validation modules."""

    validator: str
    target: str
    finding_type: str
    confirmed: bool
    status: str
    confidence: float = 0.0
    message: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    attempts: List[ValidationAttempt] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    checked_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["attempts"] = [attempt.to_dict() for attempt in self.attempts]
        return data
