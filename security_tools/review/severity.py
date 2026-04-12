from __future__ import annotations

from security_tools.models import Severity

SEVERITY_ORDER: dict[Severity, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}

SEVERITY_RISK_SCORES: dict[Severity, int] = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
    "info": 0,
    "unknown": 0,
}


def normalize_severity(value: str | None) -> Severity:
    if not value:
        return "unknown"

    value = value.strip().lower()
    mapping: dict[str, Severity] = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "warning": "medium",
        "error": "high",
        "unknown": "unknown",
    }
    return mapping.get(value, "unknown")


def max_severity(left: Severity, right: Severity) -> Severity:
    return left if SEVERITY_ORDER[left] >= SEVERITY_ORDER[right] else right


def severity_to_risk_score(severity: Severity) -> int:
    return SEVERITY_RISK_SCORES.get(severity, 0)