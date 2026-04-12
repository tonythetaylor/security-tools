from __future__ import annotations


def normalize_severity(value: str | None) -> str:
    if not value:
        return "unknown"

    value = value.strip().lower()
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "warning": "medium",
        "error": "high",
    }
    return mapping.get(value, "unknown")