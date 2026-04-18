from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping, cast

from security_tools.models import EnrichedFinding, Verdict


DEFAULT_BLOCK_SEVERITIES = {"critical", "high"}
DEFAULT_WARN_SEVERITIES = {"medium"}


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y", "on"}:
            return True
        if lowered in {"false", "0", "no", "n", "off"}:
            return False
    if value is None:
        return default
    return bool(value)


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_str_set(value: Any, default: Iterable[str] | None = None) -> set[str]:
    if isinstance(value, (list, tuple, set)):
        return {str(item).strip() for item in value if str(item).strip()}
    if isinstance(value, str) and value.strip():
        return {value.strip()}
    return set(default or [])


def _normalize_policy_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _normalize_findings(
    findings: Iterable[EnrichedFinding],
) -> list[EnrichedFinding]:
    return list(findings)


def build_severity_counter(
    findings: Iterable[EnrichedFinding],
) -> Counter[str]:
    return Counter(
        str(finding.severity).lower().strip() or "unknown"
        for finding in findings
    )


def has_blocking_category(
    findings: Iterable[EnrichedFinding],
    always_block_categories: set[str],
) -> bool:
    if not always_block_categories:
        return False

    for finding in findings:
        category = (finding.category or "").strip()
        if category and category in always_block_categories:
            return True
    return False


def has_blocking_finding_type(
    findings: Iterable[EnrichedFinding],
    always_block_finding_types: set[str],
) -> bool:
    if not always_block_finding_types:
        return False

    for finding in findings:
        finding_type = (finding.finding_type or "").strip()
        if finding_type and finding_type in always_block_finding_types:
            return True
    return False


def has_any_severity(
    severity_counts: Mapping[str, int],
    severities: set[str],
) -> bool:
    return any(severity_counts.get(sev, 0) > 0 for sev in severities)


def summarize_verdict_inputs(
    findings: Iterable[EnrichedFinding],
    missing_scans: Iterable[str] | None = None,
    operational_warnings: Iterable[str] | None = None,
) -> dict[str, Any]:
    normalized_findings = _normalize_findings(findings)
    missing = sorted({str(item) for item in (missing_scans or []) if str(item).strip()})
    warnings = [str(item) for item in (operational_warnings or []) if str(item).strip()]
    severity_counts = build_severity_counter(normalized_findings)

    return {
        "total_findings": len(normalized_findings),
        "severity_counts": dict(severity_counts),
        "missing_scans": missing,
        "operational_warnings": warnings,
    }


def calculate_verdict(
    *,
    findings: Iterable[EnrichedFinding],
    missing_scans: list[str] | None = None,
    operational_warnings: list[str] | None = None,
    risk_score: int = 0,
    policy: dict[str, Any] | None = None,
) -> Verdict:
    """
    Central verdict engine for security review decisions.

    Expected policy shape:
    {
        "verdict_rules": {
            "operational_error_on_warnings": true,
            "block_if_missing_scans": true,
            "always_block_categories": ["secrets", "iam"],
            "always_block_finding_types": ["hardcoded_secret"],
            "block_on_severities": ["critical", "high"],
            "warn_on_severities": ["medium"]
        },
        "risk": {
            "enabled": true,
            "block_if_score_gte": 50,
            "warn_if_score_gte": 20
        }
    }
    """
    normalized_findings = _normalize_findings(findings)
    missing_scans = sorted(
        {str(item) for item in (missing_scans or []) if str(item).strip()}
    )
    operational_warnings = [
        str(item) for item in (operational_warnings or []) if str(item).strip()
    ]

    policy = policy or {}
    verdict_rules = _normalize_policy_dict(policy.get("verdict_rules"))
    risk_rules = _normalize_policy_dict(policy.get("risk"))

    if operational_warnings and _as_bool(
        verdict_rules.get("operational_error_on_warnings"),
        default=True,
    ):
        return cast(Verdict, "OPERATIONAL_ERROR")

    if missing_scans and _as_bool(
        verdict_rules.get("block_if_missing_scans"),
        default=True,
    ):
        return cast(Verdict, "BLOCK")

    always_block_categories = _as_str_set(
        verdict_rules.get("always_block_categories"),
        default=[],
    )
    always_block_finding_types = _as_str_set(
        verdict_rules.get("always_block_finding_types"),
        default=[],
    )
    block_on_severities = _as_str_set(
        verdict_rules.get("block_on_severities"),
        default=DEFAULT_BLOCK_SEVERITIES,
    )
    warn_on_severities = _as_str_set(
        verdict_rules.get("warn_on_severities"),
        default=DEFAULT_WARN_SEVERITIES,
    )

    if has_blocking_category(normalized_findings, always_block_categories):
        return cast(Verdict, "BLOCK")

    if has_blocking_finding_type(normalized_findings, always_block_finding_types):
        return cast(Verdict, "BLOCK")

    severity_counts = build_severity_counter(normalized_findings)

    if has_any_severity(severity_counts, block_on_severities):
        return cast(Verdict, "BLOCK")

    if _as_bool(risk_rules.get("enabled"), default=False):
        block_threshold = _as_int(
            risk_rules.get("block_if_score_gte"),
            default=999999,
        )
        warn_threshold = _as_int(
            risk_rules.get("warn_if_score_gte"),
            default=999999,
        )

        if risk_score >= block_threshold:
            return cast(Verdict, "BLOCK")

        if risk_score >= warn_threshold:
            return cast(Verdict, "WARN")

    if has_any_severity(severity_counts, warn_on_severities):
        return cast(Verdict, "WARN")

    return cast(Verdict, "PASS")


def build_verdict_rationale(
    *,
    verdict: str,
    findings: Iterable[EnrichedFinding],
    missing_scans: list[str] | None = None,
    operational_warnings: list[str] | None = None,
    runtime_context: Mapping[str, Any] | None = None,
    risk_score: int = 0,
) -> str:
    """
    Reusable human-readable explanation for why the verdict was chosen.
    """
    normalized_findings = _normalize_findings(findings)
    missing_scans = sorted(
        {str(item) for item in (missing_scans or []) if str(item).strip()}
    )
    operational_warnings = [
        str(item) for item in (operational_warnings or []) if str(item).strip()
    ]
    severity_counts = build_severity_counter(normalized_findings)

    if verdict == "OPERATIONAL_ERROR":
        if operational_warnings:
            return (
                "The review is OPERATIONAL_ERROR because one or more operational "
                f"warnings prevented a clean decision: {', '.join(operational_warnings)}."
            )
        return (
            "The review is OPERATIONAL_ERROR because the review pipeline encountered "
            "an operational condition that requires attention."
        )

    if verdict == "BLOCK" and missing_scans:
        return (
            "The review is BLOCK because one or more required scans were missing: "
            f"{', '.join(missing_scans)}."
        )

    if verdict == "BLOCK":
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        return (
            "The review is BLOCK because blocking findings or policy violations were "
            f"detected. Critical: {critical}, High: {high}, Risk score: {risk_score}."
        )

    if verdict == "WARN":
        runtime_phrase = ""
        if runtime_context and str(runtime_context.get("Verdict", "")).upper() == "PASS":
            runtime_phrase = " Runtime verification passed."
        medium = severity_counts.get("medium", 0)
        return (
            "The review is WARN because non-blocking findings or hardening "
            f"recommendations remain. Medium: {medium}, Risk score: {risk_score}."
            f"{runtime_phrase}"
        )

    if verdict == "PASS":
        return (
            "The review is PASS because required scans were present and no blocking "
            "findings were detected."
        )

    return "The review completed, but no rationale could be derived for the final verdict."