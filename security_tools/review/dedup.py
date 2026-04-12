from __future__ import annotations

from security_tools.models import EnrichedFinding
from security_tools.review.severity import max_severity


def deduplicate_findings(findings: list[EnrichedFinding]) -> list[EnrichedFinding]:
    deduped: dict[tuple[str | None, str, str | None, str], EnrichedFinding] = {}

    for finding in findings:
        key = (
            finding.rule_id,
            finding.finding_type,
            finding.location.path,
            finding.title.strip().lower(),
        )

        if key not in deduped:
            deduped[key] = finding
            continue

        existing = deduped[key]
        existing.severity = max_severity(existing.severity, finding.severity)

        if not existing.description and finding.description:
            existing.description = finding.description

        if not existing.rationale and finding.rationale:
            existing.rationale = finding.rationale

        if not existing.suggested_fix and finding.suggested_fix:
            existing.suggested_fix = finding.suggested_fix

        existing_refs = set(existing.compliance_refs)
        new_refs = [ref for ref in finding.compliance_refs if ref not in existing_refs]
        existing.compliance_refs.extend(new_refs)

    return list(deduped.values())