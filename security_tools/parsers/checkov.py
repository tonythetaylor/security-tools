from __future__ import annotations

from typing import Any

from security_tools.models import FindingLocation, NormalizedFinding
from security_tools.parsers.common import normalize_severity


def parse_checkov(payload: Any) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    if not payload or not isinstance(payload, dict):
        return findings

    failed_checks = (
        payload.get("results", {}).get("failed_checks", [])
        if isinstance(payload.get("results"), dict)
        else []
    )

    for item in failed_checks:
        if not isinstance(item, dict):
            continue

        file_path = item.get("file_path")
        file_abs = item.get("file_abs_path")
        check_id = item.get("check_id")
        check_name = item.get("check_name")

        findings.append(
            NormalizedFinding(
                tool="checkov",
                finding_type="iac_misconfiguration",
                rule_id=check_id,
                category="iac_scanning",
                severity=normalize_severity(item.get("severity")),
                title=check_name or f"IaC issue: {check_id or 'check'}",
                description=item.get("guideline"),
                location=FindingLocation(
                    path=file_path or file_abs,
                    line=item.get("file_line_range", [None])[0]
                    if isinstance(item.get("file_line_range"), list) and item.get("file_line_range")
                    else None,
                ),
                metadata={
                    "resource": item.get("resource"),
                    "check_class": item.get("check_class"),
                },
                raw_payload=item,
            )
        )

    return findings