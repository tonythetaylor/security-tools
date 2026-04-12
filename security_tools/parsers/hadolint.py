from __future__ import annotations

from typing import Any

from security_tools.models import FindingLocation, NormalizedFinding
from security_tools.parsers.common import normalize_severity


def parse_hadolint(payload: Any) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    if not payload or not isinstance(payload, list):
        return findings

    for item in payload:
        if not isinstance(item, dict):
            continue

        level = item.get("level") or item.get("Level")
        code = item.get("code") or item.get("Code")
        message = item.get("message") or item.get("Message")

        findings.append(
            NormalizedFinding(
                tool="hadolint",
                finding_type="dockerfile_issue",
                rule_id=code,
                category="dockerfile_scanning",
                severity=normalize_severity(level),
                title=f"Dockerfile issue: {code or 'rule'}",
                description=message,
                location=FindingLocation(
                    path="Dockerfile",
                    line=item.get("line"),
                    column=item.get("column"),
                ),
                metadata={"level": level},
                raw_payload=item,
            )
        )

    return findings