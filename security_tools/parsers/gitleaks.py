from __future__ import annotations

from typing import Any

from security_tools.models import FindingLocation, NormalizedFinding


def parse_gitleaks(payload: Any) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    if not payload or not isinstance(payload, list):
        return findings

    for item in payload:
        if not isinstance(item, dict):
            continue

        findings.append(
            NormalizedFinding(
                tool="gitleaks",
                finding_type="secret_exposure",
                rule_id=item.get("RuleID"),
                category="secret_detection",
                severity="high",
                title=item.get("Description") or "Potential secret detected",
                description=item.get("Match"),
                location=FindingLocation(
                    path=item.get("File"),
                    line=item.get("StartLine"),
                    column=item.get("StartColumn"),
                ),
                metadata={
                    "commit": item.get("Commit"),
                    "author": item.get("Author"),
                    "secret_type": item.get("RuleID"),
                },
                raw_payload=item,
            )
        )

    return findings