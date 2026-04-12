from __future__ import annotations

from typing import Any

from security_tools.models import FindingLocation, NormalizedFinding


def parse_safety(payload: Any) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    if not payload:
        return findings

    entries: list[dict[str, Any]] = []
    if isinstance(payload, list):
        entries = [item for item in payload if isinstance(item, dict)]
    elif isinstance(payload, dict):
        if isinstance(payload.get("vulnerabilities"), list):
            entries = [item for item in payload["vulnerabilities"] if isinstance(item, dict)]
        elif isinstance(payload.get("results"), list):
            entries = [item for item in payload["results"] if isinstance(item, dict)]

    for item in entries:
        vuln_id = str(
            item.get("vulnerability_id")
            or item.get("id")
            or item.get("advisory")
            or "safety-finding"
        )
        package_name = item.get("package_name") or item.get("package") or "unknown-package"
        affected_version = item.get("analyzed_version") or item.get("installed_version")
        description = item.get("advisory") or item.get("description")

        findings.append(
            NormalizedFinding(
                tool="safety",
                finding_type="dependency_vulnerability",
                rule_id=vuln_id,
                category="dependency_scanning",
                severity="medium",
                title=f"Vulnerable dependency detected: {package_name}",
                description=description,
                location=FindingLocation(path="requirements.txt"),
                metadata={
                    "package_name": package_name,
                    "affected_version": affected_version,
                    "fixed_versions": item.get("fixed_versions"),
                },
                raw_payload=item,
            )
        )

    return findings