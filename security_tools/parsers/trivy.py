from __future__ import annotations

from typing import Any

from security_tools.models import FindingLocation, NormalizedFinding
from security_tools.parsers.common import normalize_severity


def parse_trivy(payload: Any) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    if not payload or not isinstance(payload, dict):
        return findings

    results = payload.get("Results", [])
    if not isinstance(results, list):
        return findings

    for result in results:
        if not isinstance(result, dict):
            continue

        target = result.get("Target")
        vulnerabilities = result.get("Vulnerabilities", [])
        misconfigurations = result.get("Misconfigurations", [])

        for item in vulnerabilities or []:
            if not isinstance(item, dict):
                continue

            vuln_id = item.get("VulnerabilityID")
            package_name = item.get("PkgName")
            installed_version = item.get("InstalledVersion")

            findings.append(
                NormalizedFinding(
                    tool="trivy",
                    finding_type="container_vulnerability",
                    rule_id=vuln_id,
                    category="container_scanning",
                    severity=normalize_severity(item.get("Severity")),
                    title=f"Container vulnerability: {package_name or vuln_id or 'unknown'}",
                    description=item.get("Title") or item.get("Description"),
                    location=FindingLocation(path=target),
                    metadata={
                        "package_name": package_name,
                        "installed_version": installed_version,
                        "fixed_version": item.get("FixedVersion"),
                    },
                    raw_payload=item,
                )
            )

        for item in misconfigurations or []:
            if not isinstance(item, dict):
                continue

            findings.append(
                NormalizedFinding(
                    tool="trivy",
                    finding_type="static_misconfiguration",
                    rule_id=item.get("ID"),
                    category="sast",
                    severity=normalize_severity(item.get("Severity")),
                    title=item.get("Title") or f"Static issue: {item.get('ID') or 'unknown'}",
                    description=item.get("Description"),
                    location=FindingLocation(path=target),
                    metadata={"message": item.get("Message")},
                    raw_payload=item,
                )
            )

    return findings