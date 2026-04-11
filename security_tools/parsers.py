from __future__ import annotations

from typing import Any

from security_tools.models import NormalizedFinding


def parse_trivy(data: Any) -> list[dict]:
    if not isinstance(data, dict):
        return []
    findings: list[dict] = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(NormalizedFinding(
                source="trivy",
                finding_type="container_vulnerability",
                severity=(vuln.get("Severity") or "unknown").lower(),
                title=vuln.get("VulnerabilityID") or "unknown-vulnerability",
                description=vuln.get("Title") or "",
                location=result.get("Target"),
                recommendation=f"Upgrade or remediate package. Fixed version: {vuln.get('FixedVersion') or 'unknown'}",
                compliance_refs=["NIST SI-2", "FedRAMP RA-5"],
            ).to_dict())
    return findings


def parse_gitleaks(data: Any) -> list[dict]:
    if not isinstance(data, list):
        return []
    findings: list[dict] = []
    for leak in data:
        findings.append(NormalizedFinding(
            source="gitleaks",
            finding_type="secret",
            severity="high",
            title=leak.get("RuleID") or "secret-detected",
            description=leak.get("Description") or "Potential secret detected",
            location=leak.get("File"),
            recommendation="Remove the secret and rotate credentials if real.",
            compliance_refs=["NIST IA-5", "FedRAMP IA-5"],
        ).to_dict())
    return findings


def parse_checkov(data: Any) -> list[dict]:
    if not isinstance(data, dict):
        return []
    findings: list[dict] = []
    failed = data.get("results", {}).get("failed_checks", []) or []
    for check in failed:
        findings.append(NormalizedFinding(
            source="checkov",
            finding_type="iac",
            severity=(check.get("severity") or "medium").lower(),
            title=check.get("check_name") or check.get("check_id") or "checkov-finding",
            description=check.get("check_id") or "",
            location=check.get("file_path"),
            recommendation="Review and remediate the IaC misconfiguration.",
            compliance_refs=["NIST CM-6", "FedRAMP CM-6"],
        ).to_dict())
    return findings


def parse_hadolint(data: Any) -> list[dict]:
    if not isinstance(data, list):
        return []
    findings: list[dict] = []
    for item in data:
        findings.append(NormalizedFinding(
            source="hadolint",
            finding_type="dockerfile",
            severity=(item.get("level") or "warning").lower(),
            title=item.get("code") or "hadolint-rule",
            description=item.get("message") or "",
            location=item.get("file"),
            recommendation="Align the Dockerfile with container hardening best practices.",
            compliance_refs=["NIST CM-6", "DISA Hardening Expectations"],
        ).to_dict())
    return findings


def parse_safety(data: Any) -> list[dict]:
    if not isinstance(data, list):
        return []
    findings: list[dict] = []
    for vuln in data:
        findings.append(NormalizedFinding(
            source="safety",
            finding_type="dependency",
            severity="high",
            title=vuln.get("vulnerability_id") or "dependency-vulnerability",
            description=vuln.get("advisory") or "",
            location=vuln.get("package_name"),
            recommendation="Upgrade the affected dependency.",
            compliance_refs=["NIST SI-2", "FedRAMP RA-5"],
        ).to_dict())
    return findings
