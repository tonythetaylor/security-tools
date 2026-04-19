from __future__ import annotations

from security_tools.intelligence.ingest.models import ExtractedSection
from security_tools.intelligence.models import ComplianceReference, KnowledgeDocument


NIST_800_53_FAMILY_MAPPINGS: dict[str, dict] = {
    "AC": {
        "category": "access_security",
        "applies_to": ["access_control", "authorization", "least_privilege", "identity_security"],
        "tags": ["access-control", "authorization", "least-privilege"],
    },
    "AT": {
        "category": "training_security",
        "applies_to": ["security_training", "awareness", "role_based_training"],
        "tags": ["training", "awareness", "education"],
    },
    "AU": {
        "category": "logging_security",
        "applies_to": ["audit_logging", "audit_trail", "security_monitoring"],
        "tags": ["audit", "logging", "traceability"],
    },
    "CA": {
        "category": "assurance_security",
        "applies_to": ["security_assessment", "continuous_monitoring", "authorization"],
        "tags": ["assessment", "continuous-monitoring", "authorization"],
    },
    "CM": {
        "category": "configuration_security",
        "applies_to": ["secure_configuration", "baseline_configuration", "change_management"],
        "tags": ["configuration", "hardening", "baseline"],
    },
    "CP": {
        "category": "resilience_security",
        "applies_to": ["contingency_planning", "recovery", "availability"],
        "tags": ["contingency", "recovery", "availability"],
    },
    "IA": {
        "category": "identity_security",
        "applies_to": ["authentication", "identity_management", "credential_security"],
        "tags": ["authentication", "identity", "credentials"],
    },
    "IR": {
        "category": "incident_response",
        "applies_to": ["incident_response", "response_process", "security_operations"],
        "tags": ["incident-response", "response", "operations"],
    },
    "MA": {
        "category": "maintenance_security",
        "applies_to": ["maintenance", "authorized_maintenance", "support_access"],
        "tags": ["maintenance", "support", "operational-security"],
    },
    "MP": {
        "category": "data_security",
        "applies_to": ["media_protection", "data_handling", "media_sanitization"],
        "tags": ["media", "data-handling", "sanitization"],
    },
    "PE": {
        "category": "physical_security",
        "applies_to": ["physical_access", "environmental_protection", "facility_security"],
        "tags": ["physical-security", "facilities", "environment"],
    },
    "PL": {
        "category": "governance_security",
        "applies_to": ["security_planning", "policy", "system_security_plan"],
        "tags": ["planning", "policy", "governance"],
    },
    "PM": {
        "category": "program_security",
        "applies_to": ["program_management", "governance", "risk_management"],
        "tags": ["program-management", "governance", "risk"],
    },
    "PS": {
        "category": "personnel_security",
        "applies_to": ["personnel_security", "screening", "role_change_controls"],
        "tags": ["personnel", "screening", "access-lifecycle"],
    },
    "PT": {
        "category": "privacy_security",
        "applies_to": ["privacy", "pii_protection", "data_processing"],
        "tags": ["privacy", "pii", "transparency"],
    },
    "RA": {
        "category": "risk_security",
        "applies_to": ["risk_assessment", "threat_analysis", "vulnerability_management"],
        "tags": ["risk", "assessment", "vulnerabilities"],
    },
    "SA": {
        "category": "secure_development",
        "applies_to": ["secure_sdlc", "developer_testing", "supply_chain_security", "application_security"],
        "tags": ["secure-development", "sdlc", "developer-testing"],
    },
    "SC": {
        "category": "network_security",
        "applies_to": ["network_security", "boundary_protection", "data_in_transit"],
        "tags": ["network", "boundary", "communications-security"],
    },
    "SI": {
        "category": "system_integrity",
        "applies_to": ["vulnerability_management", "flaw_remediation", "malware_protection", "integrity_monitoring"],
        "tags": ["integrity", "flaw-remediation", "malware-protection"],
    },
    "SR": {
        "category": "supply_chain_security",
        "applies_to": ["software_supply_chain", "vendor_risk", "component_integrity"],
        "tags": ["supply-chain", "vendor-risk", "component-integrity"],
    },
}


def _normalize_id(value: str) -> str:
    return (
        value.lower()
        .replace("(", "_")
        .replace(")", "")
        .replace("-", "_")
        .replace(" ", "_")
    )


def _build_doc_id(section: ExtractedSection) -> str:
    meta = section.metadata or {}

    if meta.get("enhancement_id"):
        return f"nist-800-53-{_normalize_id(str(meta['enhancement_id']))}"
    if meta.get("control_id"):
        return f"nist-800-53-{_normalize_id(str(meta['control_id']))}"
    if meta.get("family_id"):
        return f"nist-800-53-{str(meta['family_id']).lower()}"
    if section.section_id:
        return f"nist-800-53-{_normalize_id(section.section_id)}"
    return "nist-800-53-baseline"


def _build_title(section: ExtractedSection) -> str:
    meta = section.metadata or {}

    if meta.get("enhancement_id") and meta.get("enhancement_title"):
        return f"{meta['enhancement_id']} {meta['enhancement_title']}"
    if meta.get("control_id") and meta.get("control_title"):
        return f"{meta['control_id']} {meta['control_title']}"
    if meta.get("family_id") and meta.get("family_title"):
        return f"{meta['family_id']} {meta['family_title']}"
    return section.title


def _family_mapping(section: ExtractedSection) -> dict:
    meta = section.metadata or {}
    family_id = str(meta.get("family_id") or "").upper()
    return NIST_800_53_FAMILY_MAPPINGS.get(
        family_id,
        {
            "category": section.category or "nist_control_family",
            "applies_to": ["governance", "secure_configuration", "vulnerability_management"],
            "tags": ["nist", "800-53"],
        },
    )


def _build_compliance_ref(section: ExtractedSection) -> ComplianceReference:
    meta = section.metadata or {}

    if meta.get("enhancement_id"):
        control = str(meta["enhancement_id"])
    elif meta.get("control_id"):
        control = str(meta["control_id"])
    elif meta.get("family_id"):
        control = str(meta["family_id"])
    else:
        control = "General Guidance"

    return ComplianceReference(
        framework="NIST SP 800-53 Rev. 5",
        control=control,
    )


def _derive_severity_guidance(section: ExtractedSection) -> str:
    meta = section.metadata or {}
    family_id = str(meta.get("family_id") or "").upper()

    if family_id in {"AC", "IA", "SC", "SI", "SR"}:
        return "high"
    if family_id in {"CM", "RA", "SA", "AU", "CA"}:
        return "medium"
    return "medium"


def map_nist_800_53_section(section: ExtractedSection) -> KnowledgeDocument:
    mapping = _family_mapping(section)
    meta = section.metadata or {}

    tags = sorted(
        set(
            list(section.tags)
            + list(mapping.get("tags", []))
            + ["nist", "800-53"]
        )
    )

    description = section.body[:4000].strip()
    rationale = section.body[:4000].strip()
    developer_guidance = section.body[:4000].strip()

    if meta.get("level") == "family":
        developer_guidance = (
            f"{_build_title(section)} defines a control family in NIST SP 800-53 Rev. 5. "
            f"Use this family as high-level guidance for related findings and control mapping.\n\n"
            f"{developer_guidance}"
        )
    elif meta.get("level") == "control":
        developer_guidance = (
            f"{_build_title(section)} is a control-level requirement in NIST SP 800-53 Rev. 5. "
            f"Map findings to this control when the issue reflects its technical or procedural requirement.\n\n"
            f"{developer_guidance}"
        )
    elif meta.get("level") == "enhancement":
        developer_guidance = (
            f"{_build_title(section)} is a control enhancement in NIST SP 800-53 Rev. 5. "
            f"Use it for more specific or strengthened expectations under the parent control.\n\n"
            f"{developer_guidance}"
        )

    return KnowledgeDocument(
        id=_build_doc_id(section),
        title=_build_title(section),
        category=mapping.get("category", section.category or "nist_control_family"),
        applies_to=mapping.get("applies_to", ["governance"]),
        tags=tags,
        severity_guidance=_derive_severity_guidance(section),
        description=description,
        rationale=rationale,
        developer_guidance=developer_guidance,
        compliance_refs=[_build_compliance_ref(section)],
        source_path=section.source_file,
        source_type="nist_800_53",
    )