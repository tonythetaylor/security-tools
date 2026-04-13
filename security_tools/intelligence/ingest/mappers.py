from __future__ import annotations

from security_tools.intelligence.ingest.models import ExtractedSection
from security_tools.intelligence.models import ComplianceReference, KnowledgeDocument


CIS_CONTROL_MAPPINGS: dict[str, dict] = {
    "01": {
        "category": "asset_security",
        "applies_to": [
            "asset_inventory",
            "asset_management",
            "unauthorized_assets",
        ],
        "tags": [
            "asset-inventory",
            "enterprise-assets",
            "visibility",
        ],
    },
    "02": {
        "category": "software_security",
        "applies_to": [
            "software_inventory",
            "software_asset_management",
            "unauthorized_software",
        ],
        "tags": [
            "software-inventory",
            "software-assets",
            "asset-management",
        ],
    },
    "03": {
        "category": "data_security",
        "applies_to": [
            "data_protection",
            "data_management",
            "data_recovery",
        ],
        "tags": [
            "data-protection",
            "recovery",
            "retention",
        ],
    },
    "04": {
        "category": "configuration_security",
        "applies_to": [
            "secure_configuration",
            "hardening",
            "baseline_configuration",
        ],
        "tags": [
            "hardening",
            "configuration",
            "baseline",
        ],
    },
    "07": {
        "category": "vulnerability_management",
        "applies_to": [
            "vulnerability_management",
            "container_scanning",
            "dependency_scan",
            "patch_management",
        ],
        "tags": [
            "vulnerabilities",
            "patching",
            "scanning",
        ],
    },
    "16": {
        "category": "application_security",
        "applies_to": [
            "sast",
            "secure_sdlc",
            "application_security",
            "dependency_scan",
            "third_party_components",
        ],
        "tags": [
            "appsec",
            "sast",
            "secure-development",
            "third-party-code",
        ],
    },
}


def map_section_to_knowledge_doc(section: ExtractedSection) -> KnowledgeDocument:
    section_id = (section.section_id or "").zfill(2)
    mapping = CIS_CONTROL_MAPPINGS.get(section_id, {})

    category = mapping.get("category", section.category or "general")
    applies_to = list(mapping.get("applies_to", []))
    tags = sorted(set(list(section.tags) + list(mapping.get("tags", []))))

    refs = []
    if section.framework.lower() == "cis" and section.section_id:
        refs.append(
            ComplianceReference(
                framework="CIS Controls v8",
                control=f"Control {section_id}",
            )
        )

    safe_id = f"{section.framework}-{section_id or section.title.lower().replace(' ', '-')}"

    return KnowledgeDocument(
        id=safe_id,
        title=section.title,
        category=category,
        applies_to=applies_to,
        tags=tags,
        severity_guidance="medium",
        description=section.body[:2000],
        rationale=section.body[:2000],
        developer_guidance=section.body[:2000],
        compliance_refs=refs,
        source_path=section.source_file,
        source_type=section.framework,
    )