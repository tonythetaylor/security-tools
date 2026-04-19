from __future__ import annotations

from security_tools.intelligence.ingest.models import ExtractedSection
from security_tools.intelligence.models import ComplianceReference, KnowledgeDocument


GROUP_MAPPINGS: dict[str, dict] = {
    "PO": {
        "category": "secure_development_governance",
        "applies_to": [
            "secure_sdlc",
            "security_requirements",
            "developer_enablement",
            "build_pipeline",
            "development_environment",
        ],
        "tags": ["prepare-the-organization", "governance", "toolchain", "development-environment"],
        "severity_guidance": "medium",
    },
    "PS": {
        "category": "software_integrity_security",
        "applies_to": [
            "code_integrity",
            "artifact_integrity",
            "sbom",
            "release_integrity",
            "provenance",
        ],
        "tags": ["protect-software", "integrity", "signing", "provenance"],
        "severity_guidance": "high",
    },
    "PW": {
        "category": "secure_development",
        "applies_to": [
            "secure_sdlc",
            "secure_coding",
            "sast",
            "dependency_scanning",
            "build_security",
            "code_review",
            "testing",
        ],
        "tags": ["produce-well-secured-software", "secure-coding", "code-review", "testing"],
        "severity_guidance": "high",
    },
    "RV": {
        "category": "vulnerability_response",
        "applies_to": [
            "vulnerability_management",
            "triage",
            "remediation",
            "root_cause_analysis",
            "security_advisories",
        ],
        "tags": ["respond-to-vulnerabilities", "triage", "remediation", "psirt"],
        "severity_guidance": "high",
    },
}


TASK_CATEGORY_OVERRIDES: dict[str, dict] = {
    "PO.3": {
        "category": "build_security",
        "applies_to": ["build_pipeline", "toolchain_security", "pipeline_integrity"],
        "tags": ["toolchain", "pipeline", "automation"],
    },
    "PO.5": {
        "category": "development_environment_security",
        "applies_to": ["development_environment", "build_environment", "access_control", "hardening"],
        "tags": ["development-environment", "hardening", "segmentation"],
    },
    "PS.2": {
        "category": "release_integrity_security",
        "applies_to": ["artifact_integrity", "code_signing", "release_validation"],
        "tags": ["integrity", "release", "verification"],
    },
    "PS.3": {
        "category": "provenance_security",
        "applies_to": ["sbom", "provenance", "artifact_retention", "software_inventory"],
        "tags": ["sbom", "provenance", "inventory"],
    },
    "PW.4": {
        "category": "supply_chain_security",
        "applies_to": ["dependency_scanning", "software_supply_chain", "component_integrity"],
        "tags": ["third-party-components", "dependencies", "supply-chain"],
    },
    "PW.5": {
        "category": "secure_coding_security",
        "applies_to": ["secure_coding", "application_security", "input_validation", "error_handling"],
        "tags": ["secure-coding", "coding-practices", "linters"],
    },
    "PW.6": {
        "category": "build_security",
        "applies_to": ["build_pipeline", "compiler_hardening", "reproducible_builds"],
        "tags": ["compiler", "build", "hardening"],
    },
    "PW.7": {
        "category": "code_review_security",
        "applies_to": ["sast", "code_review", "static_analysis", "review_workflow"],
        "tags": ["code-review", "static-analysis", "review"],
    },
    "PW.8": {
        "category": "security_testing",
        "applies_to": ["dast", "fuzzing", "dynamic_testing", "penetration_testing"],
        "tags": ["testing", "fuzzing", "dynamic-analysis"],
    },
    "PW.9": {
        "category": "secure_configuration",
        "applies_to": ["secure_defaults", "configuration_security", "hardening"],
        "tags": ["secure-defaults", "configuration", "hardening"],
    },
    "RV.1": {
        "category": "vulnerability_management",
        "applies_to": ["vulnerability_intake", "continuous_monitoring", "dependency_scanning"],
        "tags": ["vulnerability-management", "monitoring", "intake"],
    },
    "RV.2": {
        "category": "remediation_management",
        "applies_to": ["triage", "remediation", "advisories", "patch_management"],
        "tags": ["triage", "remediation", "patching"],
    },
    "RV.3": {
        "category": "root_cause_security",
        "applies_to": ["root_cause_analysis", "lessons_learned", "process_improvement"],
        "tags": ["root-cause", "lessons-learned", "feedback-loop"],
    },
}


def _normalize_id(value: str) -> str:
    return value.lower().replace(".", "_").replace("-", "_").replace(" ", "_")


def _build_doc_id(section: ExtractedSection) -> str:
    meta = section.metadata or {}
    if meta.get("task_id"):
        return f"nist-800-218-{_normalize_id(str(meta['task_id']))}"
    if meta.get("practice_id"):
        return f"nist-800-218-{_normalize_id(str(meta['practice_id']))}"
    if meta.get("group_code"):
        return f"nist-800-218-{str(meta['group_code']).lower()}"
    if section.section_id:
        return f"nist-800-218-{_normalize_id(section.section_id)}"
    return "nist-800-218-baseline"


def _build_title(section: ExtractedSection) -> str:
    meta = section.metadata or {}
    if meta.get("task_id") and meta.get("task_title"):
        return f"{meta['task_id']} {meta['task_title']}"
    if meta.get("practice_id") and meta.get("practice_title"):
        return f"{meta['practice_id']} {meta['practice_title']}"
    if meta.get("group_title"):
        return str(meta["group_title"])
    return section.title


def _mapping_for_section(section: ExtractedSection) -> dict:
    meta = section.metadata or {}
    group_code = str(meta.get("group_code") or "").upper()
    practice_id = str(meta.get("practice_id") or "").upper()

    mapping = dict(GROUP_MAPPINGS.get(group_code, {
        "category": section.category or "secure_development",
        "applies_to": ["secure_sdlc"],
        "tags": ["ssdf", "nist_800_218"],
        "severity_guidance": "medium",
    }))

    if practice_id in TASK_CATEGORY_OVERRIDES:
        override = TASK_CATEGORY_OVERRIDES[practice_id]
        mapping["category"] = override.get("category", mapping["category"])
        mapping["applies_to"] = override.get("applies_to", mapping["applies_to"])
        mapping["tags"] = list(set(mapping.get("tags", []) + override.get("tags", [])))

    return mapping


def _build_compliance_ref(section: ExtractedSection) -> ComplianceReference:
    meta = section.metadata or {}
    if meta.get("task_id"):
        control = str(meta["task_id"])
    elif meta.get("practice_id"):
        control = str(meta["practice_id"])
    elif meta.get("group_code"):
        control = str(meta["group_code"])
    else:
        control = "General Guidance"

    return ComplianceReference(
        framework="NIST SP 800-218 SSDF",
        control=control,
    )


def map_ssdf_section(section: ExtractedSection) -> KnowledgeDocument:
    mapping = _mapping_for_section(section)
    meta = section.metadata or {}

    tags = sorted(
        set(list(section.tags) + list(mapping.get("tags", [])) + ["ssdf", "nist_800_218"])
    )

    level = str(meta.get("level") or "baseline")
    title = _build_title(section)

    if level == "group":
        developer_guidance = (
            f"{title} defines one of the four high-level SSDF practice groups. "
            f"Use this record as strategic guidance for grouping findings and aligning SDLC expectations.\n\n"
            f"{section.body[:4000].strip()}"
        )
    elif level == "practice":
        developer_guidance = (
            f"{title} defines an SSDF practice. "
            f"Use it to align implementation, process, and review expectations for this part of the SDLC.\n\n"
            f"{section.body[:4000].strip()}"
        )
    elif level == "task":
        developer_guidance = (
            f"{title} defines an actionable SSDF task. "
            f"Use it when findings indicate a gap in development workflow, toolchain, review, testing, or vulnerability response.\n\n"
            f"{section.body[:4000].strip()}"
        )
    else:
        developer_guidance = section.body[:4000].strip()

    return KnowledgeDocument(
        id=_build_doc_id(section),
        title=title,
        category=mapping.get("category", section.category or "secure_development"),
        applies_to=mapping.get("applies_to", ["secure_sdlc"]),
        tags=tags,
        severity_guidance=mapping.get("severity_guidance", "medium"),
        description=section.body[:4000].strip(),
        rationale=section.body[:4000].strip(),
        developer_guidance=developer_guidance,
        compliance_refs=[_build_compliance_ref(section)],
        source_path=section.source_file,
        source_type="ssdf",
    )