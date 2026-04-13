from __future__ import annotations

from security_tools.intelligence.ingest.models import ExtractedSection
from security_tools.intelligence.models import ComplianceReference, KnowledgeDocument


def map_nist_800_53_section(section: ExtractedSection) -> KnowledgeDocument:
    return KnowledgeDocument(
        id="nist-800-53-baseline",
        title=section.title,
        category=section.category or "nist_control_family",
        applies_to=["governance", "secure_configuration", "vulnerability_management"],
        tags=sorted(set(section.tags + ["nist", "800-53"])),
        severity_guidance="medium",
        description=section.body[:4000],
        rationale=section.body[:4000],
        developer_guidance=section.body[:4000],
        compliance_refs=[
            ComplianceReference(
                framework="NIST SP 800-53 Rev. 5",
                control="General Guidance",
            )
        ],
        source_path=section.source_file,
        source_type="nist_800_53",
    )