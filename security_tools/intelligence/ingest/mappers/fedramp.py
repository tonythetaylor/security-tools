from __future__ import annotations

from security_tools.intelligence.ingest.models import ExtractedSection
from security_tools.intelligence.models import ComplianceReference, KnowledgeDocument


def map_fedramp_section(section: ExtractedSection) -> KnowledgeDocument:
    return KnowledgeDocument(
        id="fedramp-baseline",
        title=section.title,
        category=section.category or "fedramp_guidance",
        applies_to=["authorization", "continuous_monitoring", "control_inheritance"],
        tags=sorted(set(section.tags + ["fedramp"])),
        severity_guidance="medium",
        description=section.body[:4000],
        rationale=section.body[:4000],
        developer_guidance=section.body[:4000],
        compliance_refs=[
            ComplianceReference(
                framework="FedRAMP",
                control="General Guidance",
            )
        ],
        source_path=section.source_file,
        source_type="fedramp",
    )