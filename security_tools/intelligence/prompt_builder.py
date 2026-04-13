from __future__ import annotations

from security_tools.intelligence.models import IntelligenceContext, KnowledgeDocument


def build_structured_guidance_input(
    context: IntelligenceContext,
    docs: list[KnowledgeDocument],
    baseline_rationale: str | None = None,
    baseline_fix: str | None = None,
) -> dict:
    return {
        "finding": {
            "finding_type": context.finding_type,
            "title": context.title,
            "severity": context.severity,
            "category": context.category,
            "rule_id": context.rule_id,
            "location": context.location,
        },
        "repo_context": {
            "service_type": context.service_type,
            "languages": context.languages,
            "frameworks": context.frameworks,
            "deploy_targets": context.deploy_targets,
            "runtime_profile": context.runtime_profile,
            "runtime_contract_present": context.runtime_contract_present,
        },
        "baseline_recommendation": {
            "rationale": baseline_rationale or "",
            "suggested_fix": baseline_fix or "",
        },
        "knowledge": [
            {
                "id": doc.id,
                "title": doc.title,
                "category": doc.category,
                "description": doc.description,
                "rationale": doc.rationale,
                "developer_guidance": doc.developer_guidance,
                "recommended_patterns": doc.recommended_patterns,
                "compliance_refs": [
                    f"{ref.framework} {ref.control}" + (f" ({ref.note})" if ref.note else "")
                    for ref in doc.compliance_refs
                ],
                "ownership": doc.ownership,
                "remediation": doc.remediation,
            }
            for doc in docs
        ],
    }