from __future__ import annotations

from security_tools.intelligence.models import (
    IntelligenceContext,
    IntelligenceRecommendation,
    KnowledgeDocument,
)
from security_tools.intelligence.prompt_builder import build_structured_guidance_input
from security_tools.intelligence.providers.base import BaseLLMProvider
from security_tools.intelligence.providers.noop import NoOpLLMProvider
from security_tools.intelligence.retriever import KnowledgeRetriever


class RecommendationEngine:
    def __init__(
        self,
        documents: list[KnowledgeDocument],
        provider: BaseLLMProvider | None = None,
    ) -> None:
        self.documents = documents
        self.retriever = KnowledgeRetriever(documents)
        self.provider = provider or NoOpLLMProvider()

    def recommend(
        self,
        context: IntelligenceContext,
        baseline_title: str,
        baseline_severity: str,
        baseline_rationale: str,
        baseline_fix: str,
    ) -> IntelligenceRecommendation | None:
        docs = self.retriever.retrieve(context, limit=5)
        if not docs:
            return None

        prompt = build_structured_guidance_input(
            context=context,
            docs=docs,
            baseline_rationale=baseline_rationale,
            baseline_fix=baseline_fix,
        )

        llm_result = self.provider.generate_recommendation(prompt, context)

        compliance_refs = []
        for doc in docs:
            for ref in doc.compliance_refs:
                rendered = f"{ref.framework} {ref.control}"
                if ref.note:
                    rendered = f"{rendered} ({ref.note})"
                compliance_refs.append(rendered)

        compliance_refs = list(dict.fromkeys(compliance_refs))

        rationale = baseline_rationale
        suggested_fix = baseline_fix
        developer_guidance = None
        ownership_guidance = None

        if llm_result:
            rationale = llm_result.rationale or rationale
            suggested_fix = llm_result.suggested_fix or suggested_fix
            developer_guidance = llm_result.developer_guidance
            ownership_guidance = llm_result.ownership_guidance
            compliance_refs = list(dict.fromkeys(compliance_refs + llm_result.compliance_notes))

        return IntelligenceRecommendation(
            title=baseline_title,
            severity=baseline_severity,  # type: ignore[arg-type]
            rationale=rationale,
            suggested_fix=suggested_fix,
            compliance_refs=compliance_refs,
            developer_guidance=developer_guidance,
            ownership_guidance=ownership_guidance,
            evidence_document_ids=[doc.id for doc in docs],
        )