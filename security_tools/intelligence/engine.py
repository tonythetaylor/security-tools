from __future__ import annotations

from security_tools.intelligence.knowledge_loader import load_knowledge_documents
from security_tools.intelligence.models import (
    IntelligenceContext,
    IntelligenceRecommendation,
    KnowledgeDocument,
)
from security_tools.intelligence.providers.base import BaseLLMProvider
from security_tools.intelligence.providers.noop import NoOpLLMProvider
from security_tools.intelligence.recommendation_engine import RecommendationEngine


class SecurityIntelligenceEngine:
    def __init__(
        self,
        knowledge_root: str | None = None,
        provider: BaseLLMProvider | None = None,
    ) -> None:
        self.documents: list[KnowledgeDocument] = load_knowledge_documents(knowledge_root)
        self.provider = provider or NoOpLLMProvider()
        self.recommendation_engine = RecommendationEngine(
            documents=self.documents,
            provider=self.provider,
        )

    def enrich(
        self,
        context: IntelligenceContext,
        baseline_title: str,
        baseline_severity: str,
        baseline_rationale: str,
        baseline_fix: str,
    ) -> IntelligenceRecommendation | None:
        return self.recommendation_engine.recommend(
            context=context,
            baseline_title=baseline_title,
            baseline_severity=baseline_severity,
            baseline_rationale=baseline_rationale,
            baseline_fix=baseline_fix,
        )

    def health(self) -> dict:
        return {
            "document_count": len(self.documents),
            "provider": self.provider.__class__.__name__,
        }