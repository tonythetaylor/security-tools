from __future__ import annotations

from security_tools.intelligence.models import IntelligenceContext, KnowledgeDocument


class KnowledgeRetriever:
    def __init__(self, documents: list[KnowledgeDocument]) -> None:
        self.documents = documents

    def _score_document(self, doc: KnowledgeDocument, context: IntelligenceContext) -> int:
        score = 0

        search_terms = {
            context.finding_type.lower(),
            (context.category or "").lower(),
            (context.rule_id or "").lower(),
            (context.service_type or "").lower(),
            (context.runtime_profile or "").lower(),
            *[x.lower() for x in context.languages],
            *[x.lower() for x in context.frameworks],
            *[x.lower() for x in context.deploy_targets],
        }

        doc_terms = {
            doc.id.lower(),
            doc.title.lower(),
            doc.category.lower(),
            *[x.lower() for x in doc.applies_to],
            *[x.lower() for x in doc.tags],
        }

        for term in search_terms:
            if not term:
                continue
            if term in doc_terms:
                score += 5
            if term in doc.description.lower():
                score += 2
            if term in doc.rationale.lower():
                score += 2
            if term in doc.developer_guidance.lower():
                score += 1

        return score

    def retrieve(self, context: IntelligenceContext, limit: int = 5) -> list[KnowledgeDocument]:
        scored: list[tuple[int, KnowledgeDocument]] = []

        for doc in self.documents:
            score = self._score_document(doc, context)
            if score > 0:
                scored.append((score, doc))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [doc for _, doc in scored[:limit]]