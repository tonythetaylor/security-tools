from __future__ import annotations

from security_tools.intelligence.models import IntelligenceContext, LLMRecommendation
from security_tools.intelligence.providers.base import BaseLLMProvider


class NoOpLLMProvider(BaseLLMProvider):
    def generate_recommendation(
        self,
        prompt: dict,
        context: IntelligenceContext,
    ) -> LLMRecommendation | None:
        return None