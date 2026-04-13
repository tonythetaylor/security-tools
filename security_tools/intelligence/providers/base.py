from __future__ import annotations

from abc import ABC, abstractmethod

from security_tools.intelligence.models import IntelligenceContext, LLMRecommendation


class BaseLLMProvider(ABC):
    @abstractmethod
    def generate_recommendation(
        self,
        prompt: dict,
        context: IntelligenceContext,
    ) -> LLMRecommendation | None:
        raise NotImplementedError