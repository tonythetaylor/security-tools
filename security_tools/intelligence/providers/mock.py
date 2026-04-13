from __future__ import annotations

from security_tools.intelligence.models import IntelligenceContext, LLMRecommendation
from security_tools.intelligence.providers.base import BaseLLMProvider


class MockLLMProvider(BaseLLMProvider):
    def generate_recommendation(
        self,
        prompt: dict,
        context: IntelligenceContext,
    ) -> LLMRecommendation | None:
        return LLMRecommendation(
            rationale=(
                f"Retrieved compliance-aware guidance for '{context.title}'. "
                "This recommendation was generated in mock mode using retrieved knowledge."
            ),
            suggested_fix=(
                "Review the matched knowledge documents, apply the recommended remediation, "
                "and align implementation with local policy and approved hardening guidance."
            ),
            developer_guidance=(
                "Start with the smallest safe remediation that reduces risk without breaking deployment flow."
            ),
            ownership_guidance="Typical owner: application_team unless overridden by platform policy.",
            compliance_notes=["Mock mode enabled; no external model was called."],
        )