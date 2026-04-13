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
                "This recommendation was generated using internal curated security intelligence."
            ),
            suggested_fix=(
                "Review the matched knowledge documents, apply the recommended remediation, "
                "and align implementation with local policy, platform standards, and approved "
                "security hardening guidance."
            ),
            developer_guidance=(
                "Start with the smallest safe remediation that reduces risk without breaking "
                "deployment flow. Validate changes through CI and runtime verification."
            ),
            ownership_guidance=(
                "Typical owner: application_team unless overridden by platform policy or "
                "organizational security ownership requirements."
            ),
            compliance_notes=[
                "Generated using internal security intelligence knowledge base.",
                "No external AI or third-party model services were used.",
                "Recommendations derived from curated compliance and security guidance."
            ],
        )