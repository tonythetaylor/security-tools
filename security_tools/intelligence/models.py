from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info", "unknown"]


class ComplianceReference(BaseModel):
    framework: str
    control: str
    note: str | None = None


class KnowledgeDocument(BaseModel):
    id: str
    title: str
    category: str

    applies_to: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    severity_guidance: Severity = "unknown"

    description: str = ""
    rationale: str = ""
    developer_guidance: str = ""

    recommended_patterns: list[str] = Field(default_factory=list)
    bad_examples: list[str] = Field(default_factory=list)
    good_examples: list[str] = Field(default_factory=list)

    compliance_refs: list[ComplianceReference] = Field(default_factory=list)

    risk_context: dict[str, str] = Field(default_factory=dict)
    ownership: dict[str, Any] = Field(default_factory=dict)
    remediation: dict[str, Any] = Field(default_factory=dict)

    source_path: str | None = None
    source_type: str = "knowledge"


class IntelligenceContext(BaseModel):
    finding_type: str
    title: str
    severity: Severity = "unknown"

    category: str | None = None
    rule_id: str | None = None
    location: str | None = None

    service_type: str | None = None
    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    deploy_targets: list[str] = Field(default_factory=list)

    runtime_profile: str | None = None
    runtime_contract_present: bool = False

    metadata: dict[str, Any] = Field(default_factory=dict)


class IntelligenceRecommendation(BaseModel):
    title: str
    severity: Severity
    rationale: str
    suggested_fix: str
    compliance_refs: list[str] = Field(default_factory=list)
    developer_guidance: str | None = None
    ownership_guidance: str | None = None
    evidence_document_ids: list[str] = Field(default_factory=list)


class LLMRecommendation(BaseModel):
    rationale: str
    suggested_fix: str
    developer_guidance: str | None = None
    ownership_guidance: str | None = None
    compliance_notes: list[str] = Field(default_factory=list)