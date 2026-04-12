from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low", "info", "unknown"]
Verdict = Literal["PASS", "WARN", "BLOCK", "OPERATIONAL_ERROR"]


class FindingLocation(BaseModel):
    path: str | None = None
    line: int | None = None
    column: int | None = None


class NormalizedFinding(BaseModel):
    tool: str
    finding_type: str
    rule_id: str | None = None
    category: str | None = None
    severity: Severity = "unknown"
    title: str
    description: str | None = None
    location: FindingLocation = Field(default_factory=FindingLocation)
    metadata: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class EnrichedFinding(BaseModel):
    tool: str
    finding_type: str
    rule_id: str | None = None
    category: str | None = None
    severity: Severity = "unknown"
    title: str
    description: str | None = None
    location: FindingLocation = Field(default_factory=FindingLocation)

    rationale: str
    suggested_fix: str
    compliance_refs: list[str] = Field(default_factory=list)

    metadata: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class ReviewRecommendation(BaseModel):
    title: str
    severity: Severity
    rationale: str
    suggested_fix: str
    compliance_refs: list[str] = Field(default_factory=list)
    location: str | None = None


class ReviewResult(BaseModel):
    verdict: Verdict
    summary: str
    recommendations: list[ReviewRecommendation] = Field(default_factory=list)
    mr_comment: str
    detected_scans: list[str] = Field(default_factory=list)
    missing_expected_scans: list[str] = Field(default_factory=list)
    operational_warnings: list[str] = Field(default_factory=list)
    risk_score: int = 0


class ReviewContext(BaseModel):
    project_id: int
    branch: str | None = None
    merge_request_iid: int | None = None

    findings: list[NormalizedFinding] = Field(default_factory=list)
    detected_scans: list[str] = Field(default_factory=list)

    gitlab_ci_content: str | None = None
    dockerfile_content: str | None = None
    dockerignore_content: str | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)