from __future__ import annotations

from collections import Counter
from typing import Any

from security_tools.loaders import load_finding_catalog, load_policy
from security_tools.models import (
    EnrichedFinding,
    NormalizedFinding,
    ReviewContext,
    ReviewRecommendation,
    ReviewResult,
)
from security_tools.review.dedup import deduplicate_findings
from security_tools.review.heuristics import build_heuristic_findings
from security_tools.review.renderers import render_mr_comment
from security_tools.review.severity import severity_to_risk_score


class SecurityReviewer:
    def __init__(
        self,
        catalog: dict[str, Any] | None = None,
        policy: dict[str, Any] | None = None,
    ) -> None:
        self.catalog = catalog or load_finding_catalog()
        self.policy = policy or load_policy()

    def _catalog_default(self) -> dict[str, Any]:
        value = self.catalog.get("default", {})
        return value if isinstance(value, dict) else {}

    def _catalog_findings(self) -> dict[str, Any]:
        value = self.catalog.get("findings", {})
        return value if isinstance(value, dict) else {}

    def _catalog_rules(self) -> dict[str, Any]:
        value = self.catalog.get("rules", {})
        return value if isinstance(value, dict) else {}

    def _policy_required_scans(self) -> dict[str, list[str]]:
        value = self.policy.get("required_scans", {})
        return value if isinstance(value, dict) else {}

    def _policy_verdict_rules(self) -> dict[str, Any]:
        value = self.policy.get("verdict_rules", {})
        return value if isinstance(value, dict) else {}

    def _policy_risk_rules(self) -> dict[str, Any]:
        value = self.policy.get("risk", {})
        return value if isinstance(value, dict) else {}

    def _lookup_catalog_item(self, finding: NormalizedFinding) -> dict[str, Any]:
        rules = self._catalog_rules()
        findings = self._catalog_findings()
        default = self._catalog_default()

        if finding.rule_id and finding.rule_id in rules:
            item = rules[finding.rule_id]
            return item if isinstance(item, dict) else default

        if finding.finding_type in findings:
            item = findings[finding.finding_type]
            return item if isinstance(item, dict) else default

        return default

    def _resolve_required_scans(self, context: ReviewContext) -> list[str]:
        required = self._policy_required_scans()

        if context.merge_request_iid is not None:
            return list(required.get("merge_request", []))

        if context.branch in {"main", "master"}:
            return list(required.get("default_branch", []))

        return list(required.get("default_branch", []))

    def enrich_finding(self, finding: NormalizedFinding) -> EnrichedFinding:
        catalog_item = self._lookup_catalog_item(finding)

        severity = (
            finding.severity
            if finding.severity != "unknown"
            else catalog_item.get("default_severity", "unknown")
        )

        return EnrichedFinding(
            tool=finding.tool,
            finding_type=finding.finding_type,
            rule_id=finding.rule_id,
            category=finding.category,
            severity=severity,
            title=str(catalog_item.get("title") or finding.title),
            description=finding.description,
            location=finding.location,
            rationale=str(
                catalog_item.get("rationale")
                or "This finding requires security review."
            ),
            suggested_fix=str(
                catalog_item.get("suggested_fix")
                or "Review the issue and apply the appropriate remediation."
            ),
            compliance_refs=list(catalog_item.get("compliance_refs", [])),
            metadata=finding.metadata,
            raw_payload=finding.raw_payload,
        )

    def _calculate_risk_score(self, findings: list[EnrichedFinding]) -> int:
        return sum(severity_to_risk_score(f.severity) for f in findings)

    def _compute_verdict(
        self,
        findings: list[EnrichedFinding],
        missing_scans: list[str],
        operational_warnings: list[str],
        risk_score: int,
    ) -> str:
        verdict_rules = self._policy_verdict_rules()
        risk_rules = self._policy_risk_rules()

        if operational_warnings and verdict_rules.get("operational_error_on_warnings", True):
            return "OPERATIONAL_ERROR"

        if missing_scans and verdict_rules.get("block_if_missing_scans", True):
            return "BLOCK"

        always_block_categories = set(verdict_rules.get("always_block_categories", []))
        always_block_finding_types = set(verdict_rules.get("always_block_finding_types", []))
        block_on_severities = set(verdict_rules.get("block_on_severities", ["critical", "high"]))
        warn_on_severities = set(verdict_rules.get("warn_on_severities", ["medium"]))

        for finding in findings:
            if finding.category and finding.category in always_block_categories:
                return "BLOCK"
            if finding.finding_type in always_block_finding_types:
                return "BLOCK"

        severities = Counter(f.severity for f in findings)

        if any(severities.get(sev, 0) > 0 for sev in block_on_severities):
            return "BLOCK"

        if risk_rules.get("enabled", False):
            if risk_score >= int(risk_rules.get("block_if_score_gte", 999999)):
                return "BLOCK"
            if risk_score >= int(risk_rules.get("warn_if_score_gte", 999999)):
                return "WARN"

        if any(severities.get(sev, 0) > 0 for sev in warn_on_severities):
            return "WARN"

        return "PASS"

    def _to_recommendations(
        self, findings: list[EnrichedFinding]
    ) -> list[ReviewRecommendation]:
        recommendations: list[ReviewRecommendation] = []
        seen: set[tuple[str, str | None, str]] = set()

        for finding in findings:
            location_str = None
            if finding.location.path:
                location_str = finding.location.path
                if finding.location.line:
                    location_str = f"{location_str}:{finding.location.line}"

            key = (finding.title, location_str, finding.severity)
            if key in seen:
                continue
            seen.add(key)

            recommendations.append(
                ReviewRecommendation(
                    title=finding.title,
                    severity=finding.severity,
                    rationale=finding.rationale,
                    suggested_fix=finding.suggested_fix,
                    compliance_refs=finding.compliance_refs,
                    location=location_str,
                )
            )

        return recommendations

    def review(self, context: ReviewContext) -> ReviewResult:
        operational_warnings: list[str] = []

        required_scans = self._resolve_required_scans(context)
        missing_scans = sorted(set(required_scans) - set(context.detected_scans))

        all_findings = list(context.findings)
        all_findings.extend(
            build_heuristic_findings(
                gitlab_ci_content=context.gitlab_ci_content,
                dockerfile_content=context.dockerfile_content,
            )
        )

        enriched = [self.enrich_finding(finding) for finding in all_findings]
        enriched = deduplicate_findings(enriched)

        risk_score = self._calculate_risk_score(enriched)
        recommendations = self._to_recommendations(enriched)

        verdict = self._compute_verdict(
            findings=enriched,
            missing_scans=missing_scans,
            operational_warnings=operational_warnings,
            risk_score=risk_score,
        )

        summary = (
            f"Pipeline-native security review completed. "
            f"Detected {len(context.detected_scans)} scans, generated "
            f"{len(recommendations)} recommendations, and calculated "
            f"a risk score of {risk_score}."
        )

        mr_comment = render_mr_comment(
            verdict=verdict,
            summary=summary,
            recommendations=recommendations,
            detected_scans=context.detected_scans,
            missing_scans=missing_scans,
            operational_warnings=operational_warnings,
        )

        return ReviewResult(
            verdict=verdict,  # type: ignore[arg-type]
            summary=summary,
            recommendations=recommendations,
            mr_comment=mr_comment,
            detected_scans=context.detected_scans,
            missing_expected_scans=missing_scans,
            operational_warnings=operational_warnings,
            risk_score=risk_score,
        )