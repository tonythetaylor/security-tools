from __future__ import annotations

from typing import Any

from security_tools.models import ReviewRecommendation


def _normalize_recommendation(
    rec: ReviewRecommendation | dict[str, Any],
) -> dict[str, Any]:
    if isinstance(rec, dict):
        return rec
    return rec.model_dump()


def render_mr_comment(
    verdict: str,
    summary: str,
    recommendations: list[ReviewRecommendation | dict[str, Any]],
    detected_scans: list[str],
    missing_scans: list[str],
    operational_warnings: list[str] | None = None,
    planning_context: dict[str, Any] | None = None,
    runtime_context: dict[str, Any] | None = None,
    risk_score: int | None = None,
    verdict_rationale: str | None = None,
) -> str:
    lines: list[str] = []

    lines.append("## Security Review Summary")
    lines.append("")
    lines.append(f"- **Verdict:** {verdict}")
    lines.append(
        f"- **Detected scans:** {', '.join(detected_scans) if detected_scans else 'none'}"
    )
    lines.append(
        f"- **Missing expected scans:** {', '.join(missing_scans) if missing_scans else 'none'}"
    )

    if risk_score is not None:
        lines.append(f"- **Risk score:** {risk_score}")

    if operational_warnings:
        lines.append(
            f"- **Operational warnings:** {'; '.join(operational_warnings)}"
        )

    lines.append("")
    lines.append(summary)
    lines.append("")

    if verdict_rationale:
        lines.append("### Why this verdict")
        lines.append(verdict_rationale)
        lines.append("")

    if planning_context:
        lines.append("### Dynamic Planning Context")

        detected_stack = planning_context.get("detected_stack")
        if detected_stack:
            if isinstance(detected_stack, list):
                lines.append(f"- **Detected stack:** {', '.join(str(x) for x in detected_stack)}")
            else:
                lines.append(f"- **Detected stack:** {detected_stack}")

        pipeline_mode = planning_context.get("pipeline_mode")
        if pipeline_mode:
            lines.append(f"- **Pipeline mode:** {pipeline_mode}")

        deploy_targets = planning_context.get("deploy_targets")
        if deploy_targets:
            if isinstance(deploy_targets, list):
                lines.append(f"- **Deploy targets:** {', '.join(str(x) for x in deploy_targets)}")
            else:
                lines.append(f"- **Deploy targets:** {deploy_targets}")

        runtime_contract_present = planning_context.get("runtime_contract_present")
        if runtime_contract_present is not None:
            lines.append(f"- **Runtime contract present:** {runtime_contract_present}")

        lines.append("")

    if runtime_context:
        lines.append("### Runtime Verification")
        for key, value in runtime_context.items():
            lines.append(f"- **{key}:** {value}")
        lines.append("")

    lines.append("### Recommendations")

    if not recommendations:
        lines.append("- No actionable recommendations generated.")
        return "\n".join(lines)

    for rec in recommendations:
        item = _normalize_recommendation(rec)

        severity = str(item.get("severity", "unknown")).upper()
        title = str(item.get("title", "Untitled recommendation"))
        lines.append(f"- **{severity}** {title}")

        location = item.get("location")
        if location:
            lines.append(f"  - Location: {location}")

        rationale = item.get("rationale")
        if rationale:
            lines.append(f"  - Rationale: {rationale}")

        suggested_fix = item.get("suggested_fix")
        if suggested_fix:
            lines.append(f"  - Suggested fix: {suggested_fix}")

        compliance_refs = item.get("compliance_refs") or []
        if compliance_refs:
            lines.append(f"  - Compliance: {', '.join(str(x) for x in compliance_refs)}")

    return "\n".join(lines)