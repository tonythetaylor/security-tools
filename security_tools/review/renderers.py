from __future__ import annotations

from security_tools.models import ReviewRecommendation


def render_mr_comment(
    verdict: str,
    summary: str,
    recommendations: list[ReviewRecommendation],
    detected_scans: list[str],
    missing_scans: list[str],
    operational_warnings: list[str],
) -> str:
    lines = [
        "## Security Review Summary",
        "",
        f"- **Verdict:** {verdict}",
        f"- **Detected scans:** {', '.join(detected_scans) if detected_scans else 'none'}",
        f"- **Missing expected scans:** {', '.join(missing_scans) if missing_scans else 'none'}",
    ]

    if operational_warnings:
        lines.append(f"- **Operational warnings:** {'; '.join(operational_warnings)}")

    lines.extend(["", summary, "", "### Recommendations"])

    if not recommendations:
        lines.append("- No actionable recommendations generated.")
    else:
        for rec in recommendations:
            lines.append(f"- **{rec.severity.upper()}** {rec.title}")
            if rec.location:
                lines.append(f"  - Location: {rec.location}")
            lines.append(f"  - Rationale: {rec.rationale}")
            lines.append(f"  - Suggested fix: {rec.suggested_fix}")
            if rec.compliance_refs:
                lines.append(f"  - Compliance: {', '.join(rec.compliance_refs)}")

    return "\n".join(lines)