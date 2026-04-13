from __future__ import annotations

from typing import Any

from security_tools.models import ReviewRecommendation


def _normalize_recommendation(
    rec: ReviewRecommendation | dict[str, Any],
) -> dict[str, Any]:
    if isinstance(rec, dict):
        return rec
    return rec.model_dump()


def _render_severity_table(
    severity_counts: dict[str, int] | None,
) -> list[str]:
    lines: list[str] = []

    if not severity_counts:
        return lines

    lines.append("### Severity Dashboard")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")

    ordered = ["critical", "high", "medium", "low", "info", "unknown"]
    for sev in ordered:
        count = severity_counts.get(sev, 0)
        if sev == "unknown" and count == 0:
            continue
        lines.append(f"| {sev.capitalize()} | {count} |")

    lines.append("")
    return lines


def _render_tool_table(
    tool_counts: dict[str, int] | None,
) -> list[str]:
    lines: list[str] = []

    if not tool_counts:
        return lines

    lines.append("### Tool Breakdown")
    lines.append("")
    lines.append("| Tool | Findings |")
    lines.append("|------|----------|")

    for tool, count in tool_counts.items():
        lines.append(f"| {tool} | {count} |")

    lines.append("")
    return lines


def _render_category_table(
    category_counts: dict[str, int] | None,
) -> list[str]:
    lines: list[str] = []

    if not category_counts:
        return lines

    lines.append("### Category Breakdown")
    lines.append("")
    lines.append("| Category | Findings |")
    lines.append("|----------|----------|")

    for category, count in category_counts.items():
        lines.append(f"| {category} | {count} |")

    lines.append("")
    return lines


def _render_scan_coverage(
    detected: list[str],
    missing: list[str],
) -> list[str]:
    lines: list[str] = []

    all_scans = sorted(set(detected + missing))
    if not all_scans:
        return lines

    lines.append("### Scan Coverage")
    lines.append("")
    lines.append("| Scan | Status |")
    lines.append("|------|--------|")

    for scan in all_scans:
        status = "✅ Present" if scan in detected else "⚠️ Missing"
        lines.append(f"| {scan} | {status} |")

    lines.append("")
    return lines


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
    severity_counts: dict[str, int] | None = None,
    tool_counts: dict[str, int] | None = None,
    category_counts: dict[str, int] | None = None,
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
        lines.append(f"- **Aggregate risk score:** {risk_score}")

    if operational_warnings:
        lines.append(
            f"- **Operational warnings:** {'; '.join(operational_warnings)}"
        )

    lines.append("")
    lines.append(summary)
    lines.append("")

    if verdict_rationale:
        lines.append("### Why this verdict")
        lines.append(str(verdict_rationale).strip())
        lines.append("")

    lines.extend(_render_severity_table(severity_counts))
    lines.extend(_render_tool_table(tool_counts))
    lines.extend(_render_category_table(category_counts))
    lines.extend(_render_scan_coverage(detected_scans, missing_scans))

    if planning_context:
        lines.append("### Dynamic Planning Context")

        detected_stack = planning_context.get("detected_stack")
        if detected_stack:
            if isinstance(detected_stack, list):
                lines.append(
                    f"- **Detected stack:** {', '.join(str(x) for x in detected_stack)}"
                )
            else:
                lines.append(f"- **Detected stack:** {detected_stack}")

        pipeline_mode = planning_context.get("pipeline_mode")
        if pipeline_mode:
            lines.append(f"- **Pipeline mode:** {pipeline_mode}")

        deploy_targets = planning_context.get("deploy_targets")
        if deploy_targets:
            if isinstance(deploy_targets, list):
                lines.append(
                    f"- **Deploy targets:** {', '.join(str(x) for x in deploy_targets)}"
                )
            else:
                lines.append(f"- **Deploy targets:** {deploy_targets}")

        runtime_contract_present = planning_context.get("runtime_contract_present")
        if runtime_contract_present is not None:
            lines.append(
                f"- **Runtime contract present:** {runtime_contract_present}"
            )

        lines.append("")

    if runtime_context:
        lines.append("### Runtime Verification")
        for key, value in runtime_context.items():
            lines.append(f"- **{key}:** {value}")
        lines.append("")

    lines.append("### Security Recommendations")

    if not recommendations:
        lines.append("- No actionable recommendations generated.")
        return "\n".join(lines)

    for rec in recommendations:
        item = _normalize_recommendation(rec)

        severity = str(item.get("severity", "unknown")).upper()
        title = str(item.get("title", "Untitled recommendation")).strip()

        lines.append("---")
        lines.append(f"#### {severity} — {title}")
        lines.append("")

        location = str(item.get("location") or "").strip()
        if location:
            lines.append(f"**Location**: `{location}`")
            lines.append("")

        rationale = str(item.get("rationale") or "").strip()
        if rationale:
            lines.append("**Security Rationale**")
            lines.append(rationale)
            lines.append("")

        suggested_fix = str(item.get("suggested_fix") or "").strip()
        if suggested_fix:
            lines.append("**Recommended Remediation**")
            lines.append(suggested_fix)
            lines.append("")

        compliance_refs = list(
            dict.fromkeys(str(x) for x in (item.get("compliance_refs") or []))
        )
        if compliance_refs:
            lines.append("**Compliance References**")
            lines.append(", ".join(compliance_refs))
            lines.append("")

        lines.append("**Ownership**")
        lines.append("- Responsible Team: _Application / Platform / Security (TBD)_")
        lines.append("")

        lines.append("**Tracking**")
        lines.append("- Jira Ticket: _SEC-XXXX (if opened for investigation / triage)_")
        lines.append("")

    return "\n".join(lines)