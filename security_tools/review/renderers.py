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

    ordered = ["critical", "high", "medium", "low", "info", "unknown"]

    lines.append("### Severity Dashboard")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")

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


def _truncate_text(value: str, limit: int = 600) -> str:
    text = value.strip()
    if len(text) <= limit:
        return text
    trimmed = text[:limit].rstrip()
    if " " in trimmed:
        trimmed = trimmed.rsplit(" ", 1)[0]
    return f"{trimmed}..."


def _clean_rationale(text: str) -> str:
    cleaned = text.strip()

    banned_fragments = [
        "This recommendation was generated in mock mode",
        "Mock mode enabled; no external model was called.",
        "Generated using internal security intelligence knowledge base.",
        "No external AI or third-party model services were used.",
        "Recommendations derived from curated compliance and security guidance.",
    ]

    for fragment in banned_fragments:
        cleaned = cleaned.replace(fragment, "").strip()

    cleaned = cleaned.replace("\n\n\n", "\n\n").strip()
    return cleaned


def _extract_guidance_sections(
    rationale: str,
) -> tuple[str, str | None, str | None]:
    base = rationale
    developer_guidance = None
    ownership_guidance = None

    dev_marker = "Developer Guidance:"
    owner_marker = "Ownership Guidance:"

    if dev_marker in base:
        prefix, suffix = base.split(dev_marker, 1)
        base = prefix.strip()

        if owner_marker in suffix:
            dev_text, owner_text = suffix.split(owner_marker, 1)
            developer_guidance = dev_text.strip()
            ownership_guidance = owner_text.strip()
        else:
            developer_guidance = suffix.strip()

    elif owner_marker in base:
        prefix, owner_text = base.split(owner_marker, 1)
        base = prefix.strip()
        ownership_guidance = owner_text.strip()

    return base.strip(), developer_guidance, ownership_guidance


def _render_preliminary_note() -> list[str]:
    return [
        "> **Preliminary Security Recommendation**",
        "> This automated review summarizes likely security concerns and recommended next actions",
        "> based on scan findings, runtime context, and internal security guidance.",
        "> Final disposition remains subject to human security review.",
        "",
    ]


def _render_recommendation_summary_table(
    recommendations: list[ReviewRecommendation | dict[str, Any]],
    max_items: int = 10,
) -> list[str]:
    lines: list[str] = []

    if not recommendations:
        return lines

    lines.append("### Action Summary")
    lines.append("")
    lines.append("| Severity | Recommendation | Location |")
    lines.append("|----------|----------------|----------|")

    for rec in recommendations[:max_items]:
        item = _normalize_recommendation(rec)
        severity = str(item.get("severity", "unknown")).upper()
        title = str(item.get("title", "Untitled recommendation")).strip()
        location = str(item.get("location") or "-").strip() or "-"
        lines.append(f"| {severity} | {title} | `{location}` |")

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

    lines.extend(_render_preliminary_note())

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
    lines.extend(_render_recommendation_summary_table(recommendations))

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

    lines.append("### Detailed Security Recommendations")
    lines.append("")

    if not recommendations:
        lines.append("- No actionable recommendations generated.")
        lines.append("")
        lines.append(
            "_Full security findings remain available in GitLab security results and pipeline artifacts._"
        )
        return "\n".join(lines)

    for rec in recommendations:
        item = _normalize_recommendation(rec)

        severity = str(item.get("severity", "unknown")).upper()
        title = str(item.get("title", "Untitled recommendation")).strip()
        location = str(item.get("location") or "").strip()

        raw_rationale = str(item.get("rationale") or "").strip()
        cleaned_rationale = _clean_rationale(raw_rationale)
        base_rationale, developer_guidance, ownership_guidance = _extract_guidance_sections(
            cleaned_rationale
        )

        suggested_fix = str(item.get("suggested_fix") or "").strip()

        compliance_refs = list(
            dict.fromkeys(str(x) for x in (item.get("compliance_refs") or []))
        )
        compliance_refs = [
            ref
            for ref in compliance_refs
            if "mock mode" not in ref.lower()
        ]

        summary_bits = [f"**{severity}**"]
        if location:
            summary_bits.append(f"`{location}`")
        summary_bits.append(title)

        lines.append("<details>")
        lines.append(f"<summary>{' | '.join(summary_bits)}</summary>")
        lines.append("")

        if location:
            lines.append(f"**Location**: `{location}`")
            lines.append("")

        if base_rationale:
            lines.append("**Security Rationale**")
            lines.append(_truncate_text(base_rationale, limit=700))
            lines.append("")

        if suggested_fix:
            lines.append("**Recommended Remediation**")
            lines.append(_truncate_text(suggested_fix, limit=700))
            lines.append("")

        if developer_guidance:
            lines.append("**Developer Guidance**")
            lines.append(_truncate_text(developer_guidance, limit=500))
            lines.append("")

        lines.append("**Ownership**")
        if ownership_guidance:
            lines.append(f"- {ownership_guidance}")
        else:
            lines.append("- Responsible Team: _Application / Platform / Security (TBD)_")
        lines.append("")

        lines.append("**Tracking**")
        lines.append("- Jira Ticket: _SEC-XXXX (if opened for investigation / triage)_")
        lines.append("")

        if compliance_refs:
            lines.append("**Compliance References**")
            lines.append(", ".join(compliance_refs[:6]))
            lines.append("")

        lines.append("</details>")
        lines.append("")

    if len(recommendations) > 10:
        lines.append(
            f"_Additional recommendations beyond the first {len(recommendations)} entries may be available in generated review artifacts._"
        )
        lines.append("")
    else:
        lines.append(
            "_Full supporting scan details remain available in GitLab security results and pipeline artifacts._"
        )
        lines.append("")

    return "\n".join(lines)