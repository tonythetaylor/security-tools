from __future__ import annotations

from typing import Any

from security_tools.models import ReviewRecommendation


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
SEVERITY_LABELS = {
    "critical": "🔴 Critical",
    "high": "🟠 High",
    "medium": "🟡 Medium",
    "low": "🟢 Low",
    "info": "🔵 Info",
    "unknown": "⚪ Unknown",
}
VERDICT_LABELS = {
    "PASS": "✅ PASS",
    "WARN": "⚠️ WARN",
    "BLOCK": "❌ BLOCK",
    "OPERATIONAL_ERROR": "❌ OPERATIONAL ERROR",
    "UNKNOWN": "UNKNOWN",
}
READINESS_BY_VERDICT = {
    "PASS": "✅ READY",
    "WARN": "❌ REMEDIATION REQUIRED",
    "BLOCK": "❌ NOT APPROVED",
    "OPERATIONAL_ERROR": "❌ UNDETERMINED",
    "UNKNOWN": "UNDETERMINED",
}
PRIORITY_LABELS = {
    "critical": "🔴 Critical",
    "high": "🟠 High",
    "medium": "🟡 Medium",
    "low": "🟢 Low",
    "info": "🔵 Info",
    "unknown": "⚪ Unknown",
}


def _normalize_recommendation(
    rec: ReviewRecommendation | dict[str, Any],
) -> dict[str, Any]:
    if isinstance(rec, dict):
        return rec
    return rec.model_dump()


def _normalize_bool_text(value: Any) -> str:
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


def _titleize_slug(value: str) -> str:
    return value.replace("_", " ").strip().title()


def _format_area_name(category: str) -> str:
    if not category:
        return "Uncategorized"
    mapping = {
        "dockerfile_scanning": "Container Build Configuration",
        "container_scanning": "Container Security",
        "dependency_scanning": "Dependency Security",
        "secret_detection": "Secret Detection",
        "iac_scanning": "Infrastructure as Code",
        "sast": "Static Application Security Testing",
        "runtime_verification": "Runtime Verification",
    }
    return mapping.get(category, _titleize_slug(category))


def _truncate_text(value: str, limit: int = 700) -> str:
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
    ]

    for fragment in banned_fragments:
        cleaned = cleaned.replace(fragment, "").strip()

    while "\n\n\n" in cleaned:
        cleaned = cleaned.replace("\n\n\n", "\n\n")

    return cleaned.strip()


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


def _extract_declared_owner(ownership_guidance: str | None) -> str:
    if not ownership_guidance:
        return "Application Team"

    text = ownership_guidance.strip()
    lowered = text.lower()

    if "typical owner:" in lowered:
        raw = text.split(":", 1)[1].strip()
        raw = raw.split("unless", 1)[0].strip()
        raw = raw.split(".", 1)[0].strip()
        if raw:
            return raw.replace("_", " ").title()

    if "application_team" in lowered or "application team" in lowered:
        return "Application Team"
    if "security_team" in lowered or "security team" in lowered:
        return "Security Team"
    if "platform_team" in lowered or "platform team" in lowered:
        return "Platform Team"

    return "Application Team"


def _render_intro() -> list[str]:
    return [
        "> Consolidated security assessment based on static analysis, dependency scanning,",
        "> container evaluation, IaC inspection, and runtime verification.",
        "> This output provides engineering-focused risk context and does not replace formal security review.",
        "",
    ]


def _render_decision_table(
    verdict: str,
    runtime_context: dict[str, Any] | None,
    risk_score: int | None,
    severity_counts: dict[str, int] | None,
) -> list[str]:
    lines: list[str] = []

    runtime_verdict = str((runtime_context or {}).get("Verdict", "UNKNOWN")).upper()
    verdict_label = VERDICT_LABELS.get(verdict.upper(), verdict.upper())
    runtime_label = VERDICT_LABELS.get(runtime_verdict, runtime_verdict)

    medium_count = (severity_counts or {}).get("medium", 0)
    high_count = (severity_counts or {}).get("high", 0)
    critical_count = (severity_counts or {}).get("critical", 0)

    if critical_count > 0:
        findings_summary = f"{critical_count} Critical"
    elif high_count > 0:
        findings_summary = f"{high_count} High"
    elif medium_count > 0:
        findings_summary = f"{medium_count} Medium"
    else:
        findings_summary = "No Significant Findings"

    production_readiness = READINESS_BY_VERDICT.get(verdict.upper(), "UNDETERMINED")

    lines.append("## Security Review")
    lines.append("")
    lines.extend(_render_intro())

    lines.append("### Decision")
    lines.append("")
    lines.append("| Status | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| **Security Verdict** | {verdict_label} |")
    lines.append(f"| **Runtime Health** | {runtime_label} |")
    lines.append(f"| **Risk Score** | {risk_score if risk_score is not None else 'N/A'} |")
    lines.append(f"| **Findings** | {findings_summary} |")
    lines.append(f"| **Production Readiness** | {production_readiness} |")
    lines.append("")

    return lines


def _render_interpretation(
    verdict: str,
    runtime_context: dict[str, Any] | None,
    severity_counts: dict[str, int] | None,
) -> list[str]:
    lines: list[str] = []

    runtime_verdict = str((runtime_context or {}).get("Verdict", "")).upper()
    critical = (severity_counts or {}).get("critical", 0)
    high = (severity_counts or {}).get("high", 0)
    medium = (severity_counts or {}).get("medium", 0)

    bullets: list[str] = []

    if critical == 0 and high == 0:
        bullets.append("No blocking vulnerabilities identified")
    else:
        bullets.append("Blocking security findings were identified")

    if runtime_verdict == "PASS":
        bullets.append("Application successfully passed runtime verification")
    elif runtime_verdict:
        bullets.append(f"Runtime verification returned {runtime_verdict}")

    if medium > 0:
        bullets.append("Security hardening is incomplete")
    else:
        bullets.append("No medium-severity hardening findings were identified")

    if verdict.upper() == "PASS":
        bullets.append("Current results support continued promotion under existing policy")
    elif verdict.upper() == "WARN":
        bullets.append("Remediation is required prior to production deployment")
    elif verdict.upper() == "BLOCK":
        bullets.append("Approval should not be granted until blocking findings are remediated")
    elif verdict.upper() == "OPERATIONAL_ERROR":
        bullets.append("Formal disposition is not possible until operational issues are resolved")

    lines.append("### Interpretation")
    lines.append("")
    for bullet in bullets:
        lines.append(f"- {bullet}")
    lines.append("")

    return lines


def _render_rationale(
    verdict_rationale: str | None,
    summary: str | None,
    verdict: str,
    risk_score: int | None,
    severity_counts: dict[str, int] | None,
    runtime_context: dict[str, Any] | None,
) -> list[str]:
    lines: list[str] = []

    lines.append("### Rationale")
    lines.append("")

    if verdict_rationale:
        lines.append(str(verdict_rationale).strip())
        lines.append("")
        return lines

    medium = (severity_counts or {}).get("medium", 0)
    runtime_verdict = str((runtime_context or {}).get("Verdict", "UNKNOWN")).upper()

    if verdict.upper() == "WARN":
        lines.append(
            f"The review resulted in a WARN verdict due to unresolved non-blocking findings "
            f"and incomplete hardening. Risk score: {risk_score if risk_score is not None else 'N/A'}. "
            f"Medium findings: {medium}. Runtime verification: {runtime_verdict}."
        )
    elif summary:
        lines.append(str(summary).strip())
    else:
        lines.append("No additional rationale was generated.")

    lines.append("")
    return lines


def _render_severity_table(
    severity_counts: dict[str, int] | None,
) -> list[str]:
    lines: list[str] = []
    if not severity_counts:
        return lines

    lines.append("### Risk Breakdown")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")

    for sev in SEVERITY_ORDER:
        count = severity_counts.get(sev, 0)
        if sev == "unknown" and count == 0:
            continue
        label = SEVERITY_LABELS.get(sev, sev.upper())
        lines.append(f"| {label} | {count} |")

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

    lines.append("### Coverage")
    lines.append("")
    if not missing:
        lines.append("All expected security scans were executed successfully:")
        lines.append("")
        for scan in sorted(detected):
            lines.append(f"- ✅ {scan}")
        lines.append("")
        return lines

    lines.append("| Scan | Status |")
    lines.append("|------|--------|")
    for scan in all_scans:
        status = "✅ Present" if scan in detected else "⚠️ Missing"
        lines.append(f"| {scan} | {status} |")
    lines.append("")

    return lines


def _render_runtime_table(
    runtime_context: dict[str, Any] | None,
) -> list[str]:
    lines: list[str] = []
    if not runtime_context:
        return lines

    lines.append("### Runtime Verification")
    lines.append("")
    lines.append("| Check | Result |")
    lines.append("|------|--------|")

    verdict = str(runtime_context.get("Verdict", "UNKNOWN")).upper()
    verdict_label = VERDICT_LABELS.get(verdict, verdict)
    lines.append(f"| Runtime Verdict | {verdict_label} |")

    profile = runtime_context.get("Profile")
    if profile:
        lines.append(f"| Profile | {profile} |")

    started = runtime_context.get("Container started")
    if started is not None:
        lines.append(f"| Container Startup | {'✅ SUCCESS' if started else '❌ FAILED'} |")

    running = runtime_context.get("Container running")
    if running is not None:
        lines.append(f"| Application Running | {'✅ CONFIRMED' if running else '❌ NOT CONFIRMED'} |")

    startup_seconds = runtime_context.get("Startup seconds")
    if startup_seconds is not None:
        lines.append(f"| Startup Time | {startup_seconds}s |")

    listening_ports = runtime_context.get("Listening ports")
    if listening_ports:
        lines.append(f"| Port | {listening_ports} |")

    image = runtime_context.get("Image")
    if image:
        lines.append(f"| Image | `{image}` |")

    http_status = runtime_context.get("HTTP status")
    if http_status:
        lines.append(f"| Response Check | ✅ {http_status} |")

    lines.append("")
    return lines


def _render_area_table(
    category_counts: dict[str, int] | None,
) -> list[str]:
    lines: list[str] = []
    if not category_counts:
        return lines

    lines.append("### Affected Areas")
    lines.append("")
    lines.append("| Area | Findings |")
    lines.append("|------|----------|")

    for category, count in category_counts.items():
        lines.append(f"| {_format_area_name(category)} | {count} |")

    lines.append("")
    return lines


def _render_tool_table(
    tool_counts: dict[str, int] | None,
) -> list[str]:
    lines: list[str] = []
    if not tool_counts:
        return lines

    lines.append("### Tool Signals")
    lines.append("")
    lines.append("| Tool | Findings |")
    lines.append("|------|----------|")

    for tool, count in tool_counts.items():
        lines.append(f"| {tool} | {count} |")

    lines.append("")
    return lines


def _render_recommendation_summary_table(
    recommendations: list[ReviewRecommendation | dict[str, Any]],
    max_items: int = 10,
) -> list[str]:
    lines: list[str] = []
    if not recommendations:
        return lines

    lines.append("### Recommended Actions")
    lines.append("")
    lines.append("| Priority | Finding | Location | Responsible Party |")
    lines.append("|----------|---------|----------|-------------------|")

    for rec in recommendations[:max_items]:
        item = _normalize_recommendation(rec)
        severity = str(item.get("severity", "unknown")).lower()
        severity_label = PRIORITY_LABELS.get(severity, "⚪ Unknown")

        title = str(item.get("title", "Untitled recommendation")).strip()
        location = str(item.get("location") or "-").strip() or "-"
        rationale = _clean_rationale(str(item.get("rationale") or ""))
        _, _, ownership_guidance = _extract_guidance_sections(rationale)
        owner = _extract_declared_owner(ownership_guidance)

        lines.append(f"| {severity_label} | {title} | `{location}` | {owner} |")

    lines.append("")
    return lines


def _render_detailed_recommendations(
    recommendations: list[ReviewRecommendation | dict[str, Any]],
) -> list[str]:
    lines: list[str] = []

    lines.append("### Details")
    lines.append("")

    if not recommendations:
        lines.append("- No actionable recommendations were generated.")
        lines.append("")
        return lines

    for rec in recommendations:
        item = _normalize_recommendation(rec)

        severity = str(item.get("severity", "unknown")).upper()
        title = str(item.get("title", "Untitled recommendation")).strip()
        location = str(item.get("location") or "").strip()
        suggested_fix = str(item.get("suggested_fix") or "").strip()

        raw_rationale = str(item.get("rationale") or "").strip()
        cleaned_rationale = _clean_rationale(raw_rationale)
        base_rationale, developer_guidance, ownership_guidance = _extract_guidance_sections(
            cleaned_rationale
        )

        compliance_refs = list(
            dict.fromkeys(str(x) for x in (item.get("compliance_refs") or []))
        )

        banned_ref_fragments = [
            "generated using internal security intelligence knowledge base",
            "no external ai or third-party model services were used",
            "recommendations derived from curated compliance and security guidance",
            "mock mode",
        ]

        filtered_refs: list[str] = []
        for ref in compliance_refs:
            lowered = ref.lower()
            if any(fragment in lowered for fragment in banned_ref_fragments):
                continue
            filtered_refs.append(ref)

        compliance_refs = filtered_refs
        owner = _extract_declared_owner(ownership_guidance)

        summary_title = title
        if location:
            summary_title = f"{location} — {title}"

        lines.append("<details>")
        lines.append(f"<summary><strong>{summary_title}</strong></summary>")
        lines.append("")

        lines.append(f"**Severity**: {severity}")
        lines.append("")

        if base_rationale:
            lines.append("**Security Context**")
            lines.append(_truncate_text(base_rationale, limit=700))
            lines.append("")

        if suggested_fix:
            lines.append("**Recommended Action**")
            lines.append(_truncate_text(suggested_fix, limit=700))
            lines.append("")

        if developer_guidance:
            lines.append("**Developer Guidance**")
            lines.append(_truncate_text(developer_guidance, limit=500))
            lines.append("")

        lines.append("**Responsible Party**")
        lines.append(f"- {owner}")
        lines.append("")

        if compliance_refs:
            lines.append("**Compliance References**")
            lines.append(", ".join(compliance_refs[:6]))
            lines.append("")

        lines.append("</details>")
        lines.append("")

    return lines


def _render_context(
    planning_context: dict[str, Any] | None,
) -> list[str]:
    lines: list[str] = []
    if not planning_context:
        return lines

    lines.append("### Context")
    lines.append("")
    lines.append("| Attribute | Value |")
    lines.append("|----------|-------|")

    pipeline_mode = planning_context.get("pipeline_mode")
    if pipeline_mode:
        lines.append(f"| Pipeline Mode | {pipeline_mode} |")

    service_type = planning_context.get("service_type")
    if service_type:
        lines.append(f"| Service Profile | {service_type} |")

    runtime_contract_present = planning_context.get("runtime_contract_present")
    if runtime_contract_present is not None:
        lines.append(
            f"| Runtime Contract Present | {_normalize_bool_text(runtime_contract_present)} |"
        )

    has_dockerfile = planning_context.get("has_dockerfile")
    if has_dockerfile is not None:
        lines.append(
            f"| Dockerfile Detected | {_normalize_bool_text(has_dockerfile)} |"
        )

    has_iac = planning_context.get("has_iac")
    if has_iac is not None:
        lines.append(
            f"| Infrastructure as Code Detected | {_normalize_bool_text(has_iac)} |"
        )

    languages = planning_context.get("languages")
    if languages:
        if isinstance(languages, list):
            language_value = ", ".join(str(x) for x in languages)
        else:
            language_value = str(languages)
        lines.append(f"| Languages | {language_value} |")

    frameworks = planning_context.get("frameworks")
    if frameworks:
        if isinstance(frameworks, list):
            framework_value = ", ".join(str(x) for x in frameworks)
        else:
            framework_value = str(frameworks)
        lines.append(f"| Frameworks | {framework_value} |")

    repo_types = planning_context.get("repo_types")
    if repo_types:
        if isinstance(repo_types, list):
            repo_type_value = ", ".join(str(x) for x in repo_types)
        else:
            repo_type_value = str(repo_types)
        lines.append(f"| Repository Classification | {repo_type_value} |")

    detected_stack = planning_context.get("detected_stack")
    if detected_stack:
        if isinstance(detected_stack, list):
            stack_value = ", ".join(str(x) for x in detected_stack)
        else:
            stack_value = str(detected_stack)
        lines.append(f"| Detected Stack | {stack_value} |")

    deploy_targets = planning_context.get("deploy_targets")
    if deploy_targets:
        if isinstance(deploy_targets, list):
            target_value = ", ".join(str(x) for x in deploy_targets)
        else:
            target_value = str(deploy_targets)
        lines.append(f"| Deployment Targets | {target_value} |")

    lines.append("")
    return lines


def _render_summary(
    verdict: str,
    runtime_context: dict[str, Any] | None,
    operational_warnings: list[str] | None,
) -> list[str]:
    lines: list[str] = []

    lines.append("### Summary")
    lines.append("")

    lines.append("- Pipeline execution completed successfully")

    if runtime_context:
        runtime_verdict = str(runtime_context.get("Verdict", "UNKNOWN")).upper()
        lines.append(f"- Runtime verification result: `{runtime_verdict}`")

    if verdict.upper() == "PASS":
        lines.append("- No blocking vulnerabilities were identified")
        lines.append("- Current results support continued promotion under existing policy")
    elif verdict.upper() == "WARN":
        lines.append("- No blocking vulnerabilities were identified")
        lines.append("- Security posture does not meet production hardening expectations")
        lines.append("- Remediation is required prior to production readiness")
    elif verdict.upper() == "BLOCK":
        lines.append("- Blocking findings were identified")
        lines.append("- Approval should not be granted until remediation is complete")
    elif verdict.upper() == "OPERATIONAL_ERROR":
        lines.append("- Review encountered operational issues")
        lines.append("- Final disposition is not possible until operational issues are resolved")

    if operational_warnings:
        lines.append(f"- Operational warnings: {'; '.join(operational_warnings)}")

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

    lines.extend(
        _render_decision_table(
            verdict=verdict,
            runtime_context=runtime_context,
            risk_score=risk_score,
            severity_counts=severity_counts,
        )
    )
    lines.extend(
        _render_interpretation(
            verdict=verdict,
            runtime_context=runtime_context,
            severity_counts=severity_counts,
        )
    )
    lines.extend(
        _render_rationale(
            verdict_rationale=verdict_rationale,
            summary=summary,
            verdict=verdict,
            risk_score=risk_score,
            severity_counts=severity_counts,
            runtime_context=runtime_context,
        )
    )
    lines.extend(_render_severity_table(severity_counts))
    lines.extend(_render_scan_coverage(detected_scans, missing_scans))
    lines.extend(_render_runtime_table(runtime_context))
    lines.extend(_render_area_table(category_counts))
    lines.extend(_render_tool_table(tool_counts))
    lines.extend(_render_recommendation_summary_table(recommendations))
    lines.extend(_render_detailed_recommendations(recommendations))
    lines.extend(_render_context(planning_context))
    lines.extend(_render_summary(verdict, runtime_context, operational_warnings))

    lines.append(
        "_Full supporting scan details remain available in GitLab security results and pipeline artifacts._"
    )
    lines.append("")

    return "\n".join(lines)