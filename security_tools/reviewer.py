from __future__ import annotations

from typing import Any


EXPECTED_SCANS = [
    "sast",
    "dependency_scanning",
    "secret_detection",
    "container_scanning",
    "iac_scanning",
]


def _heuristic_recommendations(context: dict[str, Any]) -> list[dict]:
    recs: list[dict] = []
    dockerfile = (context.get("dockerfile_content") or "").lower()
    ci = (context.get("gitlab_ci_content") or "").lower()

    if "copy . ." in dockerfile:
        recs.append({
            "title": "Dockerfile uses broad COPY pattern",
            "severity": "high",
            "rationale": "Broad copy patterns can move unnecessary files into the image.",
            "suggested_fix": "Replace broad COPY with targeted paths only.",
            "compliance_refs": ["NIST CM-6", "FedRAMP CM-6"],
            "location": "Dockerfile",
        })

    if "from " in dockerfile and " as " not in dockerfile:
        recs.append({
            "title": "Dockerfile may not separate build and runtime stages",
            "severity": "medium",
            "rationale": "Single-stage builds commonly retain build tools in runtime images.",
            "suggested_fix": "Use multi-stage builds and copy only runtime artifacts.",
            "compliance_refs": ["NIST CM-6", "NIST SI-2"],
            "location": "Dockerfile",
        })

    for marker, fix in [
        ("artifacts:", "Review artifact boundaries to ensure only deployable outputs are persisted."),
        ("paths:", "Artifact path collection should be scoped to release outputs only."),
        ("latest", "Avoid mutable tags to reduce drift across environments."),
    ]:
        if marker in ci:
            recs.append({
                "title": f"CI/CD YAML contains pattern requiring security review: {marker}",
                "severity": "medium",
                "rationale": "Pipeline configuration patterns can unintentionally broaden deploy scope or artifact scope.",
                "suggested_fix": fix,
                "compliance_refs": ["NIST CM-3", "NIST SA-11"],
                "location": ".gitlab-ci.yml",
            })

    return recs


def build_review(context: dict[str, Any]) -> dict[str, Any]:
    detected_scans = context.get("detected_scans", [])
    findings = context.get("findings", [])
    missing_expected_scans = [scan for scan in EXPECTED_SCANS if scan not in detected_scans]

    recommendations = _heuristic_recommendations(context)

    for finding in findings:
        recommendations.append({
            "title": finding.get("title", "Finding"),
            "severity": str(finding.get("severity", "medium")).upper(),
            "rationale": finding.get("description", ""),
            "suggested_fix": finding.get("recommendation", "Review and remediate."),
            "compliance_refs": finding.get("compliance_refs", []),
            "location": finding.get("location"),
        })

    verdict = "APPROVE"
    if missing_expected_scans or any(str(r["severity"]).lower() in {"high", "critical"} for r in recommendations):
        verdict = "BLOCK"
    elif recommendations:
        verdict = "REVIEW"

    summary = f"Pipeline-native security review completed. Detected {len(detected_scans)} scans and generated {len(recommendations)} recommendations."

    lines = [
        "## Security Review Summary",
        "",
        f"- **Verdict:** {verdict}",
        f"- **Detected scans:** {', '.join(detected_scans) if detected_scans else 'none'}",
        f"- **Missing expected scans:** {', '.join(missing_expected_scans) if missing_expected_scans else 'none'}",
        "",
        summary,
        "",
        "### Recommendations",
    ]

    if recommendations:
        for rec in recommendations:
            lines.append(f"- **{str(rec['severity']).upper()}** {rec['title']}")
            if rec.get("location"):
                lines.append(f"  - Location: {rec['location']}")
            if rec.get("rationale"):
                lines.append(f"  - Rationale: {rec['rationale']}")
            if rec.get("suggested_fix"):
                lines.append(f"  - Suggested fix: {rec['suggested_fix']}")
            refs = rec.get("compliance_refs") or []
            if refs:
                lines.append(f"  - Compliance: {', '.join(refs)}")
    else:
        lines.append("- No issues detected by configured heuristics and scanner parsers.")

    return {
        "verdict": verdict,
        "summary": summary,
        "recommendations": recommendations,
        "mr_comment": "\n".join(lines),
        "missing_expected_scans": missing_expected_scans,
    }
