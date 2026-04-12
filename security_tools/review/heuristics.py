from __future__ import annotations

from security_tools.models import NormalizedFinding


def build_heuristic_findings(
    gitlab_ci_content: str | None,
    dockerfile_content: str | None,
) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []

    dockerfile = dockerfile_content or ""
    if "COPY . ." in dockerfile:
        findings.append(
            NormalizedFinding(
                tool="heuristic",
                finding_type="dockerfile_issue",
                rule_id="docker.broad_copy",
                category="dockerfile_scanning",
                severity="high",
                title="Dockerfile uses broad COPY pattern",
                description="Broad COPY patterns can copy unnecessary files into the runtime image.",
                location={"path": "Dockerfile"},
                metadata={"source": "heuristic"},
            )
        )

    if dockerfile and "FROM" in dockerfile and dockerfile.count("FROM") == 1:
        findings.append(
            NormalizedFinding(
                tool="heuristic",
                finding_type="dockerfile_issue",
                rule_id="docker.single_stage",
                category="dockerfile_scanning",
                severity="medium",
                title="Dockerfile may not separate build and runtime stages",
                description="Single-stage Dockerfiles often retain build dependencies in runtime.",
                location={"path": "Dockerfile"},
                metadata={"source": "heuristic"},
            )
        )

    gitlab_ci = gitlab_ci_content or ""
    if "artifacts:" in gitlab_ci:
        findings.append(
            NormalizedFinding(
                tool="heuristic",
                finding_type="static_misconfiguration",
                rule_id="ci.artifacts_scope",
                category="pipeline_review",
                severity="medium",
                title="CI/CD YAML contains artifact scope patterns requiring review",
                description="Artifact usage should be reviewed for over-broad collection.",
                location={"path": ".gitlab-ci.yml"},
                metadata={"source": "heuristic"},
            )
        )

    if "paths:" in gitlab_ci:
        findings.append(
            NormalizedFinding(
                tool="heuristic",
                finding_type="static_misconfiguration",
                rule_id="ci.paths_scope",
                category="pipeline_review",
                severity="medium",
                title="CI/CD YAML contains artifact path patterns requiring review",
                description="Artifact paths should be limited to deployable outputs.",
                location={"path": ".gitlab-ci.yml"},
                metadata={"source": "heuristic"},
            )
        )

    return findings