from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from security_tools.clients import GitLabAPI
from security_tools.models import ReviewContext
from security_tools.parsers import (
    parse_checkov,
    parse_gitleaks,
    parse_hadolint,
    parse_safety,
    parse_trivy,
)
from security_tools.review import SecurityReviewer


def load_json(path: str) -> Any | None:
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run GitLab security review from scan artifacts."
    )
    parser.add_argument(
        "--project-id",
        default=os.environ.get("CI_PROJECT_ID"),
        help="GitLab project ID. Defaults to CI_PROJECT_ID.",
    )
    parser.add_argument(
        "--mr-iid",
        default=os.environ.get("CI_MERGE_REQUEST_IID"),
        help="Merge request IID. Defaults to CI_MERGE_REQUEST_IID.",
    )
    parser.add_argument(
        "--branch",
        default=os.environ.get("CI_COMMIT_REF_NAME"),
        help="Branch name. Defaults to CI_COMMIT_REF_NAME.",
    )
    parser.add_argument(
        "--gitlab-url",
        default=os.environ.get("GITLAB_URL", "http://host.docker.internal:8088"),
        help="GitLab base URL.",
    )
    parser.add_argument(
        "--api-token",
        default=os.environ.get("GITLAB_API_TOKEN"),
        help="GitLab API token for MR comments.",
    )
    parser.add_argument(
        "--enable-comments",
        action="store_true",
        default=os.environ.get("ENABLE_MR_COMMENTS", "true").lower() == "true",
        help="Post MR comments when token and MR IID are available.",
    )
    return parser


def summarize_runtime_report(runtime_report: dict[str, Any] | None) -> str:
    if not runtime_report:
        return "Runtime verification: not provided."

    verdict = runtime_report.get("verdict", "UNKNOWN")
    image = runtime_report.get("image", "unknown")
    profile = runtime_report.get("profile", {}) or {}
    startup = runtime_report.get("startup", {}) or {}
    listening_ports = runtime_report.get("listening_ports", []) or []
    warnings = runtime_report.get("warnings", []) or []
    errors = runtime_report.get("errors", []) or []

    lines = [
        "## Runtime Verification",
        f"- Verdict: `{verdict}`",
        f"- Image: `{image}`",
        f"- Profile: `{profile.get('name', 'unknown')}`",
        f"- Container started: `{startup.get('container_started', False)}`",
        f"- Container running: `{startup.get('container_running', False)}`",
        f"- Startup seconds: `{startup.get('startup_seconds', 0)}`",
        f"- Listening ports: `{', '.join(str(p) for p in listening_ports) if listening_ports else 'none'}`",
    ]

    if warnings:
        lines.append("- Warnings:")
        for warning in warnings:
            lines.append(f"  - {warning}")

    if errors:
        lines.append("- Errors:")
        for error in errors:
            lines.append(f"  - {error}")

    return "\n".join(lines)


def final_verdict_from_review_and_runtime(
    review_verdict: str,
    runtime_report: dict[str, Any] | None,
) -> str:
    if not runtime_report:
        return review_verdict

    runtime_verdict = str(runtime_report.get("verdict", "PASS")).upper()

    if runtime_verdict == "OPERATIONAL_ERROR":
        return "OPERATIONAL_ERROR"

    if runtime_verdict == "BLOCK":
        return "BLOCK"

    if runtime_verdict == "WARN":
        if review_verdict == "BLOCK":
            return "BLOCK"
        if review_verdict == "OPERATIONAL_ERROR":
            return "OPERATIONAL_ERROR"
        return "WARN"

    return review_verdict


def build_planning_context() -> dict[str, Any] | None:
    generated_plan = load_json("scan-plan.json")
    if isinstance(generated_plan, dict):
        detected = generated_plan.get("detected", {}) or {}
        return {
            "pipeline_mode": "dynamic child pipeline",
            "detected_stack": sorted(
                set(
                    list(detected.get("languages", []) or [])
                    + list(detected.get("frameworks", []) or [])
                    + ([detected.get("service_type")] if detected.get("service_type") else [])
                )
            ),
            "deploy_targets": detected.get("deploy_targets", []) or [],
            "runtime_contract_present": detected.get("has_runtime_contract", False),
        }

    runtime_contract = load_json("runtime-contract.json")
    if isinstance(runtime_contract, dict):
        service = runtime_contract.get("service", {}) or {}
        stack = []
        role = service.get("role")
        if role:
            stack.append(str(role))
        return {
            "pipeline_mode": "runtime contract guided",
            "detected_stack": stack,
            "deploy_targets": [],
            "runtime_contract_present": True,
        }

    if Path("runtime-contract.yml").exists():
        return {
            "pipeline_mode": "dynamic child pipeline",
            "detected_stack": [],
            "deploy_targets": [],
            "runtime_contract_present": True,
        }

    return {
        "pipeline_mode": "static or inferred",
        "detected_stack": [],
        "deploy_targets": [],
        "runtime_contract_present": False,
    }


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    project_id = args.project_id
    mr_iid = args.mr_iid
    branch = args.branch
    api_token = args.api_token
    gitlab_url = args.gitlab_url
    enable_comments = args.enable_comments

    if not project_id:
        print("CI_PROJECT_ID is required", file=sys.stderr)
        return 2

    scan_files = {
        "dependency_scanning": "safety-report.json",
        "secret_detection": "gl-secret-detection-report.json",
        "sast": "gl-sast-report.sarif",
        "container_scanning": "gl-container-scanning-report.json",
        "dockerfile_scanning": "hadolint-report.json",
        "iac_scanning": "checkov-report.json",
    }

    runtime_report = load_json("runtime-report.json")
    runtime_present = runtime_report is not None
    planning_context = build_planning_context()

    present_scans = [
        scan_name
        for scan_name, file_name in scan_files.items()
        if Path(file_name).exists()
    ]

    if runtime_present:
        present_scans.append("runtime_verification")

    if not present_scans:
        print(
            "No scan artifacts found. The security scan jobs may not have run, "
            "or their artifacts were not downloaded into the security_review job.",
            file=sys.stderr,
        )
        print("Expected one or more of:", file=sys.stderr)
        for _, file_name in scan_files.items():
            print(f"  - {file_name}", file=sys.stderr)
        print("  - runtime-report.json", file=sys.stderr)
        return 2

    findings = []
    findings.extend(parse_safety(load_json("safety-report.json")))
    findings.extend(parse_gitleaks(load_json("gl-secret-detection-report.json")))
    findings.extend(parse_trivy(load_json("gl-container-scanning-report.json")))
    findings.extend(parse_hadolint(load_json("hadolint-report.json")))
    findings.extend(parse_checkov(load_json("checkov-report.json")))

    context = ReviewContext(
        project_id=int(project_id),
        branch=branch,
        merge_request_iid=int(mr_iid) if mr_iid else None,
        findings=findings,
        detected_scans=present_scans,
        gitlab_ci_content=Path(".gitlab-ci.yml").read_text(encoding="utf-8")
        if Path(".gitlab-ci.yml").exists()
        else None,
        dockerfile_content=Path("Dockerfile").read_text(encoding="utf-8")
        if Path("Dockerfile").exists()
        else None,
        dockerignore_content=Path(".dockerignore").read_text(encoding="utf-8")
        if Path(".dockerignore").exists()
        else None,
        metadata={
            "runtime_report": runtime_report,
            "planning_context": planning_context,
        },
    )

    try:
        reviewer = SecurityReviewer()
        review = reviewer.review(context)
    except Exception as exc:
        print(f"Operational error while building review: {exc}", file=sys.stderr)
        return 2

    runtime_summary = summarize_runtime_report(runtime_report)
    final_verdict = final_verdict_from_review_and_runtime(
        str(review.verdict).upper(),
        runtime_report,
    )

    output = {
        "review": review.model_dump(),
        "runtime_report": runtime_report,
        "planning_context": planning_context,
        "runtime_summary": runtime_summary,
        "final_verdict": final_verdict,
    }
    print(json.dumps(output, indent=2))

    mr_comment = review.mr_comment

    if api_token and mr_iid and enable_comments:
        try:
            api = GitLabAPI(base_url=gitlab_url, token=api_token, verify_ssl=False)
            api.post_merge_request_note(
                project_id=int(project_id),
                merge_request_iid=int(mr_iid),
                body=mr_comment,
            )
        except Exception as exc:
            print(f"Failed to post MR comment: {exc}", file=sys.stderr)
            return 2

    if final_verdict == "BLOCK":
        return 1
    if final_verdict == "OPERATIONAL_ERROR":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())