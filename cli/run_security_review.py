from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from security_tools.parsers import parse_checkov, parse_gitleaks, parse_hadolint, parse_safety, parse_trivy
from security_tools.reviewer import build_review
from security_tools.gitlab_api import GitLabAPI


def load_json(path: str):
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def main() -> int:
    project_id = os.environ.get("CI_PROJECT_ID")
    mr_iid = os.environ.get("CI_MERGE_REQUEST_IID")
    branch = os.environ.get("CI_COMMIT_REF_NAME")
    api_token = os.environ.get("GITLAB_API_TOKEN")
    gitlab_url = os.environ.get("GITLAB_URL", "http://host.docker.internal:8088")
    enable_comments = os.environ.get("ENABLE_MR_COMMENTS", "true").lower() == "true"

    if not project_id:
        print("CI_PROJECT_ID is required", file=sys.stderr)
        return 2

    findings = []
    findings.extend(parse_safety(load_json("safety-report.json")))
    findings.extend(parse_gitleaks(load_json("gl-secret-detection-report.json")))
    findings.extend(parse_trivy(load_json("gl-container-scanning-report.json")))
    findings.extend(parse_hadolint(load_json("hadolint-report.json")))
    findings.extend(parse_checkov(load_json("checkov-report.json")))

    context = {
        "project_id": int(project_id),
        "branch": branch,
        "merge_request_iid": int(mr_iid) if mr_iid else None,
        "findings": findings,
        "detected_scans": [
            scan for scan, file_name in [
                ("dependency_scanning", "safety-report.json"),
                ("secret_detection", "gl-secret-detection-report.json"),
                ("sast", "gl-sast-report.sarif"),
                ("container_scanning", "gl-container-scanning-report.json"),
                ("dockerfile_scanning", "hadolint-report.json"),
                ("iac_scanning", "checkov-report.json"),
            ] if Path(file_name).exists()
        ],
        "gitlab_ci_content": Path(".gitlab-ci.yml").read_text(encoding="utf-8") if Path(".gitlab-ci.yml").exists() else None,
        "dockerfile_content": Path("Dockerfile").read_text(encoding="utf-8") if Path("Dockerfile").exists() else None,
        "dockerignore_content": Path(".dockerignore").read_text(encoding="utf-8") if Path(".dockerignore").exists() else None,
    }

    review = build_review(context)
    print(json.dumps(review, indent=2))

    if api_token and mr_iid and enable_comments:
        api = GitLabAPI(base_url=gitlab_url, token=api_token, verify_ssl=False)
        api.post_merge_request_note(
            project_id=int(project_id),
            merge_request_iid=int(mr_iid),
            body=review["mr_comment"],
        )

    return 1 if review["verdict"] == "BLOCK" else 0


if __name__ == "__main__":
    raise SystemExit(main())
