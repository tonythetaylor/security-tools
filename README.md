# security-tools

Reusable **GitLab CI/CD security scanning and review framework** for merge requests and branch protection workflows.

This repository provides a **modular security pipeline platform** for GitLab projects.

---

# Architecture

security-tools/
├── templates/
│   ├── base/
│   │   └── security-rules.yml
│   ├── scans/
│   │   ├── dependency-scan.yml
│   │   ├── secret-detection.yml
│   │   ├── sast.yml
│   │   ├── container-scanning.yml
│   │   ├── dockerfile-scan.yml
│   │   └── iac-scanning.yml
│   ├── review/
│   │   └── security-review.yml
│   └── suites/
│       ├── security-scans.yml
│       └── security-suite.yml

---

# Quick Start

include:
  - project: "root/security-tools"
    ref: "main"
    file: "/templates/suites/security-suite.yml"

stages:
  - build
  - security
  - review
  - test

---

# Included Scanners

- Dependency Scanning (Safety)
- Secret Detection (Gitleaks)
- SAST (Trivy)
- Container Scanning (Trivy)
- Dockerfile Scanning (Hadolint)
- IaC Scanning (Checkov)

---

# Review Engine

The security_review job:

- downloads artifacts
- installs security-tools
- parses findings
- generates verdict
- optionally comments on MR

Exit Codes:

0 = Pass
1 = Block
2 = Operational Error

---

# CLI

security-review

or

python -m security_tools.cli

---

# Variables

PYTHON_VERSION=3.12
SECURITY_TOOLS_PROJECT_PATH=root/security-tools
SECURITY_TOOLS_REF=main
ENABLE_MR_COMMENTS=true

---

# Modular Includes

Include everything:

/templates/suites/security-suite.yml

Include only scans:

/templates/suites/security-scans.yml

Include individual scan:

/templates/scans/*.yml

---

# Artifacts Expected

safety-report.json
gl-secret-detection-report.json
gl-sast-report.sarif
gl-container-scanning-report.json
hadolint-report.json
checkov-report.json

---

# Goals

Reusable
Modular
Enterprise-ready
DevSecOps-friendly
