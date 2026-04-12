# security-tools

Reusable **GitLab CI/CD Security Scanning & Review Framework** for Merge Requests, Pipelines, and Enterprise DevSecOps workflows.

This repository provides a **modular, reusable, and extensible security pipeline platform** designed to standardize security scanning across multiple GitLab repositories.

---

# Features

## Modular Security Architecture

- Reusable scan templates
- Centralized security review engine
- Merge Request security gating
- Modular suite-based includes
- Cross‑repository DevSecOps standardization
- Pipeline-native security enforcement

---

# Supported Security Scanners

| Scanner | Purpose |
|--------|--------|
| Safety | Python dependency vulnerabilities |
| Gitleaks | Secret detection |
| Trivy (SAST) | Static analysis |
| Trivy (Container) | Container scanning |
| Hadolint | Dockerfile linting |
| Checkov | Infrastructure as Code scanning |

---

# Architecture

```text
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
│
├── security_tools/
│   ├── cli.py
│   ├── reviewer.py
│   ├── parsers.py
│   └── gitlab_api.py
│
├── cli/
│   └── run_security_review.py
│
├── pyproject.toml
└── README.md
```

---

# Quick Start

Include the full security suite:

```yaml
include:
  - project: "root/security-tools"
    ref: "main"
    file: "/templates/suites/security-suite.yml"
```

Define stages:

```yaml
stages:
  - build
  - security
  - review
  - test
```

That's it — all scans and review logic will run automatically.

---

# Security Pipeline Flow

```text
build
  ↓
security scans
  ↓
security_review
  ↓
test
```

---

# Modular Includes

## Include Everything (Recommended)

```yaml
/templates/suites/security-suite.yml
```

Includes:

- All scans
- Security review job

---

## Include Only Scans

```yaml
/templates/suites/security-scans.yml
```

---

## Include Individual Scanner

```yaml
/templates/scans/secret-detection.yml
```

---

# Security Review Engine

The `security_review` job:

- downloads scan artifacts
- installs security-tools package
- parses findings
- generates security verdict
- optionally comments on MR
- blocks pipeline if required

---

# Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Security Passed |
| 1 | Security Block |
| 2 | Operational Error (non‑blocking) |

---

# Merge Request Integration

Security review can:

- Comment on MR
- Provide security summary
- Show vulnerabilities
- Recommend fixes
- Block unsafe merges

---

# Expected Artifacts

The review engine looks for:

```
safety-report.json
gl-secret-detection-report.json
gl-sast-report.sarif
gl-container-scanning-report.json
hadolint-report.json
checkov-report.json
```

---

# Required Variables

```yaml
variables:
  PYTHON_VERSION: "3.12"
  SECURITY_TOOLS_PROJECT_PATH: "root/security-tools"
  SECURITY_TOOLS_REF: "main"
  ENABLE_MR_COMMENTS: "true"
```

---

# CLI Usage

After installation:

```bash
security-review
```

or

```bash
python -m security_tools.cli
```

---

# Authentication Model

Uses:

- CI_JOB_TOKEN
- GitLab project-to-project access
- GitLab API for MR comments

---

# Local Development

Clone:

```bash
git clone http://gitlab/root/security-tools
cd security-tools
```

Install:

```bash
pip install -e .
```

Run:

```bash
security-review
```

---

# Benefits

- Centralized security policy
- Reusable DevSecOps platform
- Consistent security enforcement
- Modular scan composition
- Enterprise-ready architecture

---

# Roadmap

Future enhancements:

- Policy engine
- Severity thresholds
- Security dashboards
- SARIF aggregation
- Slack notifications
- Compliance profiles

---

# Goals

- Reusable
- Modular
- Enterprise-ready
- DevSecOps-friendly
- Multi‑repo support

---

# security-tools

Enterprise‑grade modular GitLab security pipeline framework.
