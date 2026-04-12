# security-tools

Reusable **GitLab CI/CD Security Scanning & Review Framework** for Merge Requests and Pipelines.

This repository provides **modular, reusable security scans** and a **pipeline-native security review engine** that can be included in any GitLab project.

---

# Features

## Security Scanners

This framework includes modular templates for:

| Scanner | Purpose |
|---------|---------|
| Safety | Python dependency vulnerabilities |
| Gitleaks | Secret detection |
| Trivy (SAST) | Static analysis |
| Trivy (Container) | Container/image scanning |
| Hadolint | Dockerfile security |
| Checkov | IaC scanning |

---

## Security Review Engine

The `security_review` job:

- Collects scan artifacts
- Parses findings
- Applies policy logic
- Generates MR comments
- Blocks pipeline when necessary

---

# Quick Start

Include in your project `.gitlab-ci.yml`:

```yaml
include:
  - project: "root/security-tools"
    ref: "main"
    file:
      - "/templates/security-scans.yml"
      - "/templates/security-review.yml"
```

Add stages:

```yaml
stages:
  - build
  - security
  - review
  - test
```

---

# Security Review Behavior

| Result | Behavior |
|--------|----------|
| PASS | Pipeline continues |
| BLOCK | Pipeline fails |
| Operational Error | Warning only |

---

# Exit Codes

| Code | Meaning |
|------|--------|
| 0 | Security passed |
| 1 | Security block |
| 2 | Operational error (non-blocking) |

---

# Required CI Variables

```yaml
variables:
  PYTHON_VERSION: "3.12"
  SECURITY_TOOLS_PROJECT_PATH: "root/security-tools"
  SECURITY_TOOLS_REF: "main"
  ENABLE_MR_COMMENTS: "true"
```

---

# CLI Usage

After install:

```bash
security-review
```

---

# Artifact Files

The review expects:

```
safety-report.json
gl-secret-detection-report.json
gl-sast-report.sarif
gl-container-scanning-report.json
hadolint-report.json
checkov-report.json
```

---

# License

Internal DevSecOps Framework
