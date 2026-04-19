# Security Intelligence Engine

## Overview

The Security Intelligence Engine transforms compliance frameworks (NIST,
CIS, etc.) into structured, actionable security guidance for engineering
teams.

It is designed to power: - Security reviews - DevSecOps pipelines -
Policy-as-code systems - Automated remediation guidance

This is not a document parser.\
It is a structured intelligence pipeline.

------------------------------------------------------------------------

## Pipeline Architecture

Source Document (PDF) ↓ Parser / Mapper ↓ Structured Controls (YAML) ↓
Enricher ↓ Actionable Intelligence (YAML)

------------------------------------------------------------------------

## Core Stages

### 1. Parse

Extracts structured control data from source documents.

Output: - Control ID - Title - Raw description - Basic metadata

### 2. Enrich

Transforms controls into engineering-ready intelligence.

Adds: - Developer guidance - Recommended patterns - Risk relationships -
Ownership - Remediation steps

### 3. Output

Writes normalized YAML knowledge documents used by the security engine.

------------------------------------------------------------------------

## CLI Usage

### Full Pipeline

python -m security_tools.intelligence.ingest.cli\
--stage full\
--input knowledge_sources/nist/NIST.SP.800-53r5.pdf\
--framework nist_800_53\
--output-dir
security_tools/intelligence/knowledge/compliance/nist_800_53

### Parse Only

--stage parse

### Enrich Only

--stage enrich

------------------------------------------------------------------------

## Knowledge Model

Each control is represented as structured YAML:

id: nist-800-53-ac_5 title: AC-5 SEPARATION OF DUTIES category:
access_security

description: Defines required behavior for enforcing separation of
duties.

developer_guidance: - Identify duties requiring separation - Define
role-based access boundaries - Enforce least privilege

recommended_patterns: - role_based_access_control -
least_privilege_enforcement

risk_context: family: AC related_controls: - AC-2 - AC-3

ownership: primary: application_team secondary: iam_team

remediation: steps: - Identify duties requiring separation - Define
access roles - Validate enforcement - Audit access assignments

------------------------------------------------------------------------

## Supported Frameworks

-   NIST 800-53
-   NIST 800-190
-   CIS Benchmarks

------------------------------------------------------------------------

## Design Principles

### Separation of Concerns

Parsing and enrichment are independent stages.

### Deterministic Output

Same input produces the same structured output.

### Engineering Focus

Output is built for developers, not auditors.

### Incremental Processing

Enrichment can run independently of parsing.

------------------------------------------------------------------------

## Common Issues

### Module Warning

Safe to ignore during repeated CLI execution.

### Low Quality Output

Indicates enrichment logic needs improvement.

------------------------------------------------------------------------

## Summary

The Intelligence Engine converts compliance frameworks into actionable
engineering intelligence.

The value of the system is determined by enrichment quality, not
parsing.
