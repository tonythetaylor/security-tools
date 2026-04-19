from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml


TASKS_BLOCK_RE = re.compile(
    r"Tasks:\s*(.*?)(?=\nNotional Implementation Examples:|\nReferences:|$)",
    re.DOTALL | re.IGNORECASE,
)

EXAMPLES_BLOCK_RE = re.compile(
    r"Notional Implementation Examples:\s*(.*?)(?=\nReferences:|$)",
    re.DOTALL | re.IGNORECASE,
)

REFERENCES_BLOCK_RE = re.compile(
    r"References:\s*(.*?)(?=$)",
    re.DOTALL | re.IGNORECASE,
)

EXAMPLE_RE = re.compile(
    r"Example\s+\d+:\s*(.*?)(?=(?:Example\s+\d+:)|$)",
    re.DOTALL | re.IGNORECASE,
)


GROUP_OWNERSHIP = {
    "PO": {"primary": "platform_team", "secondary": "security_team"},
    "PS": {"primary": "platform_team", "secondary": "application_team"},
    "PW": {"primary": "application_team", "secondary": "security_team"},
    "RV": {"primary": "security_team", "secondary": "application_team"},
}

GROUP_PATTERNS = {
    "PO": [
        "secure_toolchain_management",
        "development_environment_hardening",
        "security_requirements_management",
    ],
    "PS": [
        "artifact_integrity_verification",
        "code_signing",
        "provenance_tracking",
    ],
    "PW": [
        "secure_sdlc",
        "secure_coding_practices",
        "code_review_and_testing",
    ],
    "RV": [
        "vulnerability_intake_and_triage",
        "risk_based_remediation",
        "root_cause_analysis",
    ],
}


def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _write_yaml(path: Path, data: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)


def _extract_block(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    if not match:
        return None
    value = match.group(1).strip()
    return re.sub(r"\n{3,}", "\n\n", value).strip() or None


def _extract_examples(text: str) -> list[str]:
    block = _extract_block(EXAMPLES_BLOCK_RE, text)
    if not block:
        return []
    results: list[str] = []
    for item in EXAMPLE_RE.findall(block):
        cleaned = " ".join(item.split())
        cleaned = cleaned.rstrip(" ;.")
        if cleaned:
            results.append(cleaned)
    return results


def _extract_task_lines(text: str) -> list[str]:
    block = _extract_block(TASKS_BLOCK_RE, text)
    if not block:
        return []

    lines: list[str] = []
    for raw in block.splitlines():
        cleaned = " ".join(raw.split()).strip(" -•")
        if cleaned:
            lines.append(cleaned.rstrip(" ;."))
    return lines


def _extract_references(text: str) -> list[str]:
    block = _extract_block(REFERENCES_BLOCK_RE, text)
    if not block:
        return []
    refs: list[str] = []
    for raw in block.splitlines():
        cleaned = " ".join(raw.split()).strip()
        if cleaned:
            refs.append(cleaned)
    return refs[:12]


def _group_from_doc(doc: dict[str, Any]) -> str | None:
    refs = doc.get("compliance_refs") or []
    for ref in refs:
        control = str((ref or {}).get("control") or "").upper()
        if control in {"PO", "PS", "PW", "RV"}:
            return control
        if re.match(r"^(PO|PS|PW|RV)\.\d+(?:\.\d+)?$", control):
            return control.split(".")[0]
    return None


def _ownership_for_group(group: str | None) -> dict[str, Any]:
    if not group:
        return {"primary": "security_team"}
    return GROUP_OWNERSHIP.get(group, {"primary": "security_team"})


def _patterns_for_group(group: str | None) -> list[str]:
    if not group:
        return []
    return GROUP_PATTERNS.get(group, [])


def _summarize_ssdf(doc: dict[str, Any]) -> str:
    title = str(doc.get("title") or "SSDF Practice")
    text = str(doc.get("description") or "")
    task_lines = _extract_task_lines(text)

    if task_lines:
        joined = "; ".join(task_lines[:2])
        joined = joined[0].lower() + joined[1:] if len(joined) > 1 else joined.lower()
        return f"{title} requires organizations to {joined}."
    return title


def _build_guidance(doc: dict[str, Any], examples: list[str]) -> str:
    title = str(doc.get("title") or "SSDF Practice")
    lines = [f"{title} is an SSDF practice or task."]

    if examples:
        lines.append("Implementation examples include:")
        for item in examples[:5]:
            lines.append(f"- {item}")

    return "\n".join(lines)


def _build_remediation(doc: dict[str, Any], group: str | None) -> list[str]:
    text = str(doc.get("description") or "")
    task_lines = _extract_task_lines(text)
    examples = _extract_examples(text)

    steps: list[str] = []

    for item in task_lines[:4]:
        cleaned = item[0].upper() + item[1:] if item else item
        steps.append(cleaned)

    for item in examples[:2]:
        if item not in steps:
            steps.append(item)

    if group == "PW":
        steps.append("Integrate the identified practice into the development workflow and verification process.")
    elif group == "RV":
        steps.append("Ensure findings are tracked, triaged, and remediated through an established vulnerability response process.")
    elif group == "PO":
        steps.append("Validate the practice is reflected in organizational policy, tooling, and development environment controls.")
    elif group == "PS":
        steps.append("Verify integrity protections are implemented and auditable across software artifacts and releases.")

    deduped: list[str] = []
    for step in steps:
        if step and step not in deduped:
            deduped.append(step)

    return deduped[:6]


def enrich_ssdf_doc(doc: dict[str, Any]) -> dict[str, Any]:
    original_description = str(doc.get("description") or "")
    original_rationale = str(doc.get("rationale") or "")
    original_guidance = str(doc.get("developer_guidance") or "")

    group = _group_from_doc(doc)
    examples = _extract_examples(original_description)
    references = _extract_references(original_description)

    summary = _summarize_ssdf(doc)
    generated_guidance = _build_guidance(doc, examples)
    generated_remediation = _build_remediation(doc, group)

    # Preserve original source-rich fields
    doc["description"] = original_description
    doc["rationale"] = original_rationale or original_description

    # Add enriched fields
    doc["summary"] = summary
    doc["implementation_examples"] = examples[:5]

    # Append guidance instead of replacing it
    if original_guidance.strip():
        doc["developer_guidance"] = (
            original_guidance.rstrip()
            + "\n\nEnriched Guidance:\n"
            + generated_guidance
        )
    else:
        doc["developer_guidance"] = generated_guidance

    # Merge patterns
    existing_patterns = list(doc.get("recommended_patterns") or [])
    for pattern in _patterns_for_group(group):
        if pattern not in existing_patterns:
            existing_patterns.append(pattern)
    doc["recommended_patterns"] = existing_patterns

    # Merge risk context
    risk_context = dict(doc.get("risk_context") or {})
    risk_context["group"] = group
    if references:
        risk_context["references"] = references
    doc["risk_context"] = risk_context

    # Merge ownership only if not already set
    ownership = dict(doc.get("ownership") or {})
    if not ownership:
        ownership = _ownership_for_group(group)
    doc["ownership"] = ownership

    # Merge remediation
    remediation = dict(doc.get("remediation") or {})
    existing_steps = list(remediation.get("steps") or [])
    for step in generated_remediation:
        if step not in existing_steps:
            existing_steps.append(step)
    remediation["steps"] = existing_steps
    doc["remediation"] = remediation

    doc.setdefault("bad_examples", [])
    doc.setdefault("good_examples", [])

    return doc


def enrich_ssdf_file(path: str | Path) -> None:
    file_path = Path(path)
    doc = _read_yaml(file_path)
    enriched = enrich_ssdf_doc(doc)
    _write_yaml(file_path, enriched)


def enrich_ssdf_directory(path: str | Path) -> int:
    base = Path(path)
    count = 0
    for file_path in sorted(base.glob("*.yml")):
        enrich_ssdf_file(file_path)
        count += 1
    return count


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Enrich SSDF YAML knowledge docs.")
    parser.add_argument("path", help="Path to a YAML file or directory of YAML files")
    args = parser.parse_args()

    target = Path(args.path)
    if target.is_dir():
        total = enrich_ssdf_directory(target)
        print(f"Enriched {total} SSDF documents in {target}")
    else:
        enrich_ssdf_file(target)
        print(f"Enriched {target}")