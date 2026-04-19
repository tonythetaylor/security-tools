from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml


CONTROL_BLOCK_RE = re.compile(
    r"Control:\s*(.*?)(?=\nDiscussion:|\nRelated Controls:|\nControl Enhancements:|\nReferences:|$)",
    re.DOTALL | re.IGNORECASE,
)

DISCUSSION_BLOCK_RE = re.compile(
    r"Discussion:\s*(.*?)(?=\nRelated Controls:|\nControl Enhancements:|\nReferences:|$)",
    re.DOTALL | re.IGNORECASE,
)

RELATED_CONTROLS_RE = re.compile(
    r"Related Controls:\s*(.*?)(?=\nControl Enhancements:|\nReferences:|$)",
    re.DOTALL | re.IGNORECASE,
)

CONTROL_STMT_RE = re.compile(
    r"(?:^|\n)\s*([a-z])\.\s+(.*?)(?=(?:\n\s*[a-z]\.\s+)|$)",
    re.DOTALL,
)

CONTROL_ID_RE = re.compile(r"\b([A-Z]{2}-\d+(?:\(\d+\))?)\b")


FAMILY_OWNERSHIP = {
    "AC": {"primary": "application_team", "secondary": "iam_team"},
    "AT": {"primary": "security_team", "secondary": "application_team"},
    "AU": {"primary": "platform_team", "secondary": "security_team"},
    "CA": {"primary": "security_team", "secondary": "platform_team"},
    "CM": {"primary": "platform_team", "secondary": "application_team"},
    "CP": {"primary": "platform_team", "secondary": "application_team"},
    "IA": {"primary": "iam_team", "secondary": "application_team"},
    "IR": {"primary": "security_team", "secondary": "platform_team"},
    "MA": {"primary": "platform_team", "secondary": "security_team"},
    "MP": {"primary": "platform_team", "secondary": "security_team"},
    "PE": {"primary": "platform_team", "secondary": "security_team"},
    "PL": {"primary": "security_team", "secondary": "application_team"},
    "PM": {"primary": "security_team", "secondary": "platform_team"},
    "PS": {"primary": "security_team", "secondary": "hr_or_management"},
    "PT": {"primary": "privacy_team", "secondary": "application_team"},
    "RA": {"primary": "security_team", "secondary": "application_team"},
    "SA": {"primary": "application_team", "secondary": "security_team"},
    "SC": {"primary": "platform_team", "secondary": "security_team"},
    "SI": {"primary": "security_team", "secondary": "application_team"},
    "SR": {"primary": "security_team", "secondary": "procurement_or_vendor_management"},
}

FAMILY_PATTERNS = {
    "AC": [
        "role_based_access_control",
        "separation_of_duties_enforcement",
        "least_privilege_enforcement",
    ],
    "AU": [
        "audit_logging",
        "tamper_resistant_logs",
        "log_review_and_alerting",
    ],
    "CM": [
        "baseline_configuration_management",
        "secure_defaults",
        "change_control",
    ],
    "IA": [
        "strong_authentication",
        "credential_lifecycle_management",
        "identity_assurance",
    ],
    "RA": [
        "risk_assessment",
        "threat_modeling",
        "vulnerability_assessment",
    ],
    "SA": [
        "secure_sdlc",
        "developer_testing",
        "supply_chain_review",
    ],
    "SC": [
        "boundary_protection",
        "secure_communications",
        "network_segmentation",
    ],
    "SI": [
        "flaw_remediation",
        "integrity_monitoring",
        "malware_protection",
    ],
    "SR": [
        "supplier_assessment",
        "component_integrity_validation",
        "software_supply_chain_controls",
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


def _extract_control_statements(text: str) -> list[str]:
    block = _extract_block(CONTROL_BLOCK_RE, text)
    if not block:
        return []

    results: list[str] = []
    for _, stmt in CONTROL_STMT_RE.findall(block):
        cleaned = " ".join(stmt.split())
        cleaned = cleaned.rstrip(" ;.")
        if cleaned:
            results.append(cleaned)
    return results


def _extract_discussion(text: str) -> str | None:
    block = _extract_block(DISCUSSION_BLOCK_RE, text)
    if not block:
        return None
    return " ".join(block.split())


def _extract_related_controls(text: str) -> list[str]:
    block = _extract_block(RELATED_CONTROLS_RE, text)
    if not block:
        return []
    found = CONTROL_ID_RE.findall(block)
    seen: list[str] = []
    for item in found:
        if item not in seen:
            seen.append(item)
    return seen


def _summarize_control(text: str, title: str) -> str:
    statements = _extract_control_statements(text)
    if statements:
        joined = "; ".join(statements[:3])
        return f"{title} requires: {joined}."
    discussion = _extract_discussion(text)
    if discussion:
        return discussion[:500].rstrip() + ("..." if len(discussion) > 500 else "")
    return title


def _family_from_doc(doc: dict[str, Any]) -> str | None:
    refs = doc.get("compliance_refs") or []
    for ref in refs:
        control = str((ref or {}).get("control") or "").upper()
        if re.match(r"^[A-Z]{2}-\d+", control):
            return control.split("-")[0]
        if re.match(r"^[A-Z]{2}$", control):
            return control
    doc_id = str(doc.get("id") or "").upper()
    match = re.search(r"NIST-800-53-([A-Z]{2})", doc_id)
    if match:
        return match.group(1)
    return None


def _ownership_for_family(family: str | None) -> dict[str, Any]:
    if not family:
        return {"primary": "security_team"}
    return FAMILY_OWNERSHIP.get(family, {"primary": "security_team"})


def _patterns_for_family(family: str | None) -> list[str]:
    if not family:
        return []
    return FAMILY_PATTERNS.get(family, [])


def _build_remediation_steps(doc: dict[str, Any], family: str | None) -> list[str]:
    text = str(doc.get("description") or "")
    statements = _extract_control_statements(text)
    steps: list[str] = []

    for stmt in statements[:5]:
        normalized = stmt[0].upper() + stmt[1:] if stmt else stmt
        steps.append(normalized)

    if not steps:
        title = str(doc.get("title") or "Control requirement")
        steps.append(f"Review implementation requirements for {title}.")
        steps.append("Document current control coverage and identify implementation gaps.")
        steps.append("Implement technical or procedural changes and validate through review.")

    if family == "CM":
        steps.append("Verify the control is reflected in baseline configuration and change management processes.")
    elif family == "SI":
        steps.append("Validate remediation through scanning, monitoring, and repeatable verification.")
    elif family == "SA":
        steps.append("Ensure the control is integrated into development and testing workflows.")
    elif family == "AC":
        steps.append("Confirm access assignments and role definitions align with least privilege and duty separation.")

    deduped: list[str] = []
    for step in steps:
        if step not in deduped:
            deduped.append(step)

    return deduped


def enrich_nist_800_53_doc(doc: dict[str, Any]) -> dict[str, Any]:
    text = str(doc.get("description") or "")
    title = str(doc.get("title") or "NIST SP 800-53 Control")
    family = _family_from_doc(doc)

    summary = _summarize_control(text, title)
    discussion = _extract_discussion(text)
    related_controls = _extract_related_controls(text)
    control_statements = _extract_control_statements(text)

    doc["description"] = summary

    if discussion:
        doc["rationale"] = discussion
    else:
        doc["rationale"] = summary

    guidance_lines = [
        f"{title} is a NIST SP 800-53 Rev. 5 requirement.",
    ]
    if control_statements:
        guidance_lines.append("Implementation expectations include:")
        for stmt in control_statements[:5]:
            guidance_lines.append(f"- {stmt}")
    else:
        guidance_lines.append("Review and implement the control requirements within the applicable system and process boundaries.")

    doc["developer_guidance"] = "\n".join(guidance_lines)

    doc["recommended_patterns"] = _patterns_for_family(family)
    doc["ownership"] = _ownership_for_family(family)
    doc["risk_context"] = {
        "family": family,
        "related_controls": related_controls,
    }
    doc["remediation"] = {
        "steps": _build_remediation_steps(doc, family),
    }

    doc.setdefault("bad_examples", [])
    doc.setdefault("good_examples", [])

    return doc


def enrich_nist_800_53_file(path: str | Path) -> None:
    file_path = Path(path)
    doc = _read_yaml(file_path)
    enriched = enrich_nist_800_53_doc(doc)
    _write_yaml(file_path, enriched)


def enrich_nist_800_53_directory(path: str | Path) -> int:
    base = Path(path)
    count = 0

    for file_path in sorted(base.glob("*.yml")):
        enrich_nist_800_53_file(file_path)
        count += 1

    return count


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Enrich NIST 800-53 YAML knowledge docs.")
    parser.add_argument("path", help="Path to a YAML file or directory of YAML files")
    args = parser.parse_args()

    target = Path(args.path)
    if target.is_dir():
        total = enrich_nist_800_53_directory(target)
        print(f"Enriched {total} NIST 800-53 documents in {target}")
    else:
        enrich_nist_800_53_file(target)
        print(f"Enriched {target}")