from __future__ import annotations

import re

from security_tools.intelligence.ingest.models import ExtractedSection


FAMILY_HEADING_RE = re.compile(
    r"^\s*(?P<family>[A-Z]{2})\s+(?P<title>[A-Z][A-Za-z0-9/&,\-()' ]{6,})\s*$",
    re.MULTILINE,
)

CONTROL_HEADING_RE = re.compile(
    r"^\s*(?P<control>[A-Z]{2}-\d+)\s+(?P<title>[A-Z][A-Za-z0-9/&,\-()' ]{4,})\s*$",
    re.MULTILINE,
)

ENHANCEMENT_HEADING_RE = re.compile(
    r"^\s*(?P<control>[A-Z]{2}-\d+\(\d+\))\s+(?P<title>[A-Z][A-Za-z0-9/&,\-()' ]{4,})\s*$",
    re.MULTILINE,
)

SKIP_FAMILY_TITLES = {
    "references",
    "glossary",
    "appendix",
    "control baselines",
    "privacy controls",
}

COMMON_FAMILIES = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "Personally Identifiable Information Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}


def _clean_text(text: str) -> str:
    cleaned = text

    cleaned = re.sub(r"\n--- PAGE \d+ ---\n", "\n", cleaned)
    cleaned = re.sub(r"[ \t]+", " ", cleaned)

    boilerplate_patterns = [
        r"NIST SP 800-53(?:,?\s*REV\.?\s*5)?",
        r"SECURITY AND PRIVACY CONTROLS FOR INFORMATION SYSTEMS AND ORGANIZATIONS",
        r"This publication is available free of charge from:\s*https://doi\.org/10\.6028/NIST\.SP\.800-53r5",
        r"^\s*[ivxlcdm]+\s*$",   # roman numeral page markers
        r"^\s*\d+\s*$",          # numeric page markers
        r"^\s*JOINT TASK FORCE\s*$",
    ]

    for pattern in boilerplate_patterns:
        cleaned = re.sub(pattern, "", cleaned, flags=re.MULTILINE | re.IGNORECASE)

    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def _is_false_positive_family(family: str, title: str) -> bool:
    if family not in COMMON_FAMILIES:
        return True

    lowered = title.strip().lower()
    if lowered in SKIP_FAMILY_TITLES:
        return True

    return False


def _control_tags(control_id: str) -> list[str]:
    family = control_id.split("-")[0].lower()
    normalized = control_id.lower().replace("(", "_").replace(")", "")
    normalized = normalized.replace("-", "_")
    return [
        "nist",
        "800-53",
        family,
        normalized,
    ]


def _build_family_sections(cleaned: str, source_file: str) -> list[ExtractedSection]:
    matches = list(FAMILY_HEADING_RE.finditer(cleaned))
    sections: list[ExtractedSection] = []

    if not matches:
        return sections

    for idx, match in enumerate(matches):
        start = match.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(cleaned)

        family = match.group("family").strip().upper()
        title = match.group("title").strip()
        body = cleaned[start:end].strip()

        if _is_false_positive_family(family, title):
            continue

        if len(body) < 300:
            continue

        sections.append(
            ExtractedSection(
                source_file=source_file,
                framework="nist_800_53",
                title=f"{family} {title}",
                section_id=family,
                body=body,
                category="nist_control_family",
                tags=[
                    "nist",
                    "800-53",
                    "control-family",
                    family.lower(),
                ],
                metadata={
                    "level": "family",
                    "family_id": family,
                    "family_title": title,
                },
            )
        )

    return sections


def _build_control_sections(cleaned: str, source_file: str) -> list[ExtractedSection]:
    matches = list(CONTROL_HEADING_RE.finditer(cleaned))
    sections: list[ExtractedSection] = []

    if not matches:
        return sections

    for idx, match in enumerate(matches):
        start = match.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(cleaned)

        control_id = match.group("control").strip().upper()
        title = match.group("title").strip()
        body = cleaned[start:end].strip()

        family = control_id.split("-")[0]

        if family not in COMMON_FAMILIES:
            continue

        if len(body) < 180:
            continue

        sections.append(
            ExtractedSection(
                source_file=source_file,
                framework="nist_800_53",
                title=f"{control_id} {title}",
                section_id=control_id,
                body=body,
                category="nist_control",
                tags=_control_tags(control_id),
                metadata={
                    "level": "control",
                    "family_id": family,
                    "control_id": control_id,
                    "control_title": title,
                    "family_title": COMMON_FAMILIES.get(family),
                },
            )
        )

    return sections


def _build_enhancement_sections(cleaned: str, source_file: str) -> list[ExtractedSection]:
    matches = list(ENHANCEMENT_HEADING_RE.finditer(cleaned))
    sections: list[ExtractedSection] = []

    if not matches:
        return sections

    for idx, match in enumerate(matches):
        start = match.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(cleaned)

        enhancement_id = match.group("control").strip().upper()
        title = match.group("title").strip()
        body = cleaned[start:end].strip()

        parent_control = enhancement_id.split("(")[0]
        family = parent_control.split("-")[0]

        if family not in COMMON_FAMILIES:
            continue

        if len(body) < 140:
            continue

        normalized = enhancement_id.lower().replace("(", "_").replace(")", "")
        normalized = normalized.replace("-", "_")

        sections.append(
            ExtractedSection(
                source_file=source_file,
                framework="nist_800_53",
                title=f"{enhancement_id} {title}",
                section_id=enhancement_id,
                body=body,
                category="nist_control_enhancement",
                tags=[
                    "nist",
                    "800-53",
                    family.lower(),
                    normalized,
                    "control-enhancement",
                ],
                metadata={
                    "level": "enhancement",
                    "family_id": family,
                    "parent_control_id": parent_control,
                    "enhancement_id": enhancement_id,
                    "enhancement_title": title,
                    "family_title": COMMON_FAMILIES.get(family),
                },
            )
        )

    return sections


def split_nist_800_53_sections(text: str, source_file: str) -> list[ExtractedSection]:
    cleaned = _clean_text(text)

    family_sections = _build_family_sections(cleaned, source_file)
    control_sections = _build_control_sections(cleaned, source_file)
    enhancement_sections = _build_enhancement_sections(cleaned, source_file)

    sections = []
    sections.extend(family_sections)
    sections.extend(control_sections)
    sections.extend(enhancement_sections)

    if sections:
        return sections

    return [
        ExtractedSection(
            source_file=source_file,
            framework="nist_800_53",
            title="NIST SP 800-53 Rev. 5",
            section_id="baseline",
            body=cleaned[:20000],
            category="nist_control_family",
            tags=["nist", "800-53", "baseline"],
            metadata={
                "level": "baseline",
                "note": "Fallback record generated because no family or control boundaries were detected.",
            },
        )
    ]