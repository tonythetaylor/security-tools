from __future__ import annotations

import re

from security_tools.intelligence.ingest.models import ExtractedSection


SECTION_RE = re.compile(
    r"^\s*(?P<num>\d+(?:\.\d+)*)\s+(?P<title>[A-Z][A-Za-z0-9/&,\-()' ]{5,})\s*$",
    re.MULTILINE,
)

SKIP_TITLES = {
    "abstract",
    "keywords",
    "audience",
    "acknowledgements",
    "executive summary",
    "purpose and scope",
    "document structure",
    "conclusion",
    "references",
    "glossary",
}

ALLOWED_TOP_LEVELS = {"3", "4", "5", "6"}


def _clean_text(text: str) -> str:
    cleaned = re.sub(r"\n--- PAGE \d+ ---\n", "\n", text)
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)

    boilerplate_patterns = [
        r"NIST SP 800-190",
        r"APPLICATION CONTAINER SECURITY GUIDE",
        r"This publication is available free of charge from: https://doi\.org/10\.6028/NIST\.SP\.800-190",
        r"^\s*\d+\s*$",
    ]

    for pattern in boilerplate_patterns:
        cleaned = re.sub(pattern, "", cleaned, flags=re.MULTILINE)

    cleaned = re.sub(r"\n{2,}", "\n\n", cleaned)
    return cleaned.strip()


def split_nist_800_190_sections(text: str, source_file: str) -> list[ExtractedSection]:
    cleaned = _clean_text(text)
    matches = list(SECTION_RE.finditer(cleaned))
    sections: list[ExtractedSection] = []

    if not matches:
        return [
            ExtractedSection(
                source_file=source_file,
                framework="nist_800_190",
                title="NIST SP 800-190",
                body=cleaned[:20000],
                category="container_security_guidance",
                tags=["nist", "800-190", "containers"],
            )
        ]

    for idx, match in enumerate(matches):
        start = match.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(cleaned)

        section_num = match.group("num").strip()
        section_title = match.group("title").strip()
        body = cleaned[start:end].strip()

        title_lower = section_title.lower()
        top_level = section_num.split(".")[0]

        if title_lower in SKIP_TITLES:
            continue

        if top_level not in ALLOWED_TOP_LEVELS:
            continue

        if len(body) < 250:
            continue

        sections.append(
            ExtractedSection(
                source_file=source_file,
                framework="nist_800_190",
                title=f"{section_num} {section_title}",
                section_id=section_num,
                body=body,
                category="container_security_guidance",
                tags=[
                    "nist",
                    "800-190",
                    "containers",
                    f"section_{section_num.replace('.', '_')}",
                ],
                metadata={
                    "level": "section",
                    "section_id": section_num,
                },
            )
        )

    return sections