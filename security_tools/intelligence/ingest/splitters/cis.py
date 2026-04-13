from __future__ import annotations

import re

from security_tools.intelligence.ingest.models import ExtractedSection


CONTROL_HEADING_RE = re.compile(
    r"^\s*(?P<num>\d{1,2})\s+(?P<title>[A-Z][A-Za-z0-9/&,\-()' ]{8,})\s*$",
    re.MULTILINE,
)

SAFEGUARD_HEADING_RE = re.compile(
    r"^\s*(?P<num>\d{1,2}\.\d{1,2})\s*$",
    re.MULTILINE,
)


def _clean_text(text: str) -> str:
    cleaned = re.sub(r"\n--- PAGE \d+ ---\n", "\n", text)
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def _is_false_positive_title(title: str) -> bool:
    return title.lower() in {
        "introduction",
        "overview",
        "contents",
        "acronyms and abbreviations",
        "safeguards",
    }


def split_cis_controls_text(text: str, source_file: str) -> list[ExtractedSection]:
    cleaned = _clean_text(text)
    matches = list(CONTROL_HEADING_RE.finditer(cleaned))
    sections: list[ExtractedSection] = []

    if not matches:
        return [
            ExtractedSection(
                source_file=source_file,
                framework="cis",
                title="CIS Controls v8",
                section_id=None,
                body=cleaned[:12000],
                category="cis_control",
                tags=["cis", "controls"],
            )
        ]

    for idx, match in enumerate(matches):
        start = match.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(cleaned)

        control_num = match.group("num").strip().zfill(2)
        control_title = match.group("title").strip()
        body = cleaned[start:end].strip()

        if _is_false_positive_title(control_title):
            continue

        if len(body) < 300:
            continue

        sections.append(
            ExtractedSection(
                source_file=source_file,
                framework="cis",
                title=f"{control_num} {control_title}",
                section_id=control_num,
                body=body,
                category="cis_control",
                tags=["cis", "control", f"control_{control_num}"],
                metadata={"level": "control", "control_id": control_num},
            )
        )

    return sections


def split_cis_safeguards_text(text: str, source_file: str) -> list[ExtractedSection]:
    cleaned = _clean_text(text)
    control_sections = split_cis_controls_text(cleaned, source_file)
    safeguards: list[ExtractedSection] = []

    for control in control_sections:
        control_body = control.body
        matches = list(SAFEGUARD_HEADING_RE.finditer(control_body))

        for idx, match in enumerate(matches):
            sg_num = match.group("num").strip()
            start = match.start()
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(control_body)
            sg_chunk = control_body[start:end].strip()

            lines = [line.strip() for line in sg_chunk.splitlines() if line.strip()]
            if len(lines) < 2:
                continue

            sg_title = lines[1]

            if len(sg_title) < 6:
                continue

            if len(sg_chunk) < 120:
                continue

            control_id = sg_num.split(".")[0].zfill(2)

            safeguards.append(
                ExtractedSection(
                    source_file=source_file,
                    framework="cis",
                    title=f"{sg_num} {sg_title}",
                    section_id=sg_num,
                    body=sg_chunk,
                    category="cis_safeguard",
                    tags=[
                        "cis",
                        "safeguard",
                        f"control_{control_id}",
                        f"safeguard_{sg_num.replace('.', '_')}",
                    ],
                    metadata={
                        "level": "safeguard",
                        "control_id": control_id,
                        "safeguard_id": sg_num,
                        "parent_control_title": control.title,
                    },
                )
            )

    return safeguards