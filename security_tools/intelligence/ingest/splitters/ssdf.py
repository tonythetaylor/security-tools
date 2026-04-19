from __future__ import annotations

import re

from security_tools.intelligence.ingest.models import ExtractedSection


PRACTICE_HEADING_RE = re.compile(
    r"^\s*(?P<practice>(?:PO|PS|PW|RV)\.\d+)\s*:\s*(?P<title>.+?)\s*$",
    re.MULTILINE,
)

TASK_HEADING_RE = re.compile(
    r"^\s*(?P<task>(?:PO|PS|PW|RV)\.\d+\.\d+)\s*:\s*(?P<title>.+?)\s*$",
    re.MULTILINE,
)

GROUP_HEADING_RE = re.compile(
    r"^\s*(?P<group>Prepare the Organization \(PO\)|Protect Software \(PS\)|Produce Well-Secured Software \(PW\)|Respond to Vulnerabilities \(RV\))\s*$",
    re.MULTILINE,
)


def _clean_text(text: str) -> str:
    cleaned = text

    cleaned = re.sub(r"\n--- PAGE \d+ ---\n", "\n", cleaned)
    cleaned = re.sub(r"This publication is available free of charge from.*?\n", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"NIST SP 800-218\s+SSDF VERSION 1\.1", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    cleaned = re.sub(r"[ \t]+", " ", cleaned)

    return cleaned.strip()


def _group_code_from_name(name: str) -> str:
    if "(PO)" in name:
        return "PO"
    if "(PS)" in name:
        return "PS"
    if "(PW)" in name:
        return "PW"
    if "(RV)" in name:
        return "RV"
    return "SSDF"


def _infer_group_title(group_code: str) -> str:
    return {
        "PO": "Prepare the Organization",
        "PS": "Protect Software",
        "PW": "Produce Well-Secured Software",
        "RV": "Respond to Vulnerabilities",
    }.get(group_code, "SSDF")


def _build_task_sections(cleaned: str, source_file: str) -> list[ExtractedSection]:
    matches = list(TASK_HEADING_RE.finditer(cleaned))
    sections: list[ExtractedSection] = []

    for idx, match in enumerate(matches):
        start = match.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(cleaned)

        task_id = match.group("task").strip().upper()
        title = match.group("title").strip()
        body = cleaned[start:end].strip()

        if len(body) < 150:
            continue

        practice_id = ".".join(task_id.split(".")[:2])
        group_code = task_id.split(".")[0]

        sections.append(
            ExtractedSection(
                source_file=source_file,
                framework="ssdf",
                title=f"{task_id} {title}",
                section_id=task_id,
                body=body,
                category="ssdf_task",
                tags=[
                    "ssdf",
                    "nist_800_218",
                    group_code.lower(),
                    practice_id.lower().replace(".", "_"),
                    task_id.lower().replace(".", "_"),
                    "task",
                ],
                metadata={
                    "level": "task",
                    "group_code": group_code,
                    "group_title": _infer_group_title(group_code),
                    "practice_id": practice_id,
                    "task_id": task_id,
                    "task_title": title,
                },
            )
        )

    return sections


def _build_practice_sections(cleaned: str, source_file: str) -> list[ExtractedSection]:
    matches = list(PRACTICE_HEADING_RE.finditer(cleaned))
    sections: list[ExtractedSection] = []

    for idx, match in enumerate(matches):
        start = match.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(cleaned)

        practice_id = match.group("practice").strip().upper()
        title = match.group("title").strip()
        body = cleaned[start:end].strip()

        if len(body) < 250:
            continue

        group_code = practice_id.split(".")[0]

        sections.append(
            ExtractedSection(
                source_file=source_file,
                framework="ssdf",
                title=f"{practice_id} {title}",
                section_id=practice_id,
                body=body,
                category="ssdf_practice",
                tags=[
                    "ssdf",
                    "nist_800_218",
                    group_code.lower(),
                    practice_id.lower().replace(".", "_"),
                    "practice",
                ],
                metadata={
                    "level": "practice",
                    "group_code": group_code,
                    "group_title": _infer_group_title(group_code),
                    "practice_id": practice_id,
                    "practice_title": title,
                },
            )
        )

    return sections


def _build_group_sections(cleaned: str, source_file: str) -> list[ExtractedSection]:
    matches = list(GROUP_HEADING_RE.finditer(cleaned))
    sections: list[ExtractedSection] = []

    for idx, match in enumerate(matches):
        start = match.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(cleaned)

        group_name = match.group("group").strip()
        group_code = _group_code_from_name(group_name)
        body = cleaned[start:end].strip()

        if len(body) < 300:
            continue

        sections.append(
            ExtractedSection(
                source_file=source_file,
                framework="ssdf",
                title=group_name,
                section_id=group_code,
                body=body,
                category="ssdf_group",
                tags=[
                    "ssdf",
                    "nist_800_218",
                    group_code.lower(),
                    "group",
                ],
                metadata={
                    "level": "group",
                    "group_code": group_code,
                    "group_title": group_name,
                },
            )
        )

    return sections


def split_ssdf_sections(text: str, source_file: str) -> list[ExtractedSection]:
    cleaned = _clean_text(text)

    task_sections = _build_task_sections(cleaned, source_file)
    practice_sections = _build_practice_sections(cleaned, source_file)
    group_sections = _build_group_sections(cleaned, source_file)

    sections: list[ExtractedSection] = []
    sections.extend(group_sections)
    sections.extend(practice_sections)
    sections.extend(task_sections)

    if sections:
        return sections

    return [
        ExtractedSection(
            source_file=source_file,
            framework="ssdf",
            title="NIST SP 800-218 SSDF Version 1.1",
            section_id="baseline",
            body=cleaned[:20000],
            category="ssdf_baseline",
            tags=["ssdf", "nist_800_218", "baseline"],
            metadata={
                "level": "baseline",
                "note": "Fallback record generated because no SSDF group, practice, or task boundaries were detected.",
            },
        )
    ]