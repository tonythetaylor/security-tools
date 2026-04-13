from __future__ import annotations

from security_tools.intelligence.ingest.models import ExtractedSection


def split_stig_sections(text: str, source_file: str) -> list[ExtractedSection]:
    return [
        ExtractedSection(
            source_file=source_file,
            framework="stig",
            title="STIG Guidance",
            body=text[:20000],
            category="stig_guidance",
            tags=["stig"],
        )
    ]