from __future__ import annotations

from security_tools.intelligence.ingest.models import ExtractedSection


def split_fedramp_sections(text: str, source_file: str) -> list[ExtractedSection]:
    return [
        ExtractedSection(
            source_file=source_file,
            framework="fedramp",
            title="FedRAMP Guidance",
            body=text[:20000],
            category="fedramp_guidance",
            tags=["fedramp"],
        )
    ]