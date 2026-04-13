from __future__ import annotations

from security_tools.intelligence.ingest.models import ExtractedSection


def split_nist_800_53_sections(text: str, source_file: str) -> list[ExtractedSection]:
    return [
        ExtractedSection(
            source_file=source_file,
            framework="nist_800_53",
            title="NIST SP 800-53 Rev. 5",
            body=text[:20000],
            category="nist_control_family",
            tags=["nist", "800-53"],
        )
    ]