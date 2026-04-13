from __future__ import annotations

from pathlib import Path

from security_tools.intelligence.ingest.extractors import extract_text
from security_tools.intelligence.ingest.mappers.cis import map_cis_section
from security_tools.intelligence.ingest.mappers.fedramp import map_fedramp_section
from security_tools.intelligence.ingest.mappers.nist_800_53 import map_nist_800_53_section
from security_tools.intelligence.ingest.mappers.nist_800_190 import map_nist_800_190_section
from security_tools.intelligence.ingest.mappers.stig import map_stig_section
from security_tools.intelligence.ingest.models import ExtractedSection, IngestResult
from security_tools.intelligence.ingest.splitters.cis import (
    split_cis_controls_text,
    split_cis_safeguards_text,
)
from security_tools.intelligence.ingest.splitters.fedramp import split_fedramp_sections
from security_tools.intelligence.ingest.splitters.nist_800_53 import split_nist_800_53_sections
from security_tools.intelligence.ingest.splitters.nist_800_190 import split_nist_800_190_sections
from security_tools.intelligence.ingest.splitters.stig import split_stig_sections
from security_tools.intelligence.ingest.writers import write_knowledge_doc


def _default_section(input_file: Path, framework: str, text: str) -> list[ExtractedSection]:
    return [
        ExtractedSection(
            source_file=str(input_file),
            framework=framework,
            title=input_file.stem,
            body=text,
            category="general",
            tags=[framework],
        )
    ]


def ingest_document(
    input_file: str | Path,
    framework: str,
    output_dir: str | Path,
) -> IngestResult:
    input_path = Path(input_file)
    out_dir = Path(output_dir)
    fw = framework.lower().strip()

    text = extract_text(input_path)

    if fw == "cis":
        sections = split_cis_controls_text(text, str(input_path))
        mapper = map_cis_section

    elif fw == "cis_safeguards":
        sections = split_cis_safeguards_text(text, str(input_path))
        mapper = map_cis_section

    elif fw == "cis_all":
        control_sections = split_cis_controls_text(text, str(input_path))
        safeguard_sections = split_cis_safeguards_text(text, str(input_path))
        sections = control_sections + safeguard_sections
        mapper = map_cis_section

    elif fw == "nist_800_53":
        sections = split_nist_800_53_sections(text, str(input_path))
        mapper = map_nist_800_53_section

    elif fw == "nist_800_190":
        sections = split_nist_800_190_sections(text, str(input_path))
        mapper = map_nist_800_190_section

    elif fw == "stig":
        sections = split_stig_sections(text, str(input_path))
        mapper = map_stig_section

    elif fw == "fedramp":
        sections = split_fedramp_sections(text, str(input_path))
        mapper = map_fedramp_section

    else:
        raise ValueError(
            f"Unsupported framework '{framework}'. "
            "Supported values: cis, cis_safeguards, cis_all, "
            "nist_800_53, nist_800_190, stig, fedramp."
        )

    if not sections:
        sections = _default_section(input_path, fw, text)

    documents = [mapper(section) for section in sections]
    written_files = [str(write_knowledge_doc(doc, out_dir)) for doc in documents]

    return IngestResult(
        framework=fw,
        input_file=str(input_path),
        output_dir=str(out_dir),
        sections=len(sections),
        written_files=written_files,
        documents=documents,
    )