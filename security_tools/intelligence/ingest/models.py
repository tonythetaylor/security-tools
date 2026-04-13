from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from security_tools.intelligence.models import KnowledgeDocument


class ExtractedSection(BaseModel):
    source_file: str
    framework: str
    title: str
    section_id: str | None = None
    body: str
    category: str | None = None
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IngestResult(BaseModel):
    framework: str
    input_file: str
    output_dir: str
    sections: int = 0
    written_files: list[str] = Field(default_factory=list)
    documents: list[KnowledgeDocument] = Field(default_factory=list)