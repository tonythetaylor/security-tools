from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class ArtifactIdentity:
    artifact_type: str
    name: str
    version: str | None = None
    digest: str | None = None
    checksum: str | None = None
    backend_name: str | None = None
    location: str | None = None


@dataclass(slots=True)
class ArtifactRecord:
    identity: ArtifactIdentity
    source_repo: str | None = None
    source_commit: str | None = None
    build_pipeline_id: str | None = None
    sbom_present: bool = False
    signature_present: bool = False
    attestation_present: bool = False
    security_verdict: str | None = None
    risk_score: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)