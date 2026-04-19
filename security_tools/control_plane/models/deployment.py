from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(slots=True)
class DeploymentRecord:
    artifact_digest: str
    environment: str
    runtime_config_refs: list[str] = field(default_factory=list)
    env_vars: dict[str, str] = field(default_factory=dict)
    manifest_hash: str | None = None
    runtime_verification_verdict: str | None = None
    drift_verification_verdict: str | None = None
    deployed_by: str | None = None
    deployed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)