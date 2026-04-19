from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class RuntimeConfigEnvelope:
    environment: str
    artifact_digest: str
    env_vars: dict[str, str] = field(default_factory=dict)
    secret_refs: list[str] = field(default_factory=list)
    config_refs: list[str] = field(default_factory=list)
    manifest_hash: str | None = None