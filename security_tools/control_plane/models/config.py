from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class RegistryAuthConfig:
    method: str
    secret_ref: str | None = None


@dataclass(slots=True)
class RegistryIntegrationConfig:
    name: str
    type: str
    supports: list[str] = field(default_factory=list)
    url: str | None = None
    verify_tls: bool = True
    region: str | None = None
    account_id: str | None = None
    repository: str | None = None
    namespace: str | None = None
    auth: RegistryAuthConfig | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EvidenceStoreConfig:
    name: str
    type: str
    base_path: str | None = None
    bucket: str | None = None
    prefix: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ArtifactTypeConfig:
    name: str
    identity: dict[str, Any] = field(default_factory=dict)
    promotion: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    policy_profile: str | None = None


@dataclass(slots=True)
class EnvironmentConfig:
    name: str
    build_allowed: bool
    deploy_allowed: bool
    approvals_required: list[str] = field(default_factory=list)
    required_controls: list[str] = field(default_factory=list)
    policy_overrides: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class TeamIntegrationConfig:
    name: str
    artifact_backends: dict[str, str] = field(default_factory=dict)
    evidence_store: str | None = None