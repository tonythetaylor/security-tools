from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from security_tools.control_plane.models.config import (
    ArtifactTypeConfig,
    EnvironmentConfig,
    EvidenceStoreConfig,
    RegistryAuthConfig,
    RegistryIntegrationConfig,
    TeamIntegrationConfig,
)


class ControlPlaneConfigLoader:
    def __init__(self, config_dir: str | Path) -> None:
        self.config_dir = Path(config_dir)

    def _read_yaml(self, filename: str) -> dict[str, Any]:
        path = self.config_dir / filename
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def load_control_plane(self) -> dict[str, Any]:
        return self._read_yaml("control_plane.yaml")

    def load_artifact_types(self) -> dict[str, ArtifactTypeConfig]:
        raw = self._read_yaml("artifact_types.yaml").get("artifact_types", {})
        result: dict[str, ArtifactTypeConfig] = {}

        for name, cfg in raw.items():
            result[name] = ArtifactTypeConfig(
                name=name,
                identity=cfg.get("identity", {}),
                promotion=cfg.get("promotion", {}),
                evidence=cfg.get("evidence", {}),
                policy_profile=cfg.get("policy_profile"),
            )

        return result

    def load_environments(self) -> dict[str, EnvironmentConfig]:
        raw = self._read_yaml("environments.yaml").get("environments", {})
        result: dict[str, EnvironmentConfig] = {}

        for name, cfg in raw.items():
            result[name] = EnvironmentConfig(
                name=name,
                build_allowed=cfg.get("build_allowed", False),
                deploy_allowed=cfg.get("deploy_allowed", False),
                approvals_required=cfg.get("approvals_required", []),
                required_controls=cfg.get("required_controls", []),
                policy_overrides=cfg.get("policy_overrides", {}),
            )

        return result

    def load_registries(self) -> dict[str, RegistryIntegrationConfig]:
        raw = self._read_yaml("integrations.yaml").get("registries", [])
        result: dict[str, RegistryIntegrationConfig] = {}

        for cfg in raw:
            auth_cfg = None
            if cfg.get("auth"):
                auth_cfg = RegistryAuthConfig(
                    method=cfg["auth"]["method"],
                    secret_ref=cfg["auth"].get("secret_ref"),
                )

            result[cfg["name"]] = RegistryIntegrationConfig(
                name=cfg["name"],
                type=cfg["type"],
                supports=cfg.get("supports", []),
                url=cfg.get("url"),
                verify_tls=cfg.get("verify_tls", True),
                region=cfg.get("region"),
                account_id=cfg.get("account_id"),
                repository=cfg.get("repository"),
                namespace=cfg.get("namespace"),
                auth=auth_cfg,
                metadata=cfg.get("metadata", {}),
            )

        return result

    def load_evidence_stores(self) -> dict[str, EvidenceStoreConfig]:
        raw = self._read_yaml("integrations.yaml").get("evidence_stores", [])
        result: dict[str, EvidenceStoreConfig] = {}

        for cfg in raw:
            result[cfg["name"]] = EvidenceStoreConfig(
                name=cfg["name"],
                type=cfg["type"],
                base_path=cfg.get("base_path"),
                bucket=cfg.get("bucket"),
                prefix=cfg.get("prefix"),
                metadata=cfg.get("metadata", {}),
            )

        return result

    def load_teams(self) -> dict[str, TeamIntegrationConfig]:
        raw = self._read_yaml("integrations.yaml").get("teams", [])
        result: dict[str, TeamIntegrationConfig] = {}

        for cfg in raw:
            result[cfg["name"]] = TeamIntegrationConfig(
                name=cfg["name"],
                artifact_backends=cfg.get("artifact_backends", {}),
                evidence_store=cfg.get("evidence_store"),
            )

        return result