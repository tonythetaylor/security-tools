from __future__ import annotations

from security_tools.control_plane.models.config import (
    EvidenceStoreConfig,
    RegistryIntegrationConfig,
    TeamIntegrationConfig,
)


class BackendResolver:
    def __init__(
        self,
        registries: dict[str, RegistryIntegrationConfig],
        evidence_stores: dict[str, EvidenceStoreConfig],
        teams: dict[str, TeamIntegrationConfig],
    ) -> None:
        self.registries = registries
        self.evidence_stores = evidence_stores
        self.teams = teams

    def resolve_registry(self, team_name: str, artifact_type: str) -> RegistryIntegrationConfig:
        team = self.teams.get(team_name)
        if not team:
            raise ValueError(f"Unknown team: {team_name}")

        backend_name = team.artifact_backends.get(artifact_type)
        if not backend_name:
            raise ValueError(
                f"No backend configured for artifact_type '{artifact_type}' in team '{team_name}'"
            )

        registry = self.registries.get(backend_name)
        if not registry:
            raise ValueError(f"Registry '{backend_name}' not found")

        if artifact_type not in registry.supports:
            raise ValueError(
                f"Registry '{backend_name}' does not support artifact type '{artifact_type}'"
            )

        return registry

    def resolve_evidence_store(self, team_name: str) -> EvidenceStoreConfig:
        team = self.teams.get(team_name)
        if not team:
            raise ValueError(f"Unknown team: {team_name}")

        store_name = team.evidence_store
        if not store_name:
            raise ValueError(f"No evidence store configured for team '{team_name}'")

        store = self.evidence_stores.get(store_name)
        if not store:
            raise ValueError(f"Evidence store '{store_name}' not found")

        return store