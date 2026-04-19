from __future__ import annotations

from security_tools.control_plane.evidence.generic_repo import GenericRepositoryEvidenceStore
from security_tools.control_plane.evidence.object_store import ObjectStoreEvidenceStore
from security_tools.control_plane.models.config import EvidenceStoreConfig, RegistryIntegrationConfig
from security_tools.control_plane.registry.artifactory import ArtifactoryRegistryAdapter
from security_tools.control_plane.registry.harbor import HarborRegistryAdapter
from security_tools.control_plane.registry.oci import OCIRegistryAdapter


class RegistryFactory:
    @staticmethod
    def create(config: RegistryIntegrationConfig):
        if config.type == "harbor":
            return HarborRegistryAdapter(
                harbor_url=config.url or "",
                project=config.namespace or config.repository or config.name,
            )

        if config.type == "artifactory":
            return ArtifactoryRegistryAdapter(
                base_url=config.url or "",
                repository=config.repository or config.name,
            )

        if config.type in {"oci", "aws_ecr", "azure_acr", "gcp_artifact_registry", "nexus"}:
            return OCIRegistryAdapter(registry_url=config.url or "")

        raise ValueError(f"Unsupported registry type: {config.type}")


class EvidenceStoreFactory:
    @staticmethod
    def create(config: EvidenceStoreConfig):
        if config.type in {"filesystem", "s3", "azure_blob", "gcs"}:
            return ObjectStoreEvidenceStore(
                bucket_name=config.bucket or config.base_path or ""
            )

        if config.type in {"generic_repo", "nexus_generic"}:
            return GenericRepositoryEvidenceStore(
                base_url=config.metadata.get("url", ""),
                repository=config.metadata.get("repository", ""),
            )

        raise ValueError(f"Unsupported evidence store type: {config.type}")