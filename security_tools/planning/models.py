from __future__ import annotations

from pydantic import BaseModel, Field


class StackDetection(BaseModel):
    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    repo_types: list[str] = Field(default_factory=list)

    has_dockerfile: bool = False
    has_runtime_contract: bool = False
    has_kubernetes: bool = False
    has_helm: bool = False
    has_terraform: bool = False
    has_ansible: bool = False
    has_compose: bool = False

    deploy_targets: list[str] = Field(default_factory=list)
    service_type: str = "unknown"


class ScanPlan(BaseModel):
    detected: StackDetection
    jobs: list[str] = Field(default_factory=list)