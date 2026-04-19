from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from security_tools.control_plane.evidence.store import EvidenceStore


class EvidenceService:
    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def _artifact_key(self, artifact_identity: dict[str, Any]) -> str:
        return "|".join(
            [
                artifact_identity.get("artifact_type", ""),
                artifact_identity.get("name", ""),
                artifact_identity.get("version", ""),
                artifact_identity.get("digest", ""),
                artifact_identity.get("checksum", ""),
            ]
        )

    def store_evidence_file(
        self,
        artifact_identity: dict[str, Any],
        evidence_type: str,
        file_path: str | Path,
    ) -> None:
        key = self._artifact_key(artifact_identity)

        self.store.store(
            key=key,
            name=evidence_type,
            path=str(file_path),
        )

    def store_evidence_json(
        self,
        artifact_identity: dict[str, Any],
        evidence_type: str,
        data: dict[str, Any],
    ) -> None:
        key = self._artifact_key(artifact_identity)

        tmp_path = Path(f"/tmp/{key}_{evidence_type}.json")
        tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        self.store.store(
            key=key,
            name=evidence_type,
            path=str(tmp_path),
        )