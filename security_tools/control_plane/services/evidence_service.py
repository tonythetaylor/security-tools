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
                str(artifact_identity.get("artifact_type") or ""),
                str(artifact_identity.get("name") or ""),
                str(artifact_identity.get("version") or ""),
                str(artifact_identity.get("digest") or ""),
                str(artifact_identity.get("checksum") or ""),
            ]
        )

    def store_evidence_file(
        self,
        artifact_identity: dict[str, Any],
        evidence_type: str,
        file_path: str | Path,
    ) -> None:
        key = self._artifact_key(artifact_identity)
        self.store.put_file(
            artifact_digest=key,
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
        self.store.put_bytes(
            artifact_digest=key,
            name=f"{evidence_type}.json",
            data=json.dumps(data, indent=2).encode("utf-8"),
        )