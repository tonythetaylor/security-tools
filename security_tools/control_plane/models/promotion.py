from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class PromotionRecord:
    artifact_digest: str
    source_environment: str
    target_environment: str
    requested_by: str | None = None
    approved_by: list[str] = field(default_factory=list)
    status: str = "requested"
    policy_snapshot: dict[str, Any] = field(default_factory=dict)
    decision_reason: str | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
