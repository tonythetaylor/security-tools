from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class PromotionExecutionResult:
    success: bool
    backend_name: str
    backend_type: str
    source_ref: str | None = None
    target_ref: str | None = None
    promoted_identity: str | None = None
    action: str | None = None
    dry_run: bool = False
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None