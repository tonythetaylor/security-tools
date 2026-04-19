from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class PromotionPolicy:
    environment: str
    require: list[str] = field(default_factory=list)
    limits: dict[str, int] = field(default_factory=dict)
    approvals: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PolicyDecision:
    eligible: bool
    environment: str
    reasons: list[str] = field(default_factory=list)
    evaluated_requirements: dict[str, bool] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
