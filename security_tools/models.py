from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class NormalizedFinding:
    source: str
    finding_type: str
    severity: str
    title: str
    description: str = ""
    location: Optional[str] = None
    recommendation: str = ""
    compliance_refs: list[str] | None = None

    def to_dict(self) -> dict:
        return asdict(self)
