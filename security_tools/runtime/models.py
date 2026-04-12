from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

RuntimeVerdict = Literal["PASS", "WARN", "BLOCK", "OPERATIONAL_ERROR"]
ProfileName = Literal["generic", "nginx", "tomcat", "python_web", "node_web", "spring_boot"]


class RuntimeProfile(BaseModel):
    name: ProfileName = "generic"
    confidence: float = 0.0
    expected_ports: list[int] = Field(default_factory=list)
    candidate_http_ports: list[int] = Field(default_factory=list)
    candidate_http_paths: list[str] = Field(default_factory=list)
    expected_process_hints: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class PortCheck(BaseModel):
    port: int
    status: Literal["PASS", "FAIL", "WARN"]
    detail: str


class HttpCheck(BaseModel):
    url: str
    status: Literal["PASS", "FAIL", "WARN"]
    http_status: int | None = None
    detail: str = ""


class RuntimeStartup(BaseModel):
    container_started: bool = False
    container_running: bool = False
    startup_seconds: float = 0.0
    container_exit_code: int | None = None


class RuntimeReport(BaseModel):
    verdict: RuntimeVerdict
    image: str
    profile: RuntimeProfile
    startup: RuntimeStartup
    exposed_ports: list[int] = Field(default_factory=list)
    listening_ports: list[int] = Field(default_factory=list)
    port_checks: list[PortCheck] = Field(default_factory=list)
    http_checks: list[HttpCheck] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    logs_tail: str = ""
    metadata: dict = Field(default_factory=dict)