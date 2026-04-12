from security_tools.runtime.models import RuntimeProfile


def generic_profile(ports: list[int]) -> RuntimeProfile:
    http_ports = [p for p in ports if p in {80, 443, 3000, 5000, 8000, 8080, 8443}] or ports[:3]
    return RuntimeProfile(
        name="generic",
        confidence=0.2,
        expected_ports=ports,
        candidate_http_ports=http_ports,
        candidate_http_paths=["/", "/health", "/ready", "/healthz", "/actuator/health"],
    )