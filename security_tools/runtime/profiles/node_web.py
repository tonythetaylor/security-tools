from security_tools.runtime.models import RuntimeProfile


def node_web_profile(ports: list[int]) -> RuntimeProfile:
    preferred = [3000, 8080, 80]
    expected = preferred + [p for p in ports if p not in preferred]
    return RuntimeProfile(
        name="node_web",
        confidence=0.8,
        expected_ports=expected,
        candidate_http_ports=[p for p in expected if p in {3000, 8080, 80}] or expected,
        candidate_http_paths=["/", "/health", "/api/health"],
    )