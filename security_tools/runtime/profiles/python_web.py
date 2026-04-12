from security_tools.runtime.models import RuntimeProfile


def python_web_profile(ports: list[int]) -> RuntimeProfile:
    preferred = [8000, 5000, 8080]
    expected = preferred + [p for p in ports if p not in preferred]
    return RuntimeProfile(
        name="python_web",
        confidence=0.8,
        expected_ports=expected,
        candidate_http_ports=[p for p in expected if p in {8000, 5000, 8080}] or expected,
        candidate_http_paths=["/", "/health", "/docs", "/openapi.json"],
    )