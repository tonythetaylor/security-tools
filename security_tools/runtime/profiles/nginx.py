from security_tools.runtime.models import RuntimeProfile


def nginx_profile(ports: list[int]) -> RuntimeProfile:
    preferred = [80, 443]
    expected = preferred + [p for p in ports if p not in preferred]
    return RuntimeProfile(
        name="nginx",
        confidence=0.95,
        expected_ports=expected,
        candidate_http_ports=[p for p in expected if p in {80, 443}] or expected,
        candidate_http_paths=["/", "/index.html"],
    )