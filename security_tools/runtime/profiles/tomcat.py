from security_tools.runtime.models import RuntimeProfile


def tomcat_profile(ports: list[int]) -> RuntimeProfile:
    preferred = [8080, 8443]
    expected = preferred + [p for p in ports if p not in preferred]
    return RuntimeProfile(
        name="tomcat",
        confidence=0.95,
        expected_ports=expected,
        candidate_http_ports=[p for p in expected if p in {8080, 8443}] or expected,
        candidate_http_paths=["/", "/manager/html"],
    )