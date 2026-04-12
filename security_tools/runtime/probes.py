from __future__ import annotations

import os
import socket
import time
import urllib.error
import urllib.request

from security_tools.runtime.models import HttpCheck, PortCheck


def tcp_check(host: str, port: int, timeout: float = 2.0) -> PortCheck:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return PortCheck(
                port=port,
                status="PASS",
                detail=f"TCP connection to {host}:{port} succeeded.",
            )
    except OSError as exc:
        return PortCheck(
            port=port,
            status="FAIL",
            detail=f"TCP connection to {host}:{port} failed: {exc}",
        )


def wait_for_tcp(
    host: str,
    port: int,
    timeout_seconds: int = 30,
    interval: float = 1.0,
) -> PortCheck:
    deadline = time.time() + timeout_seconds
    last = PortCheck(
        port=port,
        status="FAIL",
        detail=f"Timed out waiting for TCP port {host}:{port}.",
    )

    while time.time() < deadline:
        check = tcp_check(host, port)
        if check.status == "PASS":
            return check
        last = check
        time.sleep(interval)

    return last


def _direct_http_opener() -> urllib.request.OpenerDirector:
    # Disable proxies for internal readiness checks.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_check(url: str, timeout: float = 3.0) -> HttpCheck:
    opener = _direct_http_opener()
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "security-tools-runtime/1.0"},
    )

    try:
        with opener.open(request, timeout=timeout) as response:
            return HttpCheck(
                url=url,
                status="PASS" if 200 <= response.status < 500 else "WARN",
                http_status=response.status,
                detail=f"HTTP responded with {response.status}.",
            )
    except urllib.error.HTTPError as exc:
        status = "PASS" if 200 <= exc.code < 500 else "FAIL"
        return HttpCheck(
            url=url,
            status=status,
            http_status=exc.code,
            detail=f"HTTP error response {exc.code}.",
        )
    except Exception as exc:
        return HttpCheck(
            url=url,
            status="FAIL",
            http_status=None,
            detail=f"HTTP request failed: {exc}",
        )


def wait_for_http(
    url: str,
    timeout_seconds: int = 30,
    interval: float = 1.0,
    request_timeout: float = 3.0,
) -> HttpCheck:
    deadline = time.time() + timeout_seconds
    last = HttpCheck(
        url=url,
        status="FAIL",
        http_status=None,
        detail=f"Timed out waiting for HTTP readiness at {url}.",
    )

    while time.time() < deadline:
        check = http_check(url, timeout=request_timeout)
        if check.status == "PASS":
            return check
        last = check
        time.sleep(interval)

    return last