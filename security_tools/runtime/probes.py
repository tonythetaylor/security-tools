from __future__ import annotations

import socket
import time
import urllib.error
import urllib.request

from security_tools.runtime.models import HttpCheck, PortCheck


def tcp_check(host: str, port: int, timeout: float = 2.0) -> PortCheck:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            return PortCheck(port=port, status="PASS", detail="Port is reachable.")
        return PortCheck(port=port, status="FAIL", detail=f"TCP connect_ex returned {result}.")
    finally:
        sock.close()


def wait_for_tcp(host: str, port: int, timeout_seconds: int = 30, interval: float = 1.0) -> PortCheck:
    deadline = time.time() + timeout_seconds
    last = PortCheck(port=port, status="FAIL", detail="Timed out waiting for TCP port.")
    while time.time() < deadline:
        check = tcp_check(host, port)
        if check.status == "PASS":
            return check
        last = check
        time.sleep(interval)
    return last


def http_check(url: str, timeout: float = 3.0) -> HttpCheck:
    request = urllib.request.Request(url, headers={"User-Agent": "security-tools-runtime/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
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
            detail=str(exc),
        )