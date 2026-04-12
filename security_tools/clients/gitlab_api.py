from __future__ import annotations

from typing import Any

import requests


class GitLabAPI:
    def __init__(
        self,
        base_url: str,
        token: str,
        verify_ssl: bool = True,
        timeout: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    @property
    def headers(self) -> dict[str, str]:
        return {
            "PRIVATE-TOKEN": self.token,
            "Content-Type": "application/json",
        }

    def post_merge_request_note(
        self,
        project_id: int,
        merge_request_iid: int,
        body: str,
    ) -> dict[str, Any]:
        url = (
            f"{self.base_url}/api/v4/projects/"
            f"{project_id}/merge_requests/{merge_request_iid}/notes"
        )

        response = requests.post(
            url,
            headers=self.headers,
            json={"body": body},
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        response.raise_for_status()
        return response.json()

    def get_merge_request(
        self,
        project_id: int,
        merge_request_iid: int,
    ) -> dict[str, Any]:
        url = (
            f"{self.base_url}/api/v4/projects/"
            f"{project_id}/merge_requests/{merge_request_iid}"
        )

        response = requests.get(
            url,
            headers=self.headers,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        response.raise_for_status()
        return response.json()