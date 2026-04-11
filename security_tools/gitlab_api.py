from __future__ import annotations

import requests


class GitLabAPI:
    def __init__(self, base_url: str, token: str, verify_ssl: bool = False) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"PRIVATE-TOKEN": token})
        self.verify_ssl = verify_ssl

    def post_merge_request_note(self, project_id: int, merge_request_iid: int, body: str) -> dict:
        response = self.session.post(
            f"{self.base_url}/api/v4/projects/{project_id}/merge_requests/{merge_request_iid}/notes",
            data={"body": body},
            verify=self.verify_ssl,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()
