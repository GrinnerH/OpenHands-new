from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict
import requests


@dataclass
class CPGQLSClient:
    endpoint: str

    def __post_init__(self) -> None:
        if not self.endpoint.startswith("http://") and not self.endpoint.startswith("https://"):
            self.endpoint = f"http://{self.endpoint}"
        self.query_url = self.endpoint.rstrip("/") + "/api/cpgqls/query"

    def execute(self, query: str) -> Dict[str, Any]:
        payload = {"query": query}
        response = requests.post(
            self.query_url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
        return response.json()


def import_code_query(path: str, project_name: str) -> str:
    escaped_path = path.replace("\\", "\\\\")
    escaped_project = project_name.replace("\\", "\\\\")
    return f'importCode(inputPath="{escaped_path}", projectName="{escaped_project}")'


def delete_query(project_name: str) -> str:
    escaped_project = project_name.replace("\\", "\\\\")
    return f'delete("{escaped_project}")'
