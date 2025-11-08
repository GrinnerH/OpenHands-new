from __future__ import annotations

import json
import time
import subprocess
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .cpgqls_client import CPGQLSClient, import_code_query, delete_query


class QueryStatus(Enum):
    SUCCESS = "success"
    EMPTY = "empty"
    ERROR = "error"


class JoernManager:
    """Thin wrapper around a Joern server instance."""

    def __init__(self, port: int, compose_file: str, repo_root: str) -> None:
        self.port = port
        self.compose_file = compose_file
        self.service_name = f"joern_server_{port}"
        self.client = CPGQLSClient(f"localhost:{port}")
        self.repo_root = Path(repo_root)
        self._file_cache: Dict[Path, List[str]] = {}

    # ------------------------------------------------------------------ server
    def check_health(self) -> bool:
        try:
            status, _ = self.execute("val x = 1")
            return status == QueryStatus.SUCCESS
        except Exception:
            return False

    def recreate(self) -> bool:
        """Force recreate the joern container when it becomes unhealthy."""
        try:
            time.sleep(1)
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "-f",
                    self.compose_file,
                    "up",
                    "-d",
                    "--force-recreate",
                    self.service_name,
                ],
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            print(f"[joern] failed to recreate {self.service_name}: {exc}")
            return False

        deadline = time.time() + 180
        while time.time() < deadline:
            if self.check_health():
                return True
            time.sleep(5)
        return False

    # ----------------------------------------------------------------- queries
    def execute(self, query: str) -> Tuple[QueryStatus, str]:
        result = self.client.execute(query)
        stdout = result.get("stdout", "")
        if "ConsoleException" in stdout or "Error" in stdout:
            return QueryStatus.ERROR, stdout
        if "List()" in stdout or "= empty iterator" in stdout:
            return QueryStatus.EMPTY, stdout
        return QueryStatus.SUCCESS, stdout

    def run_reachable_query(
        self, query: str
    ) -> Tuple[QueryStatus, List[List[Dict[str, Any]]], str]:
        status, stdout = self.execute(query)
        if status != QueryStatus.SUCCESS:
            return status, [], stdout

        try:
            flows = self._parse_path_output(stdout)
        except ValueError as exc:
            return QueryStatus.ERROR, [], f"Failed to parse Joern output: {exc}\n{stdout}"
        return status, flows, stdout

    # ------------------------------------------------------------ import/delete
    def load_project(self, folder_path: str) -> QueryStatus:
        query = import_code_query(folder_path, folder_path)
        status, stdout = self.execute(query)
        if status == QueryStatus.ERROR:
            raise RuntimeError(f"Failed to import code: {stdout}")
        return status

    def delete_project(self, project_name: str) -> None:
        query = delete_query(project_name)
        self.execute(query)

    # ----------------------------------------------------------------- helpers
    def _parse_path_output(self, stdout: str) -> List[List[Dict[str, Any]]]:
        """
        Convert Joern's reachableByFlows pretty JSON output into Python objects.
        """
        # Joern prints `resXX: List[List[Map[String,Any]]] =` on the first line.
        if "\n" not in stdout:
            raise ValueError("unexpected Joern output format")
        json_blob = stdout.split("\n", 1)[1].strip()

        # Drop potential trailing summary lines produced by the console.
        if json_blob.endswith("\n"):
            json_blob = json_blob.rstrip()
        if not json_blob.startswith("["):
            # Sometimes Joern prints each element separated by newlines without []
            json_blob = "[" + json_blob.rsplit("\n", 2)[0] + "]"

        flows = json.loads(json_blob)
        parsed: List[List[Dict[str, Any]]] = []
        for flow in flows:
            nodes: List[Dict[str, Any]] = []
            for element in flow:
                line_no = element.get("line_number")
                file_name = element.get("file")
                if file_name and isinstance(line_no, int):
                    code = self._read_line(Path(file_name), line_no)
                    if code is not None:
                        element["line_code"] = code
                nodes.append(element)
            parsed.append(nodes)
        return parsed

    def _read_line(self, rel_path: Path, line_no: int) -> Optional[str]:
        full_path = (self.repo_root / rel_path).resolve()
        if full_path not in self._file_cache:
            if not full_path.exists():
                return None
            self._file_cache[full_path] = full_path.read_text().splitlines()
        lines = self._file_cache[full_path]
        if 1 <= line_no <= len(lines):
            return lines[line_no - 1]
        return None
