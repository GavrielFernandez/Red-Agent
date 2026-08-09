"""Cyber range inventory plugin for safe, local-only range discovery."""

from __future__ import annotations

from typing import Any, Dict, List
from pathlib import Path
import json
import time

try:
    from red_agent.tools.tool_factory import BaseTool
except ImportError:
    from tools.tool_factory import BaseTool


class CyberRangeTool(BaseTool):
    """Inventory local cyber range assets and scenario manifests."""

    def __init__(self):
        super().__init__("cyber_range", timeout=30, max_retries=0)

    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        range_path = str(params.get("range_path", "cyber_range")).strip() or "cyber_range"
        root = Path(range_path)
        if not root.is_absolute():
            root = Path(__file__).resolve().parents[2] / root

        start = time.time()
        manifests: List[str] = []
        compose_files: List[str] = []
        dockerfiles: List[str] = []
        notes: List[str] = []
        services: List[str] = []
        scenarios: List[Dict[str, str]] = []

        if root.exists() and root.is_dir():
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                lowered = path.name.lower()
                if lowered in {"docker-compose.yml", "docker-compose.yaml"}:
                    compose_files.append(str(path))
                    services.extend(self._extract_compose_services(path))
                elif lowered == "dockerfile":
                    dockerfiles.append(str(path))
                elif lowered.endswith((".json", ".yaml", ".yml")):
                    manifests.append(str(path))
                    scenario = self._extract_scenario_metadata(path)
                    if scenario:
                        scenarios.append(scenario)
                elif lowered.endswith((".md", ".txt")):
                    notes.append(str(path))
        else:
            notes.append(f"Range path not found: {root}")

        summary = {
            "range_path": str(root),
            "manifests": len(manifests),
            "compose_files": len(compose_files),
            "dockerfiles": len(dockerfiles),
            "services": len(services),
            "scenarios": len(scenarios),
            "notes": len(notes),
            "status": "inventory_complete" if root.exists() else "missing",
        }

        elapsed = time.time() - start
        return {
            "stdout": json.dumps(summary, indent=2),
            "stderr": "",
            "return_code": 0,
            "status": "success",
            "error_message": None,
            "execution_time": elapsed,
            "retries_used": 0,
            "metadata": {
                "summary": summary,
                "compose_files": compose_files[:50],
                "dockerfiles": dockerfiles[:50],
                "manifests": manifests[:50],
                "services": sorted(set(services))[:50],
                "scenarios": scenarios[:50],
                "notes": notes[:50],
            },
        }

    def _extract_compose_services(self, compose_path: Path) -> List[str]:
        services: List[str] = []
        in_services = False
        with compose_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.rstrip("\n")
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped == "services:":
                    in_services = True
                    continue
                if in_services:
                    if not line.startswith("  "):
                        in_services = False
                        continue
                    if line.startswith("  ") and not line.startswith("    ") and stripped.endswith(":"):
                        services.append(stripped[:-1])
        return services

    def _extract_scenario_metadata(self, manifest_path: Path) -> Dict[str, str]:
        data: Dict[str, str] = {}
        try:
            with manifest_path.open("r", encoding="utf-8") as handle:
                for raw_line in handle:
                    stripped = raw_line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if stripped.startswith("name:") and "name" not in data:
                        data["name"] = stripped.split(":", 1)[1].strip()
                    elif stripped.startswith("objective:") and "objective" not in data:
                        data["objective"] = stripped.split(":", 1)[1].strip()
                    elif stripped.startswith("version:") and "version" not in data:
                        data["version"] = stripped.split(":", 1)[1].strip()
        except OSError:
            return {}
        if data:
            data["path"] = str(manifest_path)
        return data


def register_tools() -> Dict[str, BaseTool]:
    return {"cyber_range": CyberRangeTool()}
