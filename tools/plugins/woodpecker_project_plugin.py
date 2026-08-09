"""Adapters for tools exposed by the extracted woodpecker-main project."""

from pathlib import Path
from typing import Any, Dict, Optional
import json
import subprocess
import time
import shutil

try:
    from red_agent.tools.tool_factory import BaseTool
except ImportError:
    from tools.tool_factory import BaseTool


def _find_woodpecker_root() -> Optional[Path]:
    here = Path(__file__).resolve()
    workspace_root = here.parents[3]
    candidate = workspace_root / "woodpecker-main"
    return candidate if candidate.exists() else None


def _resolve_go_binary() -> str:
    """Resolve Go executable even when PATH is stale in current shell."""
    path_go = shutil.which("go")
    if path_go:
        return path_go
    win_default = Path("C:/Program Files/Go/bin/go.exe")
    if win_default.exists():
        return str(win_default)
    return "go"


class WoodpeckerExperimentsTool(BaseTool):
    """List available Woodpecker experiments from the extracted project."""

    def __init__(self):
        super().__init__("woodpecker_experiments", timeout=420, max_retries=0)

    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        root = _find_woodpecker_root()
        if root is None:
            return {
                "stdout": "",
                "stderr": "woodpecker-main not found in workspace root",
                "return_code": 1,
                "status": "error",
                "error_message": "Missing project folder",
                "execution_time": 0,
                "retries_used": 0,
            }

        cmd = [_resolve_go_binary(), "run", "./cmd/woodpecker", "experiment"]
        start = time.time()
        try:
            result = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True, timeout=self.timeout)
            elapsed = time.time() - start
            return {
                "stdout": result.stdout[:8000],
                "stderr": result.stderr[:2000],
                "return_code": result.returncode,
                "status": "success" if result.returncode == 0 else "failed",
                "error_message": None,
                "execution_time": elapsed,
                "retries_used": 0,
            }
        except Exception as exc:
            elapsed = time.time() - start
            return {
                "stdout": "",
                "stderr": str(exc),
                "return_code": 1,
                "status": "error",
                "error_message": str(exc),
                "execution_time": elapsed,
                "retries_used": 0,
            }


class WoodpeckerSnippetTool(BaseTool):
    """Generate a Woodpecker experiment snippet for a given experiment type."""

    def __init__(self):
        super().__init__("woodpecker_snippet", timeout=420, max_retries=0)

    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        experiment_type = str(params.get("experiment_type", "")).strip()
        if not experiment_type:
            return {
                "stdout": "",
                "stderr": "experiment_type is required",
                "return_code": 1,
                "status": "error",
                "error_message": "Missing parameter",
                "execution_time": 0,
                "retries_used": 0,
            }

        root = _find_woodpecker_root()
        if root is None:
            return {
                "stdout": "",
                "stderr": "woodpecker-main not found in workspace root",
                "return_code": 1,
                "status": "error",
                "error_message": "Missing project folder",
                "execution_time": 0,
                "retries_used": 0,
            }

        cmd = [_resolve_go_binary(), "run", "./cmd/woodpecker", "experiment", "snippet", "-e", experiment_type]
        start = time.time()
        try:
            result = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True, timeout=self.timeout)
            elapsed = time.time() - start
            return {
                "stdout": result.stdout[:12000],
                "stderr": result.stderr[:2000],
                "return_code": result.returncode,
                "status": "success" if result.returncode == 0 else "failed",
                "error_message": None,
                "execution_time": elapsed,
                "retries_used": 0,
            }
        except Exception as exc:
            elapsed = time.time() - start
            return {
                "stdout": "",
                "stderr": str(exc),
                "return_code": 1,
                "status": "error",
                "error_message": str(exc),
                "execution_time": elapsed,
                "retries_used": 0,
            }


class WoodpeckerVerifyTool(BaseTool):
    """Run Woodpecker verification on an experiment file and emit structured output."""

    def __init__(self):
        super().__init__("woodpecker_verify", timeout=600, max_retries=0)

    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        experiment_file = str(params.get("experiment_file", "")).strip()
        if not experiment_file:
            return {
                "stdout": "",
                "stderr": "experiment_file is required",
                "return_code": 1,
                "status": "error",
                "error_message": "Missing parameter",
                "execution_time": 0,
                "retries_used": 0,
            }

        root = _find_woodpecker_root()
        if root is None:
            return {
                "stdout": "",
                "stderr": "woodpecker-main not found in workspace root",
                "return_code": 1,
                "status": "error",
                "error_message": "Missing project folder",
                "execution_time": 0,
                "retries_used": 0,
            }

        exp_path = Path(experiment_file)
        if not exp_path.is_absolute():
            exp_path = root / exp_path

        cmd = [
            _resolve_go_binary(),
            "run",
            "./cmd/woodpecker",
            "experiment",
            "verify",
            "-f",
            str(exp_path),
            "-o",
            "json",
        ]
        start = time.time()
        try:
            result = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True, timeout=self.timeout)
            elapsed = time.time() - start

            parsed = None
            if result.stdout.strip().startswith("{"):
                try:
                    parsed = json.loads(result.stdout)
                except json.JSONDecodeError:
                    parsed = None

            return {
                "stdout": result.stdout[:12000],
                "stderr": result.stderr[:2000],
                "return_code": result.returncode,
                "status": "success" if result.returncode == 0 else "failed",
                "error_message": None,
                "execution_time": elapsed,
                "retries_used": 0,
                "metadata": {"parsed": parsed},
            }
        except Exception as exc:
            elapsed = time.time() - start
            return {
                "stdout": "",
                "stderr": str(exc),
                "return_code": 1,
                "status": "error",
                "error_message": str(exc),
                "execution_time": elapsed,
                "retries_used": 0,
            }


def register_tools() -> Dict[str, BaseTool]:
    return {
        "woodpecker_experiments": WoodpeckerExperimentsTool(),
        "woodpecker_snippet": WoodpeckerSnippetTool(),
        "woodpecker_verify": WoodpeckerVerifyTool(),
    }
