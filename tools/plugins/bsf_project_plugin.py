"""Adapters for analytics tooling from extracted BSF-master project."""

from pathlib import Path
from typing import Any, Dict, Optional
import re
import time

try:
    from red_agent.tools.tool_factory import BaseTool
except ImportError:
    from tools.tool_factory import BaseTool


EDGE_RE = re.compile(r'\"(\d+)\"->{(.*)}')


def _find_bsf_root() -> Optional[Path]:
    here = Path(__file__).resolve()
    workspace_root = here.parents[3]
    candidate = workspace_root / "BSF-master"
    return candidate if candidate.exists() else None


def _parse_graph_file(file_path: Path) -> Dict[str, int]:
    nodes = set()
    edges = 0
    with file_path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = EDGE_RE.match(line.strip())
            if not m:
                continue
            src = int(m.group(1))
            nodes.add(src)
            neighbors = m.group(2).replace('"', "").split(" ")
            for n in neighbors:
                if not n:
                    continue
                nodes.add(int(n))
                edges += 1
    return {"nodes": len(nodes), "edges": edges}


class BSFSimulationOverviewTool(BaseTool):
    """Summarize BSF simulation dump folders and available snapshots."""

    def __init__(self):
        super().__init__("bsf_simulation_overview", timeout=30, max_retries=0)

    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        root = _find_bsf_root()
        if root is None:
            return {
                "stdout": "",
                "stderr": "BSF-master not found in workspace root",
                "return_code": 1,
                "status": "error",
                "error_message": "Missing project folder",
                "execution_time": 0,
                "retries_used": 0,
            }

        start = time.time()
        dumps_root = root / "simulations" / "dumps"
        graphs = list(dumps_root.glob("**/graphs/*")) if dumps_root.exists() else []
        crawlers = list(dumps_root.glob("**/crawlers/*")) if dumps_root.exists() else []
        sensors = list(dumps_root.glob("**/sensors/*")) if dumps_root.exists() else []

        elapsed = time.time() - start
        return {
            "stdout": (
                f"BSF overview: graph_files={len(graphs)}, "
                f"crawler_files={len(crawlers)}, sensor_files={len(sensors)}"
            ),
            "stderr": "",
            "return_code": 0,
            "status": "success",
            "error_message": None,
            "execution_time": elapsed,
            "retries_used": 0,
            "metadata": {
                "graph_files": [str(p) for p in graphs[:100]],
                "crawler_files": [str(p) for p in crawlers[:100]],
                "sensor_files": [str(p) for p in sensors[:100]],
            },
        }


class BSFGraphSummaryTool(BaseTool):
    """Compute node/edge summary statistics for a BSF graph snapshot file."""

    def __init__(self):
        super().__init__("bsf_graph_summary", timeout=30, max_retries=0)

    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        graph_file = str(params.get("graph_file", "")).strip()
        if not graph_file:
            return {
                "stdout": "",
                "stderr": "graph_file is required",
                "return_code": 1,
                "status": "error",
                "error_message": "Missing parameter",
                "execution_time": 0,
                "retries_used": 0,
            }

        root = _find_bsf_root()
        if root is None:
            return {
                "stdout": "",
                "stderr": "BSF-master not found in workspace root",
                "return_code": 1,
                "status": "error",
                "error_message": "Missing project folder",
                "execution_time": 0,
                "retries_used": 0,
            }

        file_path = Path(graph_file)
        if not file_path.is_absolute():
            file_path = root / file_path

        if not file_path.exists() or not file_path.is_file():
            return {
                "stdout": "",
                "stderr": f"graph_file not found: {file_path}",
                "return_code": 1,
                "status": "error",
                "error_message": "File not found",
                "execution_time": 0,
                "retries_used": 0,
            }

        start = time.time()
        stats = _parse_graph_file(file_path)
        elapsed = time.time() - start

        return {
            "stdout": f"Graph summary for {file_path.name}: nodes={stats['nodes']}, edges={stats['edges']}",
            "stderr": "",
            "return_code": 0,
            "status": "success",
            "error_message": None,
            "execution_time": elapsed,
            "retries_used": 0,
            "metadata": stats,
        }


def register_tools() -> Dict[str, BaseTool]:
    return {
        "bsf_simulation_overview": BSFSimulationOverviewTool(),
        "bsf_graph_summary": BSFGraphSummaryTool(),
    }
