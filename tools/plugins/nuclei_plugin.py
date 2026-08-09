"""Nuclei plugin tool wrapper for dynamic ToolFactory loading."""

from typing import Dict, Any, List
import os
from pathlib import Path

try:
    from red_agent.tools.tool_factory import BaseTool
    from red_agent.tools.nuclei_scanner import get_nuclei_scanner, ScanConfig, TemplateSeverity
except ImportError:
    from tools.tool_factory import BaseTool
    from tools.nuclei_scanner import get_nuclei_scanner, ScanConfig, TemplateSeverity


class NucleiTool(BaseTool):
    """Template-based web vulnerability scanning via Nuclei."""

    def __init__(self):
        super().__init__("nuclei", timeout=240, max_retries=0)
        local_nuclei = Path(__file__).resolve().parents[1] / "bin" / "nuclei.exe"
        if local_nuclei.exists():
            os.environ.setdefault("REDAGENT_NUCLEI_PATH", str(local_nuclei))
        self.scanner = get_nuclei_scanner()

    def _check_availability(self):
        # Availability is checked by the scanner itself.
        return

    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target") or params.get("url")
        if not target:
            return {
                "stdout": "",
                "stderr": "target or url is required",
                "return_code": 1,
                "status": "error",
                "error_message": "Missing target parameter",
                "execution_time": 0,
                "retries_used": 0,
            }

        severity_names: List[str] = params.get("severity", []) or []
        severities: List[TemplateSeverity] = []
        for name in severity_names:
            try:
                severities.append(TemplateSeverity(str(name).lower()))
            except ValueError:
                continue

        config = ScanConfig(
            targets=[str(target)],
            template_tags=params.get("tags", []) or [],
            severity_filter=severities,
            timeout=int(params.get("timeout_minutes", 5)),
            retries=int(params.get("retries", 1)),
            rate_limit=int(params.get("rate_limit", 100)),
            bulk_size=int(params.get("bulk_size", 25)),
            concurrency=int(params.get("concurrency", 25)),
            headless=bool(params.get("headless", False)),
            interactsh=bool(params.get("interactsh", True)),
        )

        results = self.scanner.scan_sync(config)
        findings = self.scanner.convert_to_findings(results)
        stats = self.scanner.get_statistics(results)

        return {
            "stdout": (
                f"Nuclei completed for {target}. "
                f"Findings={len(findings)}, BySeverity={stats.get('by_severity', {})}"
            ),
            "stderr": "" if findings is not None else "Nuclei scan returned no parseable results",
            "return_code": 0,
            "status": "success",
            "error_message": None,
            "execution_time": 0,
            "retries_used": 0,
            "metadata": {
                "findings": findings,
                "statistics": stats,
            },
        }


def register_tools() -> Dict[str, BaseTool]:
    """Plugin contract consumed by ToolFactory."""
    return {"nuclei": NucleiTool()}
