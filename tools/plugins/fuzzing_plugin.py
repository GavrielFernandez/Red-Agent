"""Safe fuzzing tool plugin for sandboxed assessment targets."""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urljoin
import hashlib
import json
import random
import string
import time

try:
    from red_agent.tools.tool_factory import BaseTool
except ImportError:
    from tools.tool_factory import BaseTool


class FuzzingHarnessTool(BaseTool):
    """Sandboxed fuzzing harness for authorized targets."""

    def __init__(self):
        super().__init__("fuzzing_harness", timeout=120, max_retries=0)

    def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        target = str(params.get("target", "")).strip()
        seed = str(params.get("seed", "redagent")).strip() or "redagent"
        iterations = int(params.get("iterations", 25))
        payload_mode = str(params.get("payload_mode", "balanced")).strip().lower()

        if not target.startswith(("http://", "https://")):
            return {
                "stdout": "",
                "stderr": "target must be an http(s) URL",
                "return_code": 1,
                "status": "error",
                "error_message": "Invalid target",
                "execution_time": 0,
                "retries_used": 0,
            }

        iterations = max(1, min(200, iterations))
        rng = random.Random(seed)
        base_paths = ["/", "/health", "/api/status", "/robots.txt", "/login", "/search"]
        payloads = self._build_payloads(payload_mode, rng)

        findings: List[Dict[str, Any]] = []
        corpus = []
        start = time.time()
        for index in range(iterations):
            base = base_paths[index % len(base_paths)]
            payload = rng.choice(payloads)
            mutated = self._mutate_payload(payload, rng, index)
            probe = urljoin(target.rstrip("/") + "/", base.lstrip("/"))
            fingerprint = hashlib.sha256(f"{probe}|{mutated}".encode("utf-8")).hexdigest()[:16]
            corpus.append({
                "probe": probe,
                "payload": mutated,
                "fingerprint": fingerprint,
            })

            if any(token in mutated.lower() for token in ["<script", "../", "${", "' or '"]):
                findings.append({
                    "id": f"fuzz-{index + 1}",
                    "category": "input_surface",
                    "probe": probe,
                    "sample": mutated,
                    "severity": "info" if payload_mode == "safe" else "medium",
                    "note": "Potentially interesting input shape for further manual validation",
                })

        elapsed = time.time() - start
        summary = {
            "target": target,
            "seed": seed,
            "iterations": iterations,
            "payload_mode": payload_mode,
            "generated_probes": len(corpus),
            "interesting_cases": len(findings),
            "status": "sandboxed",
        }

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
                "findings": findings,
                "corpus": corpus[:100],
            },
        }

    def _build_payloads(self, payload_mode: str, rng: random.Random) -> List[str]:
        safe_payloads = [
            "test",
            "123",
            "alpha",
            "sample-input",
            "probe",
        ]
        balanced_payloads = safe_payloads + [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../etc/passwd",
            "\" onmouseover=alert(1) \"",
        ]
        aggressive_payloads = balanced_payloads + [
            "../../../../windows/win.ini",
            "${7*7}",
            "%0d%0aX-Injected: yes",
        ]

        if payload_mode == "safe":
            return safe_payloads
        if payload_mode == "aggressive":
            return aggressive_payloads
        return balanced_payloads

    def _mutate_payload(self, payload: str, rng: random.Random, index: int) -> str:
        suffix = "".join(rng.choice(string.ascii_lowercase) for _ in range(3))
        if index % 3 == 0:
            return f"{payload}{suffix}"
        if index % 3 == 1:
            return f"{suffix}{payload}"
        return f"{payload}:{suffix}"


def register_tools() -> Dict[str, BaseTool]:
    return {"fuzzing_harness": FuzzingHarnessTool()}
