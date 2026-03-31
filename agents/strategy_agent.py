"""
Strategy Agent - Assessment Planning Specialist
===============================================

Creates and revises assessment strategy based on reconnaissance intel,
discovered vulnerabilities, and execution outcomes.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List

from .base_agent import BaseAgent, AgentCapability, TaskResult

logger = logging.getLogger(__name__)


class StrategyAgent(BaseAgent):
    """Plans and iterates test strategy for the swarm."""

    def __init__(self, llm_client: Any = None, **kwargs):
        super().__init__(name="StrategyAgent", llm_client=llm_client, **kwargs)

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="strategy_planning",
                description="Build and refine assessment strategy",
                input_types=["target", "intel", "vulnerabilities", "failures"],
                output_types=["strategy", "priorities", "next_actions"]
            )
        ]

    async def execute_task(self, task: Dict[str, Any]) -> TaskResult:
        task_type = task.get("type", "")

        try:
            if task_type == "build_strategy":
                strategy = await self._build_strategy(task)
            elif task_type == "replan_strategy":
                strategy = await self._replan_strategy(task)
            else:
                return TaskResult(
                    task_id=task.get("id", ""),
                    success=False,
                    error=f"Unknown task type: {task_type}"
                )

            self.update_knowledge(task.get("id", f"strategy_{datetime.now().isoformat()}"), strategy)
            return TaskResult(task_id=task.get("id", ""), success=True, data=strategy)
        except Exception as e:
            logger.error(f"StrategyAgent task failed: {e}")
            return TaskResult(task_id=task.get("id", ""), success=False, error=str(e))

    async def _build_strategy(self, task: Dict[str, Any]) -> Dict[str, Any]:
        target = task.get("target", "")
        recon = task.get("recon", {})
        vulnerabilities = task.get("vulnerabilities", [])
        objectives = task.get("objectives", [])

        if self.llm_client:
            prompt = (
                "You are a defensive security assessment strategy assistant. "
                "Create a concise JSON strategy only.\n"
                f"Target: {target}\n"
                f"Objectives: {objectives}\n"
                f"Recon: {json.dumps(recon)[:2000]}\n"
                f"Vulnerabilities: {json.dumps(vulnerabilities)[:2000]}\n"
                "Required JSON keys: priorities (list), rationale (list), next_actions (list), "
                "stop_conditions (list), confidence (number 0-1)."
            )
            try:
                raw = await self.llm_client.generate(prompt)
                return {
                    "source": "llm",
                    "generated_at": datetime.now().isoformat(),
                    "raw": raw
                }
            except Exception as e:
                logger.warning(f"LLM strategy generation failed, using heuristic strategy: {e}")

        return self._heuristic_strategy(target, vulnerabilities, objectives)

    async def _replan_strategy(self, task: Dict[str, Any]) -> Dict[str, Any]:
        failures = task.get("failures", [])
        previous = task.get("previous_strategy", {})
        vulnerabilities = task.get("vulnerabilities", [])

        strategy = self._heuristic_strategy(
            target=task.get("target", ""),
            vulnerabilities=vulnerabilities,
            objectives=task.get("objectives", [])
        )

        strategy["replan"] = {
            "trigger": "execution_failures",
            "failed_attempts": len(failures),
            "adjustments": [
                "Reduce parallel exploit attempts for noisy vectors",
                "Prioritize evidence quality and reproducibility",
                "Defer low-confidence checks until stronger signals emerge"
            ],
            "previous_strategy_available": bool(previous)
        }
        return strategy

    def _heuristic_strategy(
        self,
        target: str,
        vulnerabilities: List[Dict[str, Any]],
        objectives: List[str]
    ) -> Dict[str, Any]:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        ranked = sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(str(v.get("severity", "low")).lower(), 4)
        )

        top_vectors = []
        for vuln in ranked[:5]:
            vector = vuln.get("type") or vuln.get("attack") or "unknown"
            top_vectors.append(vector)

        return {
            "source": "heuristic",
            "generated_at": datetime.now().isoformat(),
            "target": target,
            "objectives": objectives or ["identify_vulnerabilities", "assess_impact"],
            "priorities": top_vectors,
            "rationale": [
                "Prioritize by severity and exploitability",
                "Prefer deterministic checks before expensive operations"
            ],
            "next_actions": [
                "Validate highest-priority vectors with reproducible evidence",
                "Escalate only when findings are corroborated"
            ],
            "stop_conditions": [
                "time_budget_exceeded",
                "max_retries_reached",
                "no_new_evidence"
            ],
            "confidence": 0.7 if top_vectors else 0.5
        }
