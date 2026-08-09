"""
Command & Control Agent - Master Orchestrator
==============================================

The brain of the RedAgent swarm. Responsibilities:
- Coordinate all specialized agents
- Distribute tasks based on capabilities
- Aggregate intelligence from all agents
- Make strategic decisions
- Generate final reports
"""

import asyncio
import logging
import os
import json
import hmac
import hashlib
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from .base_agent import (
    BaseAgent, AgentCapability, AgentMessage, AgentPool,
    AgentStatus, MessageType, Priority, TaskResult
)

try:
    from ..tools.tool_factory import ToolFactory
except ImportError:
    from tools.tool_factory import ToolFactory

try:
    from ..storage.runtime_store import persist_findings
except ImportError:
    def persist_findings(*args, **kwargs):
        pass

logger = logging.getLogger(__name__)

try:
    from intelligence.mitre_attack import get_mitre_mapper
except Exception:
    get_mitre_mapper = None


class MissionPhase(Enum):
    """Attack mission phases"""
    PLANNING = "planning"
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    COMPLETED = "completed"


@dataclass
class MissionPolicy:
    """Rules of engagement and execution guardrails for a mission."""
    allowed_target_types: List[str] = field(default_factory=lambda: ["url", "ip"])
    forbidden_attack_types: List[str] = field(default_factory=list)
    min_confidence_for_exploitation: float = 0.6
    require_validation_for_exploitation: bool = True
    max_replans: int = 2
    threat_profile: str = "adaptive_baseline"
    max_attack_attempts: int = 12
    max_detection_rate: float = 85.0


@dataclass
class ThreatProfile:
    """Profile pack describing adversary behavior and mission priorities."""
    name: str
    objective_bias: List[str] = field(default_factory=list)
    preferred_vectors: List[str] = field(default_factory=list)
    mitre_focus: List[str] = field(default_factory=list)
    stealth_weight: float = 0.4
    speed_weight: float = 0.3
    impact_weight: float = 0.3


@dataclass
class Mission:
    """Represents an attack mission"""
    id: str
    target: str
    target_type: str  # url, ip, network, domain
    objectives: List[str]
    phase: MissionPhase = MissionPhase.PLANNING
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    findings: List[Dict] = field(default_factory=list)
    intel: Dict[str, Any] = field(default_factory=dict)
    agent_assignments: Dict[str, str] = field(default_factory=dict)  # task_id -> agent_id
    progress: float = 0.0
    status: str = "active"
    replans: int = 0
    phase_history: List[Dict[str, Any]] = field(default_factory=list)
    phase_started_at: Optional[datetime] = None
    last_phase_change_at: Optional[datetime] = None
    phase_durations: Dict[str, float] = field(default_factory=dict)
    agent_timings: Dict[str, float] = field(default_factory=dict)
    attack_metrics: Dict[str, Any] = field(default_factory=lambda: {
        "attempted": 0,
        "detected": 0,
        "successful": 0,
        "failed": 0,
        "detection_rate": 0.0,
        "success_rate": 0.0,
        "replan_count": 0,
        "fallback_attacks_used": False
    })
    policy: MissionPolicy = field(default_factory=MissionPolicy)
    kill_switch_triggered: bool = False
    kill_switch_reason: Optional[str] = None
    validation_checkpoints: List[Dict[str, Any]] = field(default_factory=list)
    campaign_plan: List[Dict[str, Any]] = field(default_factory=list)
    deferred_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    threat_profile: str = "adaptive_baseline"
    evidence_graph: Dict[str, Any] = field(default_factory=dict)
    audit_events: List[Dict[str, Any]] = field(default_factory=list)
    what_if_branches: List[Dict[str, Any]] = field(default_factory=list)
    selected_branch: Optional[str] = None
    governance_actions: List[Dict[str, Any]] = field(default_factory=list)


class CommandControl(BaseAgent):
    """
    Command & Control - The master orchestrator
    
    Coordinates the swarm, distributes tasks, aggregates results,
    and makes strategic decisions about attack progression.
    """
    
    def __init__(self, llm_client: Any = None, kill_switch_check=None, **kwargs):
        super().__init__(
            name="CommandControl",
            llm_client=llm_client,
            **kwargs
        )
        
        # Agent management
        self.agent_pool = AgentPool()
        
        # Mission management
        self.active_missions: Dict[str, Mission] = {}
        self.completed_missions: List[Mission] = []
        self._kill_switch_check = kill_switch_check
        
        # Strategy
        self.attack_playbook: Dict[str, List[Dict]] = {}
        self.threat_profiles: Dict[str, ThreatProfile] = self._load_threat_profiles()
        self._audit_secret = str(os.getenv("REDAGENT_AUDIT_SECRET", "redagent-dev-secret"))
        self._mitre_mapper = get_mitre_mapper() if callable(get_mitre_mapper) else None
        
        # Safe tools factory
        self.tool_factory = ToolFactory()
        
        # Register C2-specific handlers
        self.message_handlers[MessageType.INTEL] = self._handle_intel
        self.message_handlers[MessageType.RESULT] = self._handle_result
        self.message_handlers[MessageType.ALERT] = self._handle_alert
        self.message_handlers[MessageType.REQUEST] = self._handle_request
        
        logger.info("Command & Control initialized")
    
    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="orchestration",
                description="Coordinate multi-agent operations",
                input_types=["mission", "target"],
                output_types=["report", "findings"]
            ),
            AgentCapability(
                name="strategy",
                description="Develop attack strategies",
                input_types=["target", "intel"],
                output_types=["attack_plan"]
            ),
            AgentCapability(
                name="aggregation",
                description="Aggregate and analyze findings",
                input_types=["findings", "intel"],
                output_types=["report"]
            )
        ]
    
    def register_agent(self, agent: BaseAgent):
        """Register an agent with the C2"""
        self.agent_pool.register(agent)
        agent.start()
    
    def unregister_agent(self, agent_id: str):
        """Unregister an agent"""
        self.agent_pool.unregister(agent_id)
    
    async def execute_task(self, task: Dict[str, Any]) -> TaskResult:
        """Execute C2 tasks"""
        task_type = task.get("type", "")
        
        if task_type == "create_mission":
            return await self._create_mission(task)
        elif task_type == "advance_phase":
            return await self._advance_phase(task)
        elif task_type == "generate_report":
            return await self._generate_report(task)
        elif task_type == "sandbox_fuzzing":
            return await self._run_safe_fuzzing(task)
        elif task_type == "cloud_posture_review":
            return await self._run_cloud_posture_check(task)
        elif task_type == "cyber_range_inventory":
            return await self._run_cyber_range_inventory(task)
        else:
            return TaskResult(
                task_id=task.get("id", ""),
                success=False,
                error=f"Unknown task type: {task_type}"
            )
    
    async def launch_mission(
        self,
        target: str,
        target_type: str = "url",
        objectives: Optional[List[str]] = None,
        policy: Optional[Dict[str, Any]] = None
    ) -> Mission:
        """
        Launch a new attack mission
        
        This is the main entry point for starting an assessment.
        """
        import uuid
        
        mission_id = f"mission_{uuid.uuid4().hex[:8]}"
        
        objectives = objectives or [
            "identify_vulnerabilities",
            "exploit_critical",
            "assess_impact",
            "document_findings"
        ]
        
        mission_policy = self._build_policy(policy or {})

        if target_type not in mission_policy.allowed_target_types:
            mission = Mission(
                id=mission_id,
                target=target,
                target_type=target_type,
                objectives=objectives,
                status="failed",
                policy=mission_policy,
            )
            mission.intel["error"] = f"ROE violation: target type '{target_type}' is not allowed"
            self.completed_missions.append(mission)
            return mission

        mission = Mission(
            id=mission_id,
            target=target,
            target_type=target_type,
            objectives=objectives,
            policy=mission_policy,
            threat_profile=mission_policy.threat_profile,
        )

        mission.campaign_plan = self._build_campaign_plan(mission)
        self._record_audit_event(
            mission,
            "mission_launched",
            {
                "target": mission.target,
                "target_type": mission.target_type,
                "threat_profile": mission.threat_profile,
            },
        )
        
        self.active_missions[mission_id] = mission
        
        logger.info(f"Mission launched: {mission_id} targeting {target}")
        
        # Start the mission execution
        asyncio.create_task(self._execute_mission(mission))
        
        return mission
    
    async def _execute_mission(self, mission: Mission):
        """Execute a mission through all phases"""
        try:
            if self._should_abort_mission(mission):
                self._cancel_mission(mission, "Kill switch activated before mission start")
                return

            # Phase 1: Planning
            self._enter_phase(mission, MissionPhase.PLANNING, 0.05, "Planning attack strategy")
            await self._plan_attack(mission)
            if self._should_abort_mission(mission):
                self._cancel_mission(mission, "Kill switch activated during planning")
                return
            
            # Phase 2: Reconnaissance
            self._enter_phase(mission, MissionPhase.RECONNAISSANCE, 0.15, "Starting reconnaissance")
            await self._execute_reconnaissance(mission)
            if self._should_abort_mission(mission):
                self._cancel_mission(mission, "Kill switch activated during reconnaissance")
                return
            
            # Phase 3: Vulnerability Discovery
            self._enter_phase(mission, MissionPhase.VULNERABILITY_DISCOVERY, 0.35, "Discovering vulnerabilities")
            await self._execute_vulnerability_discovery(mission)
            if self._should_abort_mission(mission):
                self._cancel_mission(mission, "Kill switch activated during vulnerability discovery")
                return
            
            # Phase 4: Exploitation
            self._enter_phase(mission, MissionPhase.EXPLOITATION, 0.55, "Executing exploitation")
            await self._execute_exploitation(mission)
            if self._should_abort_mission(mission):
                self._cancel_mission(mission, "Kill switch activated during exploitation")
                return
            
            # Phase 5: Post-Exploitation
            self._enter_phase(mission, MissionPhase.POST_EXPLOITATION, 0.75, "Post-exploitation analysis")
            await self._execute_post_exploitation(mission)
            if self._should_abort_mission(mission):
                self._cancel_mission(mission, "Kill switch activated during post-exploitation")
                return
            
            # Phase 6: Reporting
            self._enter_phase(mission, MissionPhase.REPORTING, 0.90, "Generating report")
            await self._generate_mission_report(mission)
            if self._should_abort_mission(mission):
                self._cancel_mission(mission, "Kill switch activated during reporting")
                return
            
            # Complete
            self._finalize_current_phase(mission)
            mission.phase = MissionPhase.COMPLETED
            mission.completed_at = datetime.now()
            mission.status = "completed"
            mission.progress = 1.0
            self.set_progress(1.0, "Mission complete")
            
            # Move to completed
            self.completed_missions.append(mission)
            del self.active_missions[mission.id]
            
            logger.info(f"Mission {mission.id} completed successfully")
            
        except Exception as e:
            logger.error(f"Mission {mission.id} failed: {e}")
            mission.status = "failed"
            mission.intel["error"] = str(e)

    def _enter_phase(self, mission: Mission, phase: MissionPhase, progress: float, message: str):
        """Record mission phase transition with timing telemetry."""
        self._finalize_current_phase(mission)

        now = datetime.now()
        mission.phase = phase
        mission.progress = progress
        mission.phase_started_at = now
        mission.last_phase_change_at = now
        mission.phase_history.append({
            "phase": phase.value,
            "started_at": now.isoformat(),
            "progress": progress
        })
        self._record_audit_event(
            mission,
            "phase_transition",
            {
                "phase": phase.value,
                "progress": progress,
                "message": message,
            },
        )
        self.set_progress(progress, message)

    def _finalize_current_phase(self, mission: Mission):
        """Close timing window for active phase before transitioning."""
        if not mission.phase_started_at:
            return

        elapsed = max(0.0, (datetime.now() - mission.phase_started_at).total_seconds())
        phase_key = mission.phase.value
        mission.phase_durations[phase_key] = mission.phase_durations.get(phase_key, 0.0) + elapsed
        mission.phase_started_at = None

    async def _run_agent_task(self, mission: Mission, agent: BaseAgent, task: Dict[str, Any], timing_key: str) -> TaskResult:
        """Run agent task with duration tracking."""
        started = time.perf_counter()
        result = await agent.run_with_retry(task)
        mission.agent_timings[timing_key] = mission.agent_timings.get(timing_key, 0.0) + (time.perf_counter() - started)
        return result
    
    async def _plan_attack(self, mission: Mission):
        """Plan the attack strategy using LLM"""
        mission.intel["threat_profile"] = mission.threat_profile
        mission.intel["playbook"] = self._build_attack_playbook(mission)

        strategy_agents = self.agent_pool.find_by_capability("strategy_planning")

        if strategy_agents:
            strategy_agent = strategy_agents[0]
            result = await strategy_agent.run_with_retry({
                "id": f"{mission.id}_strategy",
                "type": "build_strategy",
                "target": mission.target,
                "objectives": mission.objectives,
                "recon": mission.intel.get("reconnaissance", {}),
                "vulnerabilities": mission.intel.get("vulnerabilities", [])
            })
            if result.success:
                mission.intel["strategy"] = result.data
                mission.what_if_branches = self._simulate_branches(mission)
                mission.intel["what_if_branches"] = mission.what_if_branches
                return

        if not self.llm_client:
            # Default strategy without LLM
            mission.intel["strategy"] = {
                "approach": "standard_assessment",
                "priority_targets": ["web_application", "authentication", "injection_points"],
                "tools": ["nmap", "sqlmap", "curl", "hydra"]
            }
            mission.what_if_branches = self._simulate_branches(mission)
            mission.intel["what_if_branches"] = mission.what_if_branches
            return
        
        # Use LLM to plan
        prompt = f"""
        You are a security assessment planner. Create an attack strategy for:
        
        Target: {mission.target}
        Type: {mission.target_type}
        Objectives: {', '.join(mission.objectives)}
        
        Provide a JSON strategy with:
        - approach: Overall methodology
        - priority_targets: List of what to focus on
        - attack_vectors: List of attacks to try
        - tools: Tools to use
        - estimated_duration: Time estimate
        """
        
        try:
            response = await self.llm_client.generate(prompt)
            # Parse response and store strategy
            mission.intel["strategy"] = {"raw": response, "planned": True}
            mission.what_if_branches = self._simulate_branches(mission)
            mission.intel["what_if_branches"] = mission.what_if_branches
        except Exception as e:
            logger.warning(f"LLM planning failed: {e}")
            mission.intel["strategy"] = {"approach": "standard", "planned": False}
            mission.what_if_branches = self._simulate_branches(mission)
            mission.intel["what_if_branches"] = mission.what_if_branches
    
    async def _execute_reconnaissance(self, mission: Mission):
        """Execute reconnaissance phase with ReconAgent"""
        recon_agents = self.agent_pool.find_by_capability("reconnaissance")
        
        if recon_agents:
            agent = recon_agents[0]
            result = await self._run_agent_task(mission, agent, {
                "id": f"{mission.id}_recon",
                "type": "full_recon",
                "target": mission.target,
                "target_type": mission.target_type
            }, "reconnaissance")
            
            if result.success:
                mission.intel["reconnaissance"] = result.data
                mission.findings.extend(agent.findings)
                self._record_validation_checkpoint(
                    mission,
                    "reconnaissance",
                    True,
                    {
                        "signals": len(result.data.get("domains", []) if isinstance(result.data, dict) else []),
                        "source": "ReconAgent"
                    }
                )
        else:
            # Fallback: basic recon without specialized agent
            logger.warning("No ReconAgent available, using basic recon")
            mission.intel["reconnaissance"] = {"status": "basic", "agent": "none"}
            self._record_validation_checkpoint(
                mission,
                "reconnaissance",
                False,
                {"reason": "ReconAgent unavailable"}
            )
    
    async def _execute_vulnerability_discovery(self, mission: Mission):
        """Execute vulnerability discovery"""
        # Use exploit agents for scanning
        exploit_agents = self.agent_pool.find_by_capability("vulnerability_scanning")
        logic_agents = self.agent_pool.find_by_capability("business_logic_analysis")
        
        discovered = []
        
        for agent in exploit_agents:
            result = await self._run_agent_task(mission, agent, {
                "id": f"{mission.id}_vuln_scan",
                "type": "vulnerability_scan",
                "target": mission.target,
                "intel": mission.intel.get("reconnaissance", {})
            }, "vulnerability_scan")
            
            if result.success and result.data:
                discovered.extend(result.data.get("vulnerabilities", []))
                mission.findings.extend(agent.findings)

        # Run business logic analysis in the same phase and merge results.
        for agent in logic_agents:
            result = await self._run_agent_task(mission, agent, {
                "id": f"{mission.id}_business_logic_scan",
                "type": "business_logic_scan",
                "target": mission.target,
                "intel": mission.intel.get("reconnaissance", {})
            }, "business_logic_scan")

            if result.success and result.data:
                discovered.extend(result.data.get("vulnerabilities", []))
                mission.intel["business_logic"] = result.data
                mission.findings.extend(agent.findings)
        
        mission.intel["vulnerabilities"] = discovered
        validated, deferred = self._apply_confidence_gate(mission, discovered)
        mission.intel["validated_vulnerabilities"] = validated
        mission.deferred_vulnerabilities = deferred
        mission.intel["vulnerability_summary"] = {
            "total_discovered": len(discovered),
            "validated_for_exploitation": len(validated),
            "deferred_for_validation": len(deferred),
            "by_type": self._count_by(discovered, key="type"),
            "by_severity": self._count_by(discovered, key="severity")
        }

        checkpoint_passed = (len(validated) > 0) or (not mission.policy.require_validation_for_exploitation)
        self._record_validation_checkpoint(
            mission,
            "vulnerability_validation",
            checkpoint_passed,
            {
                "total_discovered": len(discovered),
                "validated": len(validated),
                "deferred": len(deferred),
                "min_confidence": mission.policy.min_confidence_for_exploitation,
            }
        )
        mission.what_if_branches = self._simulate_branches(mission)
        mission.intel["what_if_branches"] = mission.what_if_branches
    
    async def _execute_exploitation(self, mission: Mission):
        """Execute exploitation attempts"""
        exploit_agents = self.agent_pool.find_by_capability("exploitation")
        if not exploit_agents:
            mission.intel["exploitation"] = []
            mission.attack_metrics["failed"] = mission.attack_metrics.get("failed", 0) + 1
            return
        
        vulnerabilities = mission.intel.get("validated_vulnerabilities", mission.intel.get("vulnerabilities", []))
        exploitation_results = []

        sorted_vulns = self._prioritize_vulnerabilities(vulnerabilities)
        attack_budget = max(1, mission.policy.max_attack_attempts)
        planned_attempts = min(attack_budget, len(sorted_vulns))
        mission.attack_metrics["attempted"] = planned_attempts
        mission.attack_metrics["detected"] = 0
        current_attempts = 0

        for vuln in sorted_vulns[:planned_attempts]:
            if self._should_abort_mission(mission):
                self._cancel_mission(mission, "Kill switch activated during exploit loop")
                return
            current_attempts += 1

            if self._is_forbidden_vector(mission, vuln.get("type")):
                mission.intel.setdefault("blocked_actions", []).append({
                    "phase": "exploitation",
                    "vector": vuln.get("type", "unknown"),
                    "reason": "ROE forbidden attack type",
                })
                mission.attack_metrics["detected"] = mission.attack_metrics.get("detected", 0) + 1
                self._record_audit_event(
                    mission,
                    "exploit_blocked",
                    {
                        "vector": vuln.get("type", "unknown"),
                        "reason": "ROE forbidden attack type",
                    },
                )
                if self._risk_budget_exceeded(mission, current_attempts):
                    return
                continue

            vuln_succeeded = False
            for agent in exploit_agents:
                result = await self._run_agent_task(mission, agent, {
                    "id": f"{mission.id}_exploit_{vuln.get('id', 'unknown')}",
                    "type": "exploit",
                    "vulnerability": vuln,
                    "target": mission.target
                }, "exploit_execution")
                
                if result.success:
                    exploitation_results.append({
                        "vulnerability": vuln,
                        "result": result.data,
                        "agent": agent.agent_id
                    })
                    mission.findings.extend(agent.findings)
                    vuln_succeeded = True
                    break

            if vuln_succeeded:
                mission.attack_metrics["successful"] = mission.attack_metrics.get("successful", 0) + 1
                self._record_audit_event(
                    mission,
                    "exploit_attempt",
                    {
                        "vector": vuln.get("type", "unknown"),
                        "result": "success",
                    },
                )
            else:
                mission.attack_metrics["failed"] = mission.attack_metrics.get("failed", 0) + 1
                mission.attack_metrics["detected"] = mission.attack_metrics.get("detected", 0) + 1
                self._record_audit_event(
                    mission,
                    "exploit_attempt",
                    {
                        "vector": vuln.get("type", "unknown"),
                        "result": "failed",
                    },
                )
            if self._risk_budget_exceeded(mission, current_attempts):
                return

        if not sorted_vulns:
            # Fall back to deterministic low-noise probes when discovery returns empty.
            primary_agent = exploit_agents[0]
            if self._is_forbidden_vector(mission, "focused_attack"):
                mission.intel.setdefault("blocked_actions", []).append({
                    "phase": "exploitation",
                    "vector": "focused_attack",
                    "reason": "ROE forbidden attack type",
                })
                mission.intel["exploitation"] = []
                return

            fallback = await self._run_agent_task(mission, primary_agent, {
                "id": f"{mission.id}_focused_attack_fallback",
                "type": "focused_attack",
                "target": mission.target
            }, "fallback_focused_attack")

            mission.attack_metrics["fallback_attacks_used"] = True
            if fallback.success and fallback.data:
                fallback_vulns = fallback.data.get("vulnerabilities", [])
                mission.intel.setdefault("vulnerabilities", []).extend(fallback_vulns)
                mission.findings.extend(primary_agent.findings)
                attempted_vectors = int(fallback.data.get("attack_attempts", 0))
                mission.attack_metrics["attempted"] = attempted_vectors
                mission.attack_metrics["detected"] = len(fallback_vulns)
                mission.attack_metrics["successful"] = len(fallback.data.get("successful_exploits", []))
                mission.attack_metrics["failed"] = max(0, attempted_vectors - mission.attack_metrics["successful"])
        
        mission.intel["exploitation"] = exploitation_results
        attempted = max(1, mission.attack_metrics.get("attempted", 0))
        mission.attack_metrics["detection_rate"] = round((mission.attack_metrics.get("detected", 0) / attempted) * 100.0, 2)
        mission.attack_metrics["success_rate"] = round((mission.attack_metrics.get("successful", 0) / attempted) * 100.0, 2)

        if sorted_vulns:
            failed_attempts = max(0, min(12, len(sorted_vulns)) - len(exploitation_results))
            if failed_attempts > 0:
                await self._request_replan(mission, failed_attempts, sorted_vulns[:12])

    async def _request_replan(self, mission: Mission, failed_attempts: int, attempted: List[Dict[str, Any]]):
        """Ask strategy agent to revise the mission approach when execution underperforms."""
        if mission.replans >= mission.policy.max_replans:
            mission.intel["replan_blocked"] = {
                "reason": "ROE max replans reached",
                "max_replans": mission.policy.max_replans,
            }
            return

        strategy_agents = self.agent_pool.find_by_capability("strategy_planning")
        if not strategy_agents:
            return

        strategy_agent = strategy_agents[0]
        previous_strategy = mission.intel.get("strategy", {})

        result = await strategy_agent.run_with_retry({
            "id": f"{mission.id}_strategy_replan_{mission.replans + 1}",
            "type": "replan_strategy",
            "target": mission.target,
            "objectives": mission.objectives,
            "vulnerabilities": attempted,
            "failures": [{"reason": "unsuccessful_exploitation"}] * failed_attempts,
            "previous_strategy": previous_strategy
        })

        if result.success:
            mission.replans += 1
            mission.attack_metrics["replan_count"] = mission.replans
            mission.intel["strategy_replan"] = result.data

    def _prioritize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize exploitation order using severity + confidence + status."""
        if not vulnerabilities:
            return []

        severity_score = {"critical": 100, "high": 75, "medium": 45, "low": 20, "info": 5}

        def score(v: Dict[str, Any]) -> float:
            sev = str(v.get("severity", "low")).lower()
            confidence = float(v.get("confidence_score") or 55)
            status = str(v.get("status") or v.get("exploitation_status") or "").lower()

            points = severity_score.get(sev, 20) + confidence
            if "confirmed" in status or "vulnerable" in status:
                points += 25
            if str(v.get("type", "")).startswith("business_logic_"):
                points += 10
            return points

        return sorted(vulnerabilities, key=score, reverse=True)

    def _count_by(self, rows: List[Dict[str, Any]], key: str) -> Dict[str, int]:
        summary: Dict[str, int] = {}
        for row in rows:
            label = str(row.get(key, "unknown")).lower()
            summary[label] = summary.get(label, 0) + 1
        return summary
    
    async def _execute_post_exploitation(self, mission: Mission):
        """Post-exploitation phase"""
        # Analyze exploitation results
        successful_exploits = [
            e for e in mission.intel.get("exploitation", [])
            if e.get("result", {}).get("success", False)
        ]
        
        mission.intel["post_exploitation"] = {
            "successful_exploits": len(successful_exploits),
            "access_gained": [e.get("result", {}).get("access_type") for e in successful_exploits],
            "impact_assessment": self._assess_impact(successful_exploits)
        }
    
    def _assess_impact(self, exploits: List[Dict]) -> Dict[str, Any]:
        """Assess business impact of successful exploits"""
        impact = {
            "risk_level": "LOW",
            "data_exposure": False,
            "system_compromise": False,
            "lateral_movement_possible": False,
            "recommendations": []
        }
        
        for exploit in exploits:
            result = exploit.get("result", {})
            vuln = exploit.get("vulnerability", {})
            
            severity = vuln.get("severity", "low").lower()
            
            if severity == "critical":
                impact["risk_level"] = "CRITICAL"
                impact["system_compromise"] = True
            elif severity == "high" and impact["risk_level"] != "CRITICAL":
                impact["risk_level"] = "HIGH"
            
            if "data" in str(result).lower() or "database" in str(result).lower():
                impact["data_exposure"] = True
            
            if "admin" in str(result).lower() or "root" in str(result).lower():
                impact["system_compromise"] = True
                impact["lateral_movement_possible"] = True
        
        return impact
    
    async def _generate_mission_report(self, mission: Mission):
        """Generate comprehensive mission report"""
        mission.evidence_graph = self._build_evidence_graph(mission)
        recommendations = self._generate_command_recommendations(mission)
        mission.intel["report"] = {
            "mission_id": mission.id,
            "target": mission.target,
            "target_type": mission.target_type,
            "started_at": mission.started_at.isoformat(),
            "completed_at": datetime.now().isoformat(),
            "duration_seconds": (datetime.now() - mission.started_at).total_seconds(),
            "findings_count": len(mission.findings),
            "findings": mission.findings,
            "phases": {
                "reconnaissance": mission.intel.get("reconnaissance", {}),
                "vulnerabilities": mission.intel.get("vulnerabilities", []),
                "exploitation": mission.intel.get("exploitation", []),
                "post_exploitation": mission.intel.get("post_exploitation", {})
            },
            "impact": mission.intel.get("post_exploitation", {}).get("impact_assessment", {}),
            "agents_used": list(self.agent_pool.agents.keys()),
            "telemetry": {
                "phase_history": mission.phase_history,
                "phase_durations": mission.phase_durations,
                "agent_timings": mission.agent_timings,
                "attack_metrics": mission.attack_metrics,
                "validation_checkpoints": mission.validation_checkpoints,
                "campaign_plan": mission.campaign_plan,
                "what_if_branches": mission.what_if_branches,
            },
            "phase2": {
                "threat_profile": mission.threat_profile,
                "playbook": mission.intel.get("playbook", {}),
                "evidence_graph": mission.evidence_graph,
                "audit_events": mission.audit_events,
            },
            "phase3": {
                "selected_branch": mission.selected_branch,
                "governance_actions": mission.governance_actions,
                "command_recommendations": recommendations,
            },
            "controls": {
                "policy": {
                    "allowed_target_types": mission.policy.allowed_target_types,
                    "forbidden_attack_types": mission.policy.forbidden_attack_types,
                    "min_confidence_for_exploitation": mission.policy.min_confidence_for_exploitation,
                    "require_validation_for_exploitation": mission.policy.require_validation_for_exploitation,
                    "max_replans": mission.policy.max_replans,
                    "threat_profile": mission.policy.threat_profile,
                    "max_attack_attempts": mission.policy.max_attack_attempts,
                    "max_detection_rate": mission.policy.max_detection_rate,
                },
                "kill_switch_triggered": mission.kill_switch_triggered,
                "kill_switch_reason": mission.kill_switch_reason,
            }
        }
    
    def _handle_intel(self, msg: AgentMessage):
        """Handle intelligence reports from agents"""
        intel_type = msg.payload.get("intel_type", "unknown")
        data = msg.payload.get("data", {})
        
        # Store in knowledge base
        self.update_knowledge(f"{msg.sender}_{intel_type}", data)
        
        # Update relevant missions
        for mission in self.active_missions.values():
            if mission.status == "active":
                if intel_type not in mission.intel:
                    mission.intel[intel_type] = []
                mission.intel[intel_type].append({
                    "source": msg.sender,
                    "data": data,
                    "timestamp": msg.timestamp.isoformat()
                })
        
        logger.debug(f"Received intel from {msg.sender}: {intel_type}")
    
    def _handle_result(self, msg: AgentMessage):
        """Handle task results from agents"""
        task_id = msg.payload.get("task_id", "")
        result = msg.payload.get("result", {})
        
        # Find which mission this task belongs to
        for mission in self.active_missions.values():
            if task_id.startswith(mission.id):
                mission.intel[f"result_{task_id}"] = result
                break
    
    def _handle_alert(self, msg: AgentMessage):
        """Handle critical alerts from agents"""
        finding = msg.payload.get("finding", {})
        
        logger.warning(f"ALERT from {msg.sender}: {finding.get('type', 'unknown')} - {finding.get('severity', 'unknown')}")
        
        # Add to all active missions
        for mission in self.active_missions.values():
            mission.findings.append(finding)
        
        # Could trigger webhooks, notifications, etc. here
    
    def _handle_request(self, msg: AgentMessage):
        """Handle assistance requests from agents"""
        capability_needed = msg.payload.get("capability_needed", "")
        request_data = msg.payload.get("data", {})
        
        # Find available agent with capability
        available_agents = self.agent_pool.find_by_capability(capability_needed)
        
        if available_agents:
            # Assign to least busy agent
            agent = min(available_agents, key=lambda a: a.metrics["tasks_completed"])
            
            # Forward the request
            agent.receive_message(AgentMessage(
                type=MessageType.TASK,
                sender=self.agent_id,
                recipient=agent.agent_id,
                payload=request_data
            ))
            
            logger.info(f"Routed request for {capability_needed} to {agent.agent_id}")
        else:
            logger.warning(f"No agent available for capability: {capability_needed}")
    
    async def _create_mission(self, task: Dict[str, Any]) -> TaskResult:
        """Create a new mission"""
        target = task.get("target", "")
        target_type = task.get("target_type", "url")
        objectives = task.get("objectives", [])
        
        if not target:
            return TaskResult(
                task_id=task.get("id", ""),
                success=False,
                error="No target specified"
            )
        
        mission = await self.launch_mission(target, target_type, objectives, task.get("policy"))
        
        return TaskResult(
            task_id=task.get("id", ""),
            success=True,
            data={"mission_id": mission.id}
        )
    
    async def _advance_phase(self, task: Dict[str, Any]) -> TaskResult:
        """Manually advance mission phase"""
        mission_id = task.get("mission_id", "")
        
        if mission_id not in self.active_missions:
            return TaskResult(
                task_id=task.get("id", ""),
                success=False,
                error="Mission not found"
            )
        
        # Phase advancement logic here
        return TaskResult(
            task_id=task.get("id", ""),
            success=True
        )
    
    async def _generate_report(self, task: Dict[str, Any]) -> TaskResult:
        """Generate report for a mission"""
        mission_id = task.get("mission_id", "")
        
        mission = self.active_missions.get(mission_id) or \
                  next((m for m in self.completed_missions if m.id == mission_id), None)
        
        if not mission:
            return TaskResult(
                task_id=task.get("id", ""),
                success=False,
                error="Mission not found"
            )
        
        return TaskResult(
            task_id=task.get("id", ""),
            success=True,
            data=mission.intel.get("report", {})
        )
    
    async def _run_safe_fuzzing(self, task: Dict[str, Any]) -> TaskResult:
        """Execute sandboxed fuzzing on a target."""
        try:
            mission_id = task.get("mission_id", "")
            tool = self.tool_factory.get_tool("fuzzing_harness")
            if not tool:
                return TaskResult(
                    task_id=task.get("id", ""),
                    success=False,
                    error="fuzzing_harness tool not available"
                )
            
            target = task.get("target", "")
            params = {
                "target": target,
                "seed": task.get("seed", "redagent"),
                "iterations": int(task.get("iterations", 25)),
                "payload_mode": task.get("payload_mode", "balanced"),
            }
            
            result = tool.execute(params)
            metadata = result.get("metadata", {})
            findings = metadata.get("findings", [])
            
            if mission_id:
                persist_findings(
                    source="swarm_sandbox_fuzzing",
                    tool_name="fuzzing_harness",
                    assessment_job_id=mission_id,
                    target=target,
                    findings=findings,
                )
            
            return TaskResult(
                task_id=task.get("id", ""),
                success=(result.get("status") == "success"),
                data=metadata,
            )
        except Exception as e:
            logger.error(f"Fuzzing task failed: {e}")
            return TaskResult(
                task_id=task.get("id", ""),
                success=False,
                error=str(e)
            )
    
    async def _run_cloud_posture_check(self, task: Dict[str, Any]) -> TaskResult:
        """Execute cloud posture audit."""
        try:
            mission_id = task.get("mission_id", "")
            tool = self.tool_factory.get_tool("cloud_posture")
            if not tool:
                return TaskResult(
                    task_id=task.get("id", ""),
                    success=False,
                    error="cloud_posture tool not available"
                )
            
            target = task.get("target", "")
            params = {
                "target": target,
                "profile": task.get("profile", "default"),
            }
            
            result = tool.execute(params)
            metadata = result.get("metadata", {})
            findings = metadata.get("findings", [])
            
            if mission_id:
                persist_findings(
                    source="swarm_cloud_posture",
                    tool_name="cloud_posture",
                    assessment_job_id=mission_id,
                    target=target,
                    findings=findings,
                )
            
            return TaskResult(
                task_id=task.get("id", ""),
                success=(result.get("status") == "success"),
                data=metadata,
            )
        except Exception as e:
            logger.error(f"Cloud posture task failed: {e}")
            return TaskResult(
                task_id=task.get("id", ""),
                success=False,
                error=str(e)
            )
    
    async def _run_cyber_range_inventory(self, task: Dict[str, Any]) -> TaskResult:
        """Execute cyber range inventory."""
        try:
            tool = self.tool_factory.get_tool("cyber_range")
            if not tool:
                return TaskResult(
                    task_id=task.get("id", ""),
                    success=False,
                    error="cyber_range tool not available"
                )
            
            target = task.get("target", "")
            params = {
                "target": target,
                "range_path": task.get("range_path", "cyber_range"),
            }
            
            result = tool.execute(params)
            metadata = result.get("metadata", {})
            
            return TaskResult(
                task_id=task.get("id", ""),
                success=(result.get("status") == "success"),
                data=metadata,
            )
        except Exception as e:
            logger.error(f"Cyber range inventory task failed: {e}")
            return TaskResult(
                task_id=task.get("id", ""),
                success=False,
                error=str(e)
            )
    
    def get_mission_status(self, mission_id: str) -> Optional[Dict]:
        """Get status of a mission"""
        mission = self.active_missions.get(mission_id)
        
        if not mission:
            mission = next((m for m in self.completed_missions if m.id == mission_id), None)
        
        if not mission:
            return None
        
        return {
            "id": mission.id,
            "target": mission.target,
            "phase": mission.phase.value,
            "status": mission.status,
            "progress": mission.progress,
            "findings_count": len(mission.findings),
            "started_at": mission.started_at.isoformat(),
            "completed_at": mission.completed_at.isoformat() if mission.completed_at else None,
            "last_phase_change_at": mission.last_phase_change_at.isoformat() if mission.last_phase_change_at else None,
            "phase_history": mission.phase_history,
            "phase_durations": mission.phase_durations,
            "agent_timings": mission.agent_timings,
            "attack_metrics": mission.attack_metrics,
            "validation_checkpoints": mission.validation_checkpoints,
            "kill_switch_triggered": mission.kill_switch_triggered,
            "kill_switch_reason": mission.kill_switch_reason,
            "policy": {
                "allowed_target_types": mission.policy.allowed_target_types,
                "forbidden_attack_types": mission.policy.forbidden_attack_types,
                "min_confidence_for_exploitation": mission.policy.min_confidence_for_exploitation,
                "require_validation_for_exploitation": mission.policy.require_validation_for_exploitation,
                "max_replans": mission.policy.max_replans,
                "threat_profile": mission.policy.threat_profile,
                "max_attack_attempts": mission.policy.max_attack_attempts,
                "max_detection_rate": mission.policy.max_detection_rate,
            },
            "campaign_plan": mission.campaign_plan,
            "deferred_vulnerabilities": mission.deferred_vulnerabilities,
            "threat_profile": mission.threat_profile,
            "what_if_branches": mission.what_if_branches,
            "evidence_graph": mission.evidence_graph,
            "audit_events": mission.audit_events,
            "selected_branch": mission.selected_branch,
            "governance_actions": mission.governance_actions,
            "command_recommendations": self._generate_command_recommendations(mission),
        }

    def select_what_if_branch(self, mission_id: str, branch_id: str) -> Optional[Dict[str, Any]]:
        """Select a what-if branch and apply governance tuning to active mission."""
        mission = self.active_missions.get(mission_id)
        if not mission:
            mission = next((m for m in self.completed_missions if m.id == mission_id), None)
        if not mission:
            return None

        selected = next((b for b in mission.what_if_branches if b.get("id") == branch_id), None)
        if not selected:
            return None

        mission.selected_branch = branch_id
        weights = selected.get("weights", {})
        stealth_weight = float(weights.get("stealth", 0.0))
        impact_weight = float(weights.get("impact", 0.0))

        if stealth_weight >= 0.5:
            mission.policy.max_attack_attempts = min(mission.policy.max_attack_attempts, 8)
            mission.policy.max_detection_rate = min(mission.policy.max_detection_rate, 60.0)
        elif impact_weight >= 0.5:
            mission.policy.max_attack_attempts = min(20, max(mission.policy.max_attack_attempts, 14))
            mission.policy.max_detection_rate = min(95.0, max(mission.policy.max_detection_rate, 90.0))

        action = {
            "timestamp": datetime.now().isoformat(),
            "type": "branch_selected",
            "branch_id": branch_id,
            "policy": {
                "max_attack_attempts": mission.policy.max_attack_attempts,
                "max_detection_rate": mission.policy.max_detection_rate,
            }
        }
        mission.governance_actions.append(action)
        self._record_audit_event(mission, "branch_selected", action)
        return selected

    def trigger_kill_switch(self, mission_id: str, reason: str = "Manual kill switch") -> bool:
        """Trigger kill switch for an active mission."""
        mission = self.active_missions.get(mission_id)
        if not mission:
            return False
        self._cancel_mission(mission, reason)
        return True

    def _build_policy(self, policy_data: Dict[str, Any]) -> MissionPolicy:
        """Build mission policy from user-provided configuration."""
        allowed = policy_data.get("allowed_target_types", ["url", "ip"])
        if not isinstance(allowed, list) or not allowed:
            allowed = ["url", "ip"]

        forbidden = policy_data.get("forbidden_attack_types", [])
        if not isinstance(forbidden, list):
            forbidden = []

        min_conf = policy_data.get("min_confidence_for_exploitation", 0.6)
        try:
            min_conf = float(min_conf)
        except (TypeError, ValueError):
            min_conf = 0.6
        min_conf = max(0.0, min(1.0, min_conf))

        max_replans = policy_data.get("max_replans", 2)
        try:
            max_replans = int(max_replans)
        except (TypeError, ValueError):
            max_replans = 2
        max_replans = max(0, min(10, max_replans))

        require_validation = bool(policy_data.get("require_validation_for_exploitation", True))

        max_attempts = policy_data.get("max_attack_attempts", 12)
        try:
            max_attempts = int(max_attempts)
        except (TypeError, ValueError):
            max_attempts = 12
        max_attempts = max(1, min(50, max_attempts))

        max_detection_rate = policy_data.get("max_detection_rate", 85.0)
        try:
            max_detection_rate = float(max_detection_rate)
        except (TypeError, ValueError):
            max_detection_rate = 85.0
        max_detection_rate = max(1.0, min(100.0, max_detection_rate))

        return MissionPolicy(
            allowed_target_types=[str(v).lower() for v in allowed],
            forbidden_attack_types=[str(v).lower() for v in forbidden],
            min_confidence_for_exploitation=min_conf,
            require_validation_for_exploitation=require_validation,
            max_replans=max_replans,
            threat_profile=str(policy_data.get("threat_profile", "adaptive_baseline")).strip().lower() or "adaptive_baseline",
            max_attack_attempts=max_attempts,
            max_detection_rate=max_detection_rate,
        )

    def _risk_budget_exceeded(self, mission: Mission, current_attempts: int) -> bool:
        """Evaluate and enforce mission risk budgets during exploitation."""
        attempted_now = max(1, current_attempts)
        detected = mission.attack_metrics.get("detected", 0)
        live_detection_rate = (float(detected) / float(attempted_now)) * 100.0

        if live_detection_rate <= mission.policy.max_detection_rate:
            return False

        reason = (
            f"Risk budget exceeded: live detection rate {live_detection_rate:.2f}% "
            f"> allowed {mission.policy.max_detection_rate:.2f}%"
        )
        action = {
            "timestamp": datetime.now().isoformat(),
            "type": "risk_budget_stop",
            "live_detection_rate": round(live_detection_rate, 2),
            "allowed_detection_rate": mission.policy.max_detection_rate,
            "attempts_processed": attempted_now,
        }
        mission.governance_actions.append(action)
        mission.intel["risk_budget"] = {
            "triggered": True,
            "reason": reason,
            "live_detection_rate": round(live_detection_rate, 2),
            "max_detection_rate": mission.policy.max_detection_rate,
        }
        self._record_audit_event(mission, "risk_budget_exceeded", action)
        self._cancel_mission(mission, reason)
        return True

    def _generate_command_recommendations(self, mission: Mission) -> List[Dict[str, Any]]:
        """Generate command recommendations for operators from phase 2+3 telemetry."""
        recommendations: List[Dict[str, Any]] = []
        checkpoints = mission.validation_checkpoints

        failed_checkpoints = [c for c in checkpoints if not c.get("passed")]
        if failed_checkpoints:
            recommendations.append({
                "priority": "high",
                "action": "increase_validation_confidence",
                "reason": f"{len(failed_checkpoints)} validation checkpoints failed",
            })

        detection_rate = float(mission.attack_metrics.get("detection_rate", 0.0))
        if detection_rate > mission.policy.max_detection_rate:
            recommendations.append({
                "priority": "critical",
                "action": "pivot_to_stealth_branch",
                "reason": (
                    f"Detection rate {detection_rate:.2f}% exceeds policy "
                    f"{mission.policy.max_detection_rate:.2f}%"
                ),
            })

        if mission.what_if_branches:
            best_branch = max(mission.what_if_branches, key=lambda b: float(b.get("score", 0.0)))
            if mission.selected_branch != best_branch.get("id"):
                recommendations.append({
                    "priority": "medium",
                    "action": "select_optimal_branch",
                    "branch_id": best_branch.get("id"),
                    "reason": f"Highest branch score is {best_branch.get('score', 0.0)}",
                })

        if not recommendations:
            recommendations.append({
                "priority": "info",
                "action": "maintain_course",
                "reason": "Mission telemetry is within configured policy budgets",
            })

        return recommendations

    def _build_campaign_plan(self, mission: Mission) -> List[Dict[str, Any]]:
        """Create deterministic campaign phase plan for mission state machine visibility."""
        return [
            {"phase": MissionPhase.PLANNING.value, "goal": "Define strategy, ROE, and phase gates"},
            {"phase": MissionPhase.RECONNAISSANCE.value, "goal": "Collect host, service, and route intel"},
            {"phase": MissionPhase.VULNERABILITY_DISCOVERY.value, "goal": "Generate candidate findings and confidence scores"},
            {"phase": MissionPhase.EXPLOITATION.value, "goal": "Attempt only validated and ROE-compliant vectors"},
            {"phase": MissionPhase.POST_EXPLOITATION.value, "goal": "Assess impact and access depth"},
            {"phase": MissionPhase.REPORTING.value, "goal": "Produce evidence-backed mission report"},
        ]

    def _extract_confidence(self, vulnerability: Dict[str, Any]) -> float:
        """Extract confidence from heterogeneous vulnerability payload fields."""
        raw = vulnerability.get("confidence")
        if raw is None:
            raw = vulnerability.get("confidence_score", vulnerability.get("score", 0.0))

        try:
            value = float(raw)
        except (TypeError, ValueError):
            value = 0.0

        if value > 1.0:
            value = value / 100.0

        return max(0.0, min(1.0, value))

    def _apply_confidence_gate(self, mission: Mission, vulnerabilities: List[Dict[str, Any]]):
        """Split vulnerabilities into validated and deferred sets based on confidence policy."""
        if not mission.policy.require_validation_for_exploitation:
            return vulnerabilities, []

        validated: List[Dict[str, Any]] = []
        deferred: List[Dict[str, Any]] = []
        threshold = mission.policy.min_confidence_for_exploitation

        for vuln in vulnerabilities:
            confidence = self._extract_confidence(vuln)
            candidate = dict(vuln)
            candidate["confidence"] = confidence
            if confidence >= threshold:
                validated.append(candidate)
            else:
                deferred.append(candidate)

        return validated, deferred

    def _record_validation_checkpoint(self, mission: Mission, name: str, passed: bool, details: Dict[str, Any]):
        """Track validation checkpoints for confidence-gated execution."""
        checkpoint = {
            "name": name,
            "passed": bool(passed),
            "timestamp": datetime.now().isoformat(),
            "details": details,
        }
        mission.validation_checkpoints.append(checkpoint)
        self._record_audit_event(
            mission,
            "validation_checkpoint",
            {
                "name": name,
                "passed": bool(passed),
                "details": details,
            },
        )

    def _is_forbidden_vector(self, mission: Mission, vector: Optional[str]) -> bool:
        """Check if ROE forbids a specific attack vector."""
        if not vector:
            return False
        return str(vector).lower() in mission.policy.forbidden_attack_types

    def _should_abort_mission(self, mission: Mission) -> bool:
        """Return True when mission should stop immediately."""
        if mission.kill_switch_triggered or mission.status in {"cancelled", "failed"}:
            return True

        if callable(self._kill_switch_check):
            try:
                if bool(self._kill_switch_check(mission)):
                    return True
            except TypeError:
                # Backward compatibility for zero-arg callbacks.
                if bool(self._kill_switch_check()):
                    return True

        return False

    def _cancel_mission(self, mission: Mission, reason: str):
        """Mark mission cancelled and capture reason in intel/telemetry."""
        self._finalize_current_phase(mission)
        mission.status = "cancelled"
        mission.kill_switch_triggered = True
        mission.kill_switch_reason = reason
        mission.completed_at = datetime.now()
        mission.intel["cancel_reason"] = reason
        self._record_audit_event(
            mission,
            "mission_cancelled",
            {
                "reason": reason,
                "phase": mission.phase.value,
            },
        )

    def _load_threat_profiles(self) -> Dict[str, ThreatProfile]:
        """Threat profile packs used by the phase-2 playbook engine."""
        return {
            "adaptive_baseline": ThreatProfile(
                name="Adaptive Baseline",
                objective_bias=["identify_vulnerabilities", "assess_impact"],
                preferred_vectors=["sql_injection", "xss", "header_injection", "path_traversal"],
                mitre_focus=["TA0043", "TA0001", "TA0002", "TA0007"],
                stealth_weight=0.35,
                speed_weight=0.35,
                impact_weight=0.30,
            ),
            "stealth_recon": ThreatProfile(
                name="Stealth Recon",
                objective_bias=["collect_intelligence", "minimize_detection"],
                preferred_vectors=["osint_gathering", "port_scan", "technology_fingerprint"],
                mitre_focus=["TA0043", "TA0007", "TA0005"],
                stealth_weight=0.60,
                speed_weight=0.20,
                impact_weight=0.20,
            ),
            "rapid_disruption": ThreatProfile(
                name="Rapid Disruption",
                objective_bias=["initial_access", "impact"],
                preferred_vectors=["command_injection", "remote_code_execution", "weak_credentials"],
                mitre_focus=["TA0001", "TA0002", "TA0040"],
                stealth_weight=0.15,
                speed_weight=0.35,
                impact_weight=0.50,
            ),
            "credential_hunter": ThreatProfile(
                name="Credential Hunter",
                objective_bias=["credential_access", "lateral_movement"],
                preferred_vectors=["brute_force", "weak_credentials", "authentication_bypass"],
                mitre_focus=["TA0006", "TA0008", "TA0001"],
                stealth_weight=0.25,
                speed_weight=0.25,
                impact_weight=0.50,
            ),
        }

    def _get_threat_profile(self, mission: Mission) -> ThreatProfile:
        return self.threat_profiles.get(mission.threat_profile, self.threat_profiles["adaptive_baseline"])

    def _build_attack_playbook(self, mission: Mission) -> Dict[str, Any]:
        """Build ATT&CK-aware playbook from selected threat profile."""
        profile = self._get_threat_profile(mission)
        vectors = list(dict.fromkeys(profile.preferred_vectors))

        mitre_techniques: List[Dict[str, Any]] = []
        if self._mitre_mapper:
            for vector in vectors:
                technique_ids = self._mitre_mapper.finding_mappings.get(vector, [])
                for technique_id in technique_ids:
                    technique = self._mitre_mapper.get_technique(technique_id)
                    if not technique:
                        continue
                    mitre_techniques.append({
                        "id": technique.id,
                        "name": technique.name,
                        "tactic": technique.tactic.value,
                        "url": technique.url,
                    })

        return {
            "profile": mission.threat_profile,
            "profile_name": profile.name,
            "objective_bias": profile.objective_bias,
            "preferred_vectors": vectors,
            "mitre_focus": profile.mitre_focus,
            "mitre_techniques": mitre_techniques,
        }

    def _simulate_branches(self, mission: Mission) -> List[Dict[str, Any]]:
        """Generate branch what-if estimates for mission command decisions."""
        profile = self._get_threat_profile(mission)
        vulnerability_count = len(mission.intel.get("vulnerabilities", []))
        recon_signal = 1 if mission.intel.get("reconnaissance") else 0

        base_success = min(0.9, 0.35 + (0.03 * vulnerability_count) + (0.12 * recon_signal))
        base_detect = min(0.95, 0.25 + (0.02 * vulnerability_count))

        branches = [
            {
                "id": "branch_stealth",
                "name": "Stealth-First",
                "description": "Lower-noise vectors with slower progression.",
                "weights": {"stealth": 0.65, "speed": 0.15, "impact": 0.20},
                "estimated_success": round(max(0.05, base_success - 0.06 + (profile.stealth_weight * 0.08)), 3),
                "estimated_detection": round(max(0.01, base_detect - 0.14), 3),
            },
            {
                "id": "branch_balanced",
                "name": "Balanced Campaign",
                "description": "Balanced speed, stealth, and impact from profile defaults.",
                "weights": {
                    "stealth": profile.stealth_weight,
                    "speed": profile.speed_weight,
                    "impact": profile.impact_weight,
                },
                "estimated_success": round(base_success, 3),
                "estimated_detection": round(base_detect, 3),
            },
            {
                "id": "branch_impact",
                "name": "Impact-First",
                "description": "High-impact vectors with elevated detection probability.",
                "weights": {"stealth": 0.10, "speed": 0.30, "impact": 0.60},
                "estimated_success": round(min(0.98, base_success + 0.09), 3),
                "estimated_detection": round(min(0.99, base_detect + 0.18), 3),
            },
        ]

        for branch in branches:
            branch["score"] = round(
                (branch["estimated_success"] * 100.0)
                - (branch["estimated_detection"] * 45.0)
                + (branch["weights"]["impact"] * 20.0),
                2,
            )

        branches.sort(key=lambda x: x["score"], reverse=True)
        return branches

    def _record_audit_event(self, mission: Mission, event_type: str, payload: Dict[str, Any]):
        """Record tamper-evident audit event with chained signature."""
        previous_signature = mission.audit_events[-1]["signature"] if mission.audit_events else "GENESIS"
        event = {
            "seq": len(mission.audit_events) + 1,
            "timestamp": datetime.now().isoformat(),
            "phase": mission.phase.value,
            "type": event_type,
            "payload": payload,
            "prev_signature": previous_signature,
        }
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
        signature = hmac.new(
            self._audit_secret.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        event["signature"] = signature
        mission.audit_events.append(event)

    def _build_evidence_graph(self, mission: Mission) -> Dict[str, Any]:
        """Build linked evidence graph across findings, checkpoints, and audit events."""
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        nodes.append({"id": f"mission:{mission.id}", "type": "mission", "label": mission.id})

        for idx, finding in enumerate(mission.findings, start=1):
            fid = f"finding:{idx}"
            nodes.append({
                "id": fid,
                "type": "finding",
                "label": str(finding.get("type", "unknown")),
                "severity": str(finding.get("severity", "medium")).lower(),
            })
            edges.append({"from": f"mission:{mission.id}", "to": fid, "relation": "produced"})

        for idx, checkpoint in enumerate(mission.validation_checkpoints, start=1):
            cid = f"checkpoint:{idx}"
            nodes.append({
                "id": cid,
                "type": "checkpoint",
                "label": checkpoint.get("name", "validation"),
                "passed": bool(checkpoint.get("passed")),
            })
            edges.append({"from": f"mission:{mission.id}", "to": cid, "relation": "validated_by"})

        for idx, audit in enumerate(mission.audit_events, start=1):
            aid = f"audit:{idx}"
            nodes.append({
                "id": aid,
                "type": "audit_event",
                "label": audit.get("type", "event"),
                "signature": audit.get("signature", ""),
            })
            edges.append({"from": f"mission:{mission.id}", "to": aid, "relation": "audited_as"})
            if idx > 1:
                edges.append({"from": f"audit:{idx-1}", "to": aid, "relation": "hash_chain"})

        return {
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "node_count": len(nodes),
                "edge_count": len(edges),
                "audit_chain_length": len(mission.audit_events),
            },
        }
    
    def get_swarm_status(self) -> Dict[str, Any]:
        """Get status of the entire swarm"""
        return {
            "c2_status": self.get_status(),
            "agent_pool": self.agent_pool.get_status(),
            "active_missions": len(self.active_missions),
            "completed_missions": len(self.completed_missions),
            "missions": [
                self.get_mission_status(m.id) for m in self.active_missions.values()
            ]
        }
