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
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from .base_agent import (
    BaseAgent, AgentCapability, AgentMessage, AgentPool,
    AgentStatus, MessageType, Priority, TaskResult
)

logger = logging.getLogger(__name__)


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
        "successful": 0,
        "failed": 0,
        "success_rate": 0.0,
        "replan_count": 0,
        "fallback_attacks_used": False
    })


class CommandControl(BaseAgent):
    """
    Command & Control - The master orchestrator
    
    Coordinates the swarm, distributes tasks, aggregates results,
    and makes strategic decisions about attack progression.
    """
    
    def __init__(self, llm_client: Any = None, **kwargs):
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
        
        # Strategy
        self.attack_playbook: Dict[str, List[Dict]] = {}
        
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
        objectives: Optional[List[str]] = None
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
        
        mission = Mission(
            id=mission_id,
            target=target,
            target_type=target_type,
            objectives=objectives
        )
        
        self.active_missions[mission_id] = mission
        
        logger.info(f"Mission launched: {mission_id} targeting {target}")
        
        # Start the mission execution
        asyncio.create_task(self._execute_mission(mission))
        
        return mission
    
    async def _execute_mission(self, mission: Mission):
        """Execute a mission through all phases"""
        try:
            # Phase 1: Planning
            self._enter_phase(mission, MissionPhase.PLANNING, 0.05, "Planning attack strategy")
            await self._plan_attack(mission)
            
            # Phase 2: Reconnaissance
            self._enter_phase(mission, MissionPhase.RECONNAISSANCE, 0.15, "Starting reconnaissance")
            await self._execute_reconnaissance(mission)
            
            # Phase 3: Vulnerability Discovery
            self._enter_phase(mission, MissionPhase.VULNERABILITY_DISCOVERY, 0.35, "Discovering vulnerabilities")
            await self._execute_vulnerability_discovery(mission)
            
            # Phase 4: Exploitation
            self._enter_phase(mission, MissionPhase.EXPLOITATION, 0.55, "Executing exploitation")
            await self._execute_exploitation(mission)
            
            # Phase 5: Post-Exploitation
            self._enter_phase(mission, MissionPhase.POST_EXPLOITATION, 0.75, "Post-exploitation analysis")
            await self._execute_post_exploitation(mission)
            
            # Phase 6: Reporting
            self._enter_phase(mission, MissionPhase.REPORTING, 0.90, "Generating report")
            await self._generate_mission_report(mission)
            
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
                return

        if not self.llm_client:
            # Default strategy without LLM
            mission.intel["strategy"] = {
                "approach": "standard_assessment",
                "priority_targets": ["web_application", "authentication", "injection_points"],
                "tools": ["nmap", "sqlmap", "curl", "hydra"]
            }
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
        except Exception as e:
            logger.warning(f"LLM planning failed: {e}")
            mission.intel["strategy"] = {"approach": "standard", "planned": False}
    
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
        else:
            # Fallback: basic recon without specialized agent
            logger.warning("No ReconAgent available, using basic recon")
            mission.intel["reconnaissance"] = {"status": "basic", "agent": "none"}
    
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
        mission.intel["vulnerability_summary"] = {
            "total_discovered": len(discovered),
            "by_type": self._count_by(discovered, key="type"),
            "by_severity": self._count_by(discovered, key="severity")
        }
    
    async def _execute_exploitation(self, mission: Mission):
        """Execute exploitation attempts"""
        exploit_agents = self.agent_pool.find_by_capability("exploitation")
        if not exploit_agents:
            mission.intel["exploitation"] = []
            mission.attack_metrics["failed"] = mission.attack_metrics.get("failed", 0) + 1
            return
        
        vulnerabilities = mission.intel.get("vulnerabilities", [])
        exploitation_results = []

        sorted_vulns = self._prioritize_vulnerabilities(vulnerabilities)
        mission.attack_metrics["attempted"] = min(12, len(sorted_vulns))

        for vuln in sorted_vulns[:12]:
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
            else:
                mission.attack_metrics["failed"] = mission.attack_metrics.get("failed", 0) + 1

        if not sorted_vulns:
            # Fall back to deterministic low-noise probes when discovery returns empty.
            primary_agent = exploit_agents[0]
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
                mission.attack_metrics["successful"] = len(fallback.data.get("successful_exploits", []))
                mission.attack_metrics["failed"] = max(0, attempted_vectors - mission.attack_metrics["successful"])
        
        mission.intel["exploitation"] = exploitation_results
        attempted = max(1, mission.attack_metrics.get("attempted", 0))
        mission.attack_metrics["success_rate"] = round((mission.attack_metrics.get("successful", 0) / attempted) * 100.0, 2)

        if sorted_vulns:
            failed_attempts = max(0, min(12, len(sorted_vulns)) - len(exploitation_results))
            if failed_attempts > 0:
                await self._request_replan(mission, failed_attempts, sorted_vulns[:12])

    async def _request_replan(self, mission: Mission, failed_attempts: int, attempted: List[Dict[str, Any]]):
        """Ask strategy agent to revise the mission approach when execution underperforms."""
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
                "attack_metrics": mission.attack_metrics
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
        
        mission = await self.launch_mission(target, target_type, objectives)
        
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
            "attack_metrics": mission.attack_metrics
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
