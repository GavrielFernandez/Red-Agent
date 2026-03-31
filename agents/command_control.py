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
            mission.phase = MissionPhase.PLANNING
            self.set_progress(0.05, "Planning attack strategy")
            await self._plan_attack(mission)
            
            # Phase 2: Reconnaissance
            mission.phase = MissionPhase.RECONNAISSANCE
            self.set_progress(0.15, "Starting reconnaissance")
            await self._execute_reconnaissance(mission)
            
            # Phase 3: Vulnerability Discovery
            mission.phase = MissionPhase.VULNERABILITY_DISCOVERY
            self.set_progress(0.35, "Discovering vulnerabilities")
            await self._execute_vulnerability_discovery(mission)
            
            # Phase 4: Exploitation
            mission.phase = MissionPhase.EXPLOITATION
            self.set_progress(0.55, "Executing exploitation")
            await self._execute_exploitation(mission)
            
            # Phase 5: Post-Exploitation
            mission.phase = MissionPhase.POST_EXPLOITATION
            self.set_progress(0.75, "Post-exploitation analysis")
            await self._execute_post_exploitation(mission)
            
            # Phase 6: Reporting
            mission.phase = MissionPhase.REPORTING
            self.set_progress(0.90, "Generating report")
            await self._generate_mission_report(mission)
            
            # Complete
            mission.phase = MissionPhase.COMPLETED
            mission.completed_at = datetime.now()
            mission.status = "completed"
            self.set_progress(1.0, "Mission complete")
            
            # Move to completed
            self.completed_missions.append(mission)
            del self.active_missions[mission.id]
            
            logger.info(f"Mission {mission.id} completed successfully")
            
        except Exception as e:
            logger.error(f"Mission {mission.id} failed: {e}")
            mission.status = "failed"
            mission.intel["error"] = str(e)
    
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
            result = await agent.run_with_retry({
                "id": f"{mission.id}_recon",
                "type": "full_recon",
                "target": mission.target,
                "target_type": mission.target_type
            })
            
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
            result = await agent.run_with_retry({
                "id": f"{mission.id}_vuln_scan",
                "type": "vulnerability_scan",
                "target": mission.target,
                "intel": mission.intel.get("reconnaissance", {})
            })
            
            if result.success and result.data:
                discovered.extend(result.data.get("vulnerabilities", []))
                mission.findings.extend(agent.findings)

        # Run business logic analysis in the same phase and merge results.
        for agent in logic_agents:
            result = await agent.run_with_retry({
                "id": f"{mission.id}_business_logic_scan",
                "type": "business_logic_scan",
                "target": mission.target,
                "intel": mission.intel.get("reconnaissance", {})
            })

            if result.success and result.data:
                discovered.extend(result.data.get("vulnerabilities", []))
                mission.intel["business_logic"] = result.data
                mission.findings.extend(agent.findings)
        
        mission.intel["vulnerabilities"] = discovered
    
    async def _execute_exploitation(self, mission: Mission):
        """Execute exploitation attempts"""
        exploit_agents = self.agent_pool.find_by_capability("exploitation")
        
        vulnerabilities = mission.intel.get("vulnerabilities", [])
        exploitation_results = []
        
        # Prioritize by severity
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                v.get("severity", "low").lower(), 4
            )
        )
        
        for vuln in sorted_vulns[:10]:  # Top 10 vulnerabilities
            for agent in exploit_agents:
                result = await agent.run_with_retry({
                    "id": f"{mission.id}_exploit_{vuln.get('id', 'unknown')}",
                    "type": "exploit",
                    "vulnerability": vuln,
                    "target": mission.target
                })
                
                if result.success:
                    exploitation_results.append({
                        "vulnerability": vuln,
                        "result": result.data,
                        "agent": agent.agent_id
                    })
                    mission.findings.extend(agent.findings)
                    break  # Move to next vuln if exploited
        
        mission.intel["exploitation"] = exploitation_results

        if sorted_vulns:
            failed_attempts = max(0, len(sorted_vulns[:10]) - len(exploitation_results))
            if failed_attempts > 0:
                await self._request_replan(mission, failed_attempts, sorted_vulns[:10])

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
            mission.intel["strategy_replan"] = result.data
    
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
            "agents_used": list(self.agent_pool.agents.keys())
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
            "completed_at": mission.completed_at.isoformat() if mission.completed_at else None
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
