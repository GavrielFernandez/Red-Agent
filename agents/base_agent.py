"""
Base Agent Class - Foundation for all specialized agents
========================================================

Provides:
- Async execution framework
- Inter-agent communication
- State management
- Progress reporting
- Error recovery
"""

import asyncio
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
from queue import Queue
import threading
import json

logger = logging.getLogger(__name__)


class AgentStatus(Enum):
    """Agent lifecycle states"""
    IDLE = "idle"
    INITIALIZING = "initializing"
    RUNNING = "running"
    WAITING = "waiting"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"


class MessageType(Enum):
    """Inter-agent message types"""
    TASK = "task"
    RESULT = "result"
    INTEL = "intel"
    REQUEST = "request"
    RESPONSE = "response"
    ALERT = "alert"
    HEARTBEAT = "heartbeat"
    SHUTDOWN = "shutdown"


class Priority(Enum):
    """Message/Task priority levels"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


@dataclass
class AgentMessage:
    """
    Message for inter-agent communication
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    type: MessageType = MessageType.INTEL
    sender: str = ""
    recipient: str = ""  # Empty = broadcast
    priority: Priority = Priority.MEDIUM
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    requires_ack: bool = False
    ttl: int = 300  # Time to live in seconds
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "sender": self.sender,
            "recipient": self.recipient,
            "priority": self.priority.value,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
            "requires_ack": self.requires_ack,
            "ttl": self.ttl
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'AgentMessage':
        return cls(
            id=data.get("id", str(uuid.uuid4())[:8]),
            type=MessageType(data.get("type", "intel")),
            sender=data.get("sender", ""),
            recipient=data.get("recipient", ""),
            priority=Priority(data.get("priority", 3)),
            payload=data.get("payload", {}),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.now().isoformat())),
            requires_ack=data.get("requires_ack", False),
            ttl=data.get("ttl", 300)
        )


@dataclass
class AgentCapability:
    """Defines what an agent can do"""
    name: str
    description: str
    input_types: List[str]
    output_types: List[str]
    requirements: List[str] = field(default_factory=list)


@dataclass 
class TaskResult:
    """Result of a task execution"""
    task_id: str
    success: bool
    data: Any = None
    error: Optional[str] = None
    duration_ms: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseAgent(ABC):
    """
    Abstract base class for all RedAgent specialized agents.
    
    Features:
    - Async task execution
    - Message queue for communication
    - State management
    - Progress callbacks
    - Auto-recovery from failures
    """
    
    def __init__(
        self,
        agent_id: Optional[str] = None,
        name: str = "BaseAgent",
        llm_client: Any = None,
        max_retries: int = 3,
        timeout: int = 300
    ):
        self.agent_id = agent_id or f"{name.lower()}_{uuid.uuid4().hex[:6]}"
        self.name = name
        self.llm_client = llm_client
        self.max_retries = max_retries
        self.timeout = timeout
        
        # State
        self.status = AgentStatus.IDLE
        self.current_task: Optional[str] = None
        self.progress: float = 0.0
        
        # Communication
        self.inbox: Queue = Queue()
        self.outbox: Queue = Queue()
        self.message_handlers: Dict[MessageType, Callable] = {}
        
        # Intelligence storage
        self.knowledge_base: Dict[str, Any] = {}
        self.findings: List[Dict] = []
        
        # Metrics
        self.metrics = {
            "tasks_completed": 0,
            "tasks_failed": 0,
            "messages_sent": 0,
            "messages_received": 0,
            "total_runtime_ms": 0,
            "started_at": None,
            "last_active": None
        }
        
        # Threading
        self._running = False
        self._thread: Optional[threading.Thread] = None
        
        # Register default message handlers
        self._register_default_handlers()
        
        logger.info(f"Agent initialized: {self.agent_id}")
    
    def _register_default_handlers(self):
        """Register default message handlers"""
        self.message_handlers[MessageType.HEARTBEAT] = self._handle_heartbeat
        self.message_handlers[MessageType.SHUTDOWN] = self._handle_shutdown
    
    def _handle_heartbeat(self, msg: AgentMessage):
        """Respond to heartbeat"""
        self.send_message(AgentMessage(
            type=MessageType.HEARTBEAT,
            sender=self.agent_id,
            recipient=msg.sender,
            payload={"status": self.status.value, "progress": self.progress}
        ))
    
    def _handle_shutdown(self, msg: AgentMessage):
        """Handle shutdown request"""
        logger.info(f"Agent {self.agent_id} received shutdown signal")
        self.stop()
    
    @property
    @abstractmethod
    def capabilities(self) -> List[AgentCapability]:
        """Define agent capabilities"""
        pass
    
    @abstractmethod
    async def execute_task(self, task: Dict[str, Any]) -> TaskResult:
        """Execute a task - must be implemented by subclasses"""
        pass
    
    def start(self):
        """Start the agent's processing loop"""
        if self._running:
            return
        
        self._running = True
        self.status = AgentStatus.RUNNING
        self.metrics["started_at"] = datetime.now()
        
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        
        logger.info(f"Agent {self.agent_id} started")
    
    def stop(self):
        """Stop the agent"""
        self._running = False
        self.status = AgentStatus.TERMINATED
        
        if self._thread:
            self._thread.join(timeout=5)
        
        logger.info(f"Agent {self.agent_id} stopped")
    
    def _run_loop(self):
        """Main processing loop"""
        while self._running:
            try:
                # Process incoming messages
                while not self.inbox.empty():
                    msg = self.inbox.get_nowait()
                    self._process_message(msg)
                
                self.metrics["last_active"] = datetime.now()
                
                # Small sleep to prevent CPU spinning
                threading.Event().wait(0.1)
                
            except Exception as e:
                logger.error(f"Agent {self.agent_id} loop error: {e}")
    
    def _process_message(self, msg: AgentMessage):
        """Process an incoming message"""
        self.metrics["messages_received"] += 1
        
        handler = self.message_handlers.get(msg.type)
        if handler:
            try:
                handler(msg)
            except Exception as e:
                logger.error(f"Error handling message {msg.id}: {e}")
        else:
            logger.warning(f"No handler for message type: {msg.type}")
    
    def send_message(self, msg: AgentMessage):
        """Send a message to the outbox"""
        msg.sender = self.agent_id
        self.outbox.put(msg)
        self.metrics["messages_sent"] += 1
    
    def receive_message(self, msg: AgentMessage):
        """Receive a message into the inbox"""
        self.inbox.put(msg)
    
    def broadcast_intel(self, intel_type: str, data: Dict[str, Any]):
        """Broadcast intelligence to all agents"""
        self.send_message(AgentMessage(
            type=MessageType.INTEL,
            sender=self.agent_id,
            recipient="",  # Broadcast
            priority=Priority.MEDIUM,
            payload={"intel_type": intel_type, "data": data}
        ))
    
    def request_assistance(self, capability: str, data: Dict[str, Any]) -> str:
        """Request help from another agent with specific capability"""
        request_id = str(uuid.uuid4())[:8]
        self.send_message(AgentMessage(
            type=MessageType.REQUEST,
            sender=self.agent_id,
            recipient="",  # C2 will route
            priority=Priority.HIGH,
            payload={
                "request_id": request_id,
                "capability_needed": capability,
                "data": data
            }
        ))
        return request_id
    
    def add_finding(self, finding: Dict[str, Any]):
        """Add a security finding"""
        finding["agent_id"] = self.agent_id
        finding["timestamp"] = datetime.now().isoformat()
        self.findings.append(finding)
        
        # Broadcast critical findings
        severity = finding.get("severity", "low").lower()
        if severity in ["critical", "high"]:
            self.send_message(AgentMessage(
                type=MessageType.ALERT,
                sender=self.agent_id,
                priority=Priority.CRITICAL if severity == "critical" else Priority.HIGH,
                payload={"finding": finding}
            ))
    
    def update_knowledge(self, key: str, value: Any):
        """Update the knowledge base"""
        self.knowledge_base[key] = {
            "value": value,
            "updated_at": datetime.now().isoformat(),
            "source": self.agent_id
        }
    
    def get_knowledge(self, key: str) -> Optional[Any]:
        """Get knowledge by key"""
        entry = self.knowledge_base.get(key)
        return entry["value"] if entry else None
    
    def set_progress(self, progress: float, message: str = ""):
        """Update progress (0.0 - 1.0)"""
        self.progress = max(0.0, min(1.0, progress))
        if message:
            logger.info(f"[{self.agent_id}] {int(self.progress * 100)}% - {message}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "status": self.status.value,
            "progress": self.progress,
            "current_task": self.current_task,
            "findings_count": len(self.findings),
            "metrics": self.metrics,
            "capabilities": [c.name for c in self.capabilities]
        }
    
    async def run_with_retry(self, task: Dict[str, Any]) -> TaskResult:
        """Execute task with retry logic"""
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                self.current_task = task.get("id", "unknown")
                self.status = AgentStatus.RUNNING
                
                start_time = datetime.now()
                result = await self.execute_task(task)
                duration = (datetime.now() - start_time).total_seconds() * 1000
                
                self.metrics["tasks_completed"] += 1
                self.metrics["total_runtime_ms"] += duration
                
                return result
                
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Agent {self.agent_id} task attempt {attempt + 1} failed: {e}")
                
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        self.metrics["tasks_failed"] += 1
        self.status = AgentStatus.FAILED
        
        return TaskResult(
            task_id=task.get("id", "unknown"),
            success=False,
            error=f"Max retries exceeded. Last error: {last_error}"
        )


class AgentPool:
    """
    Pool of agents for parallel execution
    """
    
    def __init__(self):
        self.agents: Dict[str, BaseAgent] = {}
        self.capability_index: Dict[str, List[str]] = {}  # capability -> [agent_ids]
    
    def register(self, agent: BaseAgent):
        """Register an agent"""
        self.agents[agent.agent_id] = agent
        
        # Index capabilities
        for cap in agent.capabilities:
            if cap.name not in self.capability_index:
                self.capability_index[cap.name] = []
            self.capability_index[cap.name].append(agent.agent_id)
        
        logger.info(f"Registered agent: {agent.agent_id} with capabilities: {[c.name for c in agent.capabilities]}")
    
    def unregister(self, agent_id: str):
        """Unregister an agent"""
        if agent_id in self.agents:
            agent = self.agents[agent_id]
            agent.stop()
            
            # Remove from capability index
            for cap in agent.capabilities:
                if cap.name in self.capability_index:
                    self.capability_index[cap.name].remove(agent_id)
            
            del self.agents[agent_id]
    
    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Get agent by ID"""
        return self.agents.get(agent_id)
    
    def find_by_capability(self, capability: str) -> List[BaseAgent]:
        """Find agents with a specific capability"""
        agent_ids = self.capability_index.get(capability, [])
        return [self.agents[aid] for aid in agent_ids if aid in self.agents]
    
    def start_all(self):
        """Start all agents"""
        for agent in self.agents.values():
            agent.start()
    
    def stop_all(self):
        """Stop all agents"""
        for agent in self.agents.values():
            agent.stop()
    
    def get_status(self) -> Dict[str, Any]:
        """Get pool status"""
        return {
            "total_agents": len(self.agents),
            "agents": {aid: agent.get_status() for aid, agent in self.agents.items()},
            "capabilities": list(self.capability_index.keys())
        }
    
    def broadcast(self, msg: AgentMessage):
        """Broadcast message to all agents"""
        for agent in self.agents.values():
            agent.receive_message(msg)
    
    def route_message(self, msg: AgentMessage):
        """Route a message to the appropriate agent(s)"""
        if msg.recipient:
            # Direct message
            if msg.recipient in self.agents:
                self.agents[msg.recipient].receive_message(msg)
        else:
            # Broadcast
            self.broadcast(msg)
