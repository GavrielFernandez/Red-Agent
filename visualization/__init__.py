"""
Real-Time Attack Visualization Backend
======================================

WebSocket-based streaming for live attack visualization,
3D attack graphs, and real-time metrics.
"""

import json
import asyncio
import logging
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import deque

logger = logging.getLogger(__name__)


class EventType(Enum):
    """Attack visualization event types"""
    # Attack phases
    SCAN_START = "scan_start"
    SCAN_PROGRESS = "scan_progress"
    SCAN_COMPLETE = "scan_complete"
    
    # Discovery events
    HOST_DISCOVERED = "host_discovered"
    PORT_DISCOVERED = "port_discovered"
    SERVICE_IDENTIFIED = "service_identified"
    TECHNOLOGY_DETECTED = "technology_detected"
    
    # Vulnerability events
    VULN_DETECTED = "vuln_detected"
    VULN_CONFIRMED = "vuln_confirmed"
    VULN_EXPLOITED = "vuln_exploited"
    
    # Attack events
    ATTACK_START = "attack_start"
    ATTACK_PROGRESS = "attack_progress"
    ATTACK_SUCCESS = "attack_success"
    ATTACK_FAILED = "attack_failed"
    
    # Agent events
    AGENT_SPAWNED = "agent_spawned"
    AGENT_TASK = "agent_task"
    AGENT_COMPLETE = "agent_complete"
    AGENT_COMMUNICATION = "agent_communication"
    
    # System events
    METRICS_UPDATE = "metrics_update"
    LOG_MESSAGE = "log_message"
    ERROR = "error"


@dataclass
class VisualizationEvent:
    """Event for real-time visualization"""
    event_type: EventType
    timestamp: str
    data: Dict[str, Any]
    source: str = "system"
    target: str = ""
    severity: str = "info"
    
    def to_dict(self) -> Dict:
        return {
            "type": self.event_type.value,
            "timestamp": self.timestamp,
            "data": self.data,
            "source": self.source,
            "target": self.target,
            "severity": self.severity
        }


@dataclass
class AttackNode:
    """Node in attack graph"""
    id: str
    type: str  # host, service, vulnerability, exploit
    label: str
    data: Dict = field(default_factory=dict)
    position: Dict = field(default_factory=lambda: {"x": 0, "y": 0, "z": 0})
    status: str = "discovered"
    severity: str = "info"


@dataclass
class AttackEdge:
    """Edge in attack graph (connection between nodes)"""
    id: str
    source: str
    target: str
    type: str  # discovered, attacked, exploited
    label: str = ""
    animated: bool = False


class AttackGraph:
    """Manages the attack graph structure"""
    
    def __init__(self):
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: Dict[str, AttackEdge] = {}
        self._node_counter = 0
        self._edge_counter = 0
    
    def add_node(self, node_type: str, label: str, data: Dict = None, 
                 severity: str = "info") -> AttackNode:
        """Add a node to the graph"""
        self._node_counter += 1
        node_id = f"node_{self._node_counter}"
        
        # Calculate position based on type
        position = self._calculate_position(node_type)
        
        node = AttackNode(
            id=node_id,
            type=node_type,
            label=label,
            data=data or {},
            position=position,
            severity=severity
        )
        self.nodes[node_id] = node
        return node
    
    def add_edge(self, source_id: str, target_id: str, 
                 edge_type: str, label: str = "") -> Optional[AttackEdge]:
        """Add an edge to the graph"""
        if source_id not in self.nodes or target_id not in self.nodes:
            return None
        
        self._edge_counter += 1
        edge_id = f"edge_{self._edge_counter}"
        
        edge = AttackEdge(
            id=edge_id,
            source=source_id,
            target=target_id,
            type=edge_type,
            label=label,
            animated=edge_type in ["attacking", "exploiting"]
        )
        self.edges[edge_id] = edge
        return edge
    
    def _calculate_position(self, node_type: str) -> Dict:
        """Calculate 3D position based on node type (layered approach)"""
        import random
        
        # Z-layers for different node types
        z_layers = {
            "target": 0,
            "host": 20,
            "service": 40,
            "vulnerability": 60,
            "exploit": 80,
            "data": 100
        }
        
        z = z_layers.get(node_type, 50)
        
        # Spread nodes in X-Y plane with some randomness
        type_nodes = [n for n in self.nodes.values() if n.type == node_type]
        spread = len(type_nodes) * 30
        
        return {
            "x": random.uniform(-spread, spread),
            "y": random.uniform(-spread/2, spread/2),
            "z": z + random.uniform(-5, 5)
        }
    
    def update_node_status(self, node_id: str, status: str, 
                           severity: str = None) -> bool:
        """Update a node's status"""
        if node_id in self.nodes:
            self.nodes[node_id].status = status
            if severity:
                self.nodes[node_id].severity = severity
            return True
        return False
    
    def to_dict(self) -> Dict:
        """Export graph for frontend"""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type,
                    "label": n.label,
                    "data": n.data,
                    "position": n.position,
                    "status": n.status,
                    "severity": n.severity
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "id": e.id,
                    "source": e.source,
                    "target": e.target,
                    "type": e.type,
                    "label": e.label,
                    "animated": e.animated
                }
                for e in self.edges.values()
            ]
        }


class MetricsCollector:
    """Collects and aggregates real-time metrics"""
    
    def __init__(self, history_size: int = 100):
        self.history_size = history_size
        self.metrics = {
            "requests_per_second": deque(maxlen=history_size),
            "vulnerabilities_found": 0,
            "exploits_attempted": 0,
            "exploits_successful": 0,
            "hosts_scanned": 0,
            "ports_discovered": 0,
            "services_identified": 0,
            "attack_progress": 0,
            "agents_active": 0,
            "messages_exchanged": 0,
            "findings_by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "attack_vectors_used": {},
            "mitre_techniques": set(),
            "timeline": []
        }
        self._start_time = datetime.now()
    
    def record_event(self, event: VisualizationEvent):
        """Record an event and update metrics"""
        # Update timeline
        self.metrics["timeline"].append({
            "timestamp": event.timestamp,
            "type": event.event_type.value,
            "severity": event.severity
        })
        
        # Keep timeline manageable
        if len(self.metrics["timeline"]) > 1000:
            self.metrics["timeline"] = self.metrics["timeline"][-500:]
        
        # Update specific metrics based on event type
        if event.event_type == EventType.HOST_DISCOVERED:
            self.metrics["hosts_scanned"] += 1
        elif event.event_type == EventType.PORT_DISCOVERED:
            self.metrics["ports_discovered"] += 1
        elif event.event_type == EventType.SERVICE_IDENTIFIED:
            self.metrics["services_identified"] += 1
        elif event.event_type == EventType.VULN_DETECTED:
            self.metrics["vulnerabilities_found"] += 1
            severity = event.data.get("severity", "info").lower()
            if severity in self.metrics["findings_by_severity"]:
                self.metrics["findings_by_severity"][severity] += 1
        elif event.event_type == EventType.ATTACK_START:
            self.metrics["exploits_attempted"] += 1
            vector = event.data.get("vector", "unknown")
            self.metrics["attack_vectors_used"][vector] = \
                self.metrics["attack_vectors_used"].get(vector, 0) + 1
        elif event.event_type == EventType.ATTACK_SUCCESS:
            self.metrics["exploits_successful"] += 1
        elif event.event_type == EventType.AGENT_SPAWNED:
            self.metrics["agents_active"] += 1
        elif event.event_type == EventType.AGENT_COMPLETE:
            self.metrics["agents_active"] = max(0, self.metrics["agents_active"] - 1)
        elif event.event_type == EventType.AGENT_COMMUNICATION:
            self.metrics["messages_exchanged"] += 1
    
    def update_progress(self, progress: float):
        """Update attack progress (0-100)"""
        self.metrics["attack_progress"] = min(100, max(0, progress))
    
    def add_mitre_technique(self, technique_id: str):
        """Track MITRE technique coverage"""
        self.metrics["mitre_techniques"].add(technique_id)
    
    def get_summary(self) -> Dict:
        """Get current metrics summary"""
        elapsed = (datetime.now() - self._start_time).total_seconds()
        
        return {
            "elapsed_seconds": int(elapsed),
            "attack_progress": self.metrics["attack_progress"],
            "hosts_scanned": self.metrics["hosts_scanned"],
            "ports_discovered": self.metrics["ports_discovered"],
            "services_identified": self.metrics["services_identified"],
            "vulnerabilities_found": self.metrics["vulnerabilities_found"],
            "exploits_attempted": self.metrics["exploits_attempted"],
            "exploits_successful": self.metrics["exploits_successful"],
            "success_rate": (
                self.metrics["exploits_successful"] / self.metrics["exploits_attempted"] * 100
                if self.metrics["exploits_attempted"] > 0 else 0
            ),
            "agents_active": self.metrics["agents_active"],
            "messages_exchanged": self.metrics["messages_exchanged"],
            "findings_by_severity": self.metrics["findings_by_severity"],
            "attack_vectors": self.metrics["attack_vectors_used"],
            "mitre_techniques_covered": len(self.metrics["mitre_techniques"]),
            "mitre_techniques": list(self.metrics["mitre_techniques"])
        }


class VisualizationHub:
    """
    Central hub for real-time attack visualization.
    
    Manages:
    - WebSocket connections
    - Event streaming
    - Attack graph
    - Metrics collection
    """
    
    def __init__(self):
        self.clients: Set[Any] = set()  # WebSocket connections
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.attack_graph = AttackGraph()
        self.metrics = MetricsCollector()
        self.is_running = False
        self._broadcast_task = None
        
        logger.info("Visualization Hub initialized")
    
    async def start(self):
        """Start the visualization hub"""
        self.is_running = True
        self._broadcast_task = asyncio.create_task(self._broadcast_loop())
        logger.info("Visualization Hub started")
    
    async def stop(self):
        """Stop the visualization hub"""
        self.is_running = False
        if self._broadcast_task:
            self._broadcast_task.cancel()
            try:
                await self._broadcast_task
            except asyncio.CancelledError:
                pass
        logger.info("Visualization Hub stopped")
    
    def register_client(self, websocket: Any):
        """Register a new WebSocket client"""
        self.clients.add(websocket)
        logger.info(f"Client registered. Total clients: {len(self.clients)}")
        
        # Send initial state
        asyncio.create_task(self._send_initial_state(websocket))
    
    def unregister_client(self, websocket: Any):
        """Unregister a WebSocket client"""
        self.clients.discard(websocket)
        logger.info(f"Client unregistered. Total clients: {len(self.clients)}")
    
    async def _send_initial_state(self, websocket: Any):
        """Send initial state to new client"""
        initial_state = {
            "type": "initial_state",
            "graph": self.attack_graph.to_dict(),
            "metrics": self.metrics.get_summary()
        }
        await self._send_to_client(websocket, initial_state)
    
    async def emit_event(self, event: VisualizationEvent):
        """Emit an event to all connected clients"""
        # Record in metrics
        self.metrics.record_event(event)
        
        # Update graph based on event
        self._update_graph_from_event(event)
        
        # Queue for broadcast
        await self.event_queue.put(event)
    
    def emit_event_sync(self, event: VisualizationEvent):
        """Synchronous event emission (creates task)"""
        asyncio.create_task(self.emit_event(event))
    
    def _update_graph_from_event(self, event: VisualizationEvent):
        """Update attack graph based on event"""
        data = event.data
        
        if event.event_type == EventType.HOST_DISCOVERED:
            self.attack_graph.add_node(
                "host", 
                data.get("host", "Unknown"),
                data,
                "info"
            )
        
        elif event.event_type == EventType.PORT_DISCOVERED:
            node = self.attack_graph.add_node(
                "service",
                f"{data.get('port', '?')}/{data.get('protocol', 'tcp')}",
                data,
                "info"
            )
            # Connect to host
            host_nodes = [n for n in self.attack_graph.nodes.values() 
                         if n.type == "host" and data.get("host") in n.label]
            if host_nodes:
                self.attack_graph.add_edge(
                    host_nodes[0].id, node.id, "discovered"
                )
        
        elif event.event_type == EventType.VULN_DETECTED:
            severity = data.get("severity", "medium")
            node = self.attack_graph.add_node(
                "vulnerability",
                data.get("type", "Unknown Vulnerability"),
                data,
                severity
            )
        
        elif event.event_type == EventType.ATTACK_START:
            # Update edge to show attack
            target_id = data.get("target_node")
            if target_id and target_id in self.attack_graph.nodes:
                self.attack_graph.update_node_status(target_id, "attacking")
        
        elif event.event_type == EventType.ATTACK_SUCCESS:
            node = self.attack_graph.add_node(
                "exploit",
                f"Exploited: {data.get('vuln_type', 'Unknown')}",
                data,
                "critical"
            )
    
    async def _broadcast_loop(self):
        """Main broadcast loop"""
        while self.is_running:
            try:
                # Wait for events with timeout
                try:
                    event = await asyncio.wait_for(
                        self.event_queue.get(), 
                        timeout=1.0
                    )
                    await self._broadcast(event.to_dict())
                except asyncio.TimeoutError:
                    # Send periodic metrics update
                    await self._broadcast({
                        "type": "metrics_update",
                        "metrics": self.metrics.get_summary()
                    })
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Broadcast error: {e}")
    
    async def _broadcast(self, message: Dict):
        """Broadcast message to all clients"""
        if not self.clients:
            return
        
        message_str = json.dumps(message)
        
        disconnected = set()
        for client in self.clients:
            try:
                await self._send_to_client(client, message)
            except Exception:
                disconnected.add(client)
        
        # Remove disconnected clients
        for client in disconnected:
            self.clients.discard(client)
    
    async def _send_to_client(self, client: Any, message: Dict):
        """Send message to a specific client"""
        try:
            if hasattr(client, 'send'):
                await client.send(json.dumps(message))
            elif hasattr(client, 'send_json'):
                await client.send_json(message)
        except Exception as e:
            logger.debug(f"Failed to send to client: {e}")
            raise
    
    def get_graph(self) -> Dict:
        """Get current attack graph"""
        return self.attack_graph.to_dict()
    
    def get_metrics(self) -> Dict:
        """Get current metrics"""
        return self.metrics.get_summary()
    
    def create_event(self, event_type: EventType, data: Dict,
                     source: str = "system", target: str = "",
                     severity: str = "info") -> VisualizationEvent:
        """Helper to create events"""
        return VisualizationEvent(
            event_type=event_type,
            timestamp=datetime.now().isoformat(),
            data=data,
            source=source,
            target=target,
            severity=severity
        )


# Singleton instance
_visualization_hub: Optional[VisualizationHub] = None

def get_visualization_hub() -> VisualizationHub:
    """Get or create visualization hub singleton"""
    global _visualization_hub
    if _visualization_hub is None:
        _visualization_hub = VisualizationHub()
    return _visualization_hub
