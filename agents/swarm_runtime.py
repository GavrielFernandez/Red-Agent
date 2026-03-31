"""
Swarm Runtime
=============

Lightweight runtime that wires agent outboxes/inboxes and supports
message routing for C2-centered swarm collaboration.
"""

import threading
import time
from typing import List

from .base_agent import BaseAgent, AgentPool
from .command_control import CommandControl


class SwarmRuntime:
    """Routes inter-agent messages and manages lifecycle."""

    def __init__(self, c2: CommandControl, poll_interval: float = 0.05):
        self.c2 = c2
        self.poll_interval = poll_interval
        self._running = False
        self._thread = None
        self._agents: List[BaseAgent] = []

    def register(self, agent: BaseAgent):
        self.c2.register_agent(agent)
        self._agents.append(agent)

    def start(self):
        if self._running:
            return
        self._running = True
        self.c2.start()
        self._thread = threading.Thread(target=self._route_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        self.c2.agent_pool.stop_all()
        self.c2.stop()

    def _route_loop(self):
        while self._running:
            self._flush_agent_outboxes()
            time.sleep(self.poll_interval)

    def _flush_agent_outboxes(self):
        # Route from registered agents to either C2 or agent pool.
        for agent in list(self._agents):
            while not agent.outbox.empty():
                msg = agent.outbox.get_nowait()
                if msg.recipient == self.c2.agent_id:
                    self.c2.receive_message(msg)
                else:
                    self.c2.agent_pool.route_message(msg)

        # Route from C2 to recipient agents.
        while not self.c2.outbox.empty():
            msg = self.c2.outbox.get_nowait()
            self.c2.agent_pool.route_message(msg)
