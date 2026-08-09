"""Phase 1 regression tests for mission controls (ROE, kill switch, confidence gating)."""

import asyncio

import app as dashboard_app
from agents.command_control import CommandControl, Mission, MissionPolicy


def test_build_swarm_policy_normalizes_values():
    policy = dashboard_app._build_swarm_policy(
        {
            "allowed_target_types": ["URL", "ip"],
            "forbidden_attack_types": ["sql_injection", "xss"],
            "min_confidence_for_exploitation": 88,
            "require_validation_for_exploitation": True,
            "max_replans": "4",
        }
    )

    assert policy["allowed_target_types"] == ["url", "ip"]
    assert policy["forbidden_attack_types"] == ["sql_injection", "xss"]
    assert policy["min_confidence_for_exploitation"] == 1.0
    assert policy["require_validation_for_exploitation"] is True
    assert policy["max_replans"] == 4


def test_cancel_endpoint_triggers_kill_switch(monkeypatch):
    monkeypatch.setattr(dashboard_app, "assessment_jobs", {
        "job_demo": {
            "id": "job_demo",
            "status": "running",
            "mode": "swarm",
            "progress": 42,
            "swarm": {
                "kill_switch": {
                    "armed": True,
                    "triggered": False,
                    "triggered_at": None,
                    "reason": None,
                }
            }
        }
    })
    monkeypatch.setattr(dashboard_app, "active_swarm_sessions", {})

    with dashboard_app.app.test_client() as client:
        response = client.post("/api/jobs/job_demo/cancel")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "cancelled"

    job = dashboard_app.assessment_jobs["job_demo"]
    assert job["status"] == "cancelled"
    assert job["swarm"]["kill_switch"]["triggered"] is True
    assert job["swarm"]["kill_switch"]["reason"] == "Cancelled by user"


def test_confidence_gate_splits_validated_and_deferred():
    c2 = CommandControl()
    mission = Mission(
        id="mission_test",
        target="https://example.com",
        target_type="url",
        objectives=["identify_vulnerabilities"],
        policy=MissionPolicy(
            min_confidence_for_exploitation=0.7,
            require_validation_for_exploitation=True,
        ),
    )

    vulns = [
        {"id": "v1", "type": "sql_injection", "confidence": 0.9},
        {"id": "v2", "type": "xss", "confidence": 0.4},
        {"id": "v3", "type": "idor", "confidence_score": 81},
    ]

    validated, deferred = c2._apply_confidence_gate(mission, vulns)

    assert len(validated) == 2
    assert len(deferred) == 1
    assert deferred[0]["id"] == "v2"


def test_kill_switch_callback_cancels_mission_early():
    async def _run_case():
        c2 = CommandControl(kill_switch_check=lambda mission=None: True)
        mission = await c2.launch_mission(target="https://example.com", target_type="url")

        for _ in range(20):
            if mission.status == "cancelled":
                break
            await asyncio.sleep(0.02)

        assert mission.status == "cancelled"
        assert mission.kill_switch_triggered is True

    asyncio.run(_run_case())
