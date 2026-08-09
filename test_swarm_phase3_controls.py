"""Phase 3 regression tests for governance budgets, branch control, and command recommendations."""

import app as dashboard_app
from agents.command_control import CommandControl, Mission, MissionPolicy


def test_build_swarm_policy_normalizes_phase3_fields():
    policy = dashboard_app._build_swarm_policy(
        {
            "max_attack_attempts": "99",
            "max_detection_rate": "120",
            "threat_profile": "Rapid_Disruption",
        }
    )

    assert policy["max_attack_attempts"] == 50
    assert policy["max_detection_rate"] == 100.0
    assert policy["threat_profile"] == "rapid_disruption"


def test_risk_budget_exceeded_cancels_mission_and_records_governance():
    c2 = CommandControl()
    mission = Mission(
        id="mission_budget",
        target="https://example.com",
        target_type="url",
        objectives=["identify_vulnerabilities"],
        policy=MissionPolicy(max_detection_rate=10.0),
    )
    mission.attack_metrics["detected"] = 2

    triggered = c2._risk_budget_exceeded(mission, current_attempts=1)

    assert triggered is True
    assert mission.status == "cancelled"
    assert mission.governance_actions
    assert mission.governance_actions[-1]["type"] == "risk_budget_stop"


def test_select_what_if_branch_applies_governance_tuning():
    c2 = CommandControl()
    mission = Mission(
        id="mission_branch",
        target="https://example.com",
        target_type="url",
        objectives=["identify_vulnerabilities"],
        policy=MissionPolicy(max_attack_attempts=20, max_detection_rate=90.0),
    )
    mission.what_if_branches = [
        {
            "id": "branch_stealth",
            "name": "Stealth-First",
            "weights": {"stealth": 0.65, "speed": 0.15, "impact": 0.20},
        }
    ]
    c2.active_missions[mission.id] = mission

    selected = c2.select_what_if_branch(mission.id, "branch_stealth")

    assert selected is not None
    assert mission.selected_branch == "branch_stealth"
    assert mission.policy.max_attack_attempts == 8
    assert mission.policy.max_detection_rate == 60.0
    assert mission.governance_actions[-1]["type"] == "branch_selected"


def test_command_recommendations_endpoint_returns_live_payload(monkeypatch):
    monkeypatch.setattr(
        dashboard_app,
        "assessment_jobs",
        {
            "job_phase3": {
                "id": "job_phase3",
                "mode": "swarm",
                "swarm": {
                    "selected_branch": "branch_balanced",
                    "governance_actions": [{"type": "branch_selected"}],
                    "command_recommendations": [{"action": "maintain_course", "priority": "info"}],
                    "policy": {"max_attack_attempts": 12, "max_detection_rate": 85.0},
                },
            }
        },
    )

    with dashboard_app.app.test_client() as client:
        response = client.get("/api/jobs/job_phase3/command-recommendations")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["selected_branch"] == "branch_balanced"
    assert payload["recommendations"][0]["action"] == "maintain_course"
