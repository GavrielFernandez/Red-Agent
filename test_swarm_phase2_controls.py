"""Phase 2 regression tests for playbook, evidence ledger, and what-if simulation APIs."""

import app as dashboard_app
from agents.command_control import CommandControl, Mission, MissionPolicy


def test_build_swarm_policy_includes_threat_profile():
    policy = dashboard_app._build_swarm_policy({"threat_profile": "Stealth_Recon"})
    assert policy["threat_profile"] == "stealth_recon"


def test_attack_playbook_enriches_mitre_techniques():
    c2 = CommandControl()
    mission = Mission(
        id="mission_playbook",
        target="https://example.com",
        target_type="url",
        objectives=["identify_vulnerabilities"],
        policy=MissionPolicy(threat_profile="credential_hunter"),
        threat_profile="credential_hunter",
    )

    playbook = c2._build_attack_playbook(mission)

    assert playbook["profile"] == "credential_hunter"
    assert "brute_force" in playbook["preferred_vectors"]
    assert any(t.get("id") == "T1110" for t in playbook.get("mitre_techniques", []))


def test_signed_audit_chain_and_evidence_graph_links():
    c2 = CommandControl()
    mission = Mission(
        id="mission_evidence",
        target="https://example.com",
        target_type="url",
        objectives=["identify_vulnerabilities"],
    )
    mission.findings = [
        {"type": "sql_injection", "severity": "high"},
        {"type": "xss", "severity": "medium"},
    ]

    c2._record_audit_event(mission, "mission_launched", {"target": mission.target})
    c2._record_audit_event(mission, "phase_transition", {"phase": "planning"})
    c2._record_validation_checkpoint(mission, "vuln_validation", True, {"validated": 2})

    graph = c2._build_evidence_graph(mission)

    assert len(mission.audit_events) >= 3
    assert mission.audit_events[0]["prev_signature"] == "GENESIS"
    assert mission.audit_events[1]["prev_signature"] == mission.audit_events[0]["signature"]
    assert graph["summary"]["audit_chain_length"] == len(mission.audit_events)
    assert any(edge.get("relation") == "hash_chain" for edge in graph.get("edges", []))


def test_what_if_endpoint_compares_branches(monkeypatch):
    monkeypatch.setattr(
        dashboard_app,
        "assessment_jobs",
        {
            "job_phase2": {
                "id": "job_phase2",
                "mode": "swarm",
                "swarm": {
                    "threat_profile": "adaptive_baseline",
                    "what_if_branches": [
                        {
                            "id": "branch_balanced",
                            "name": "Balanced Campaign",
                            "score": 75.0,
                            "estimated_success": 0.68,
                            "estimated_detection": 0.31,
                        },
                        {
                            "id": "branch_impact",
                            "name": "Impact-First",
                            "score": 70.0,
                            "estimated_success": 0.75,
                            "estimated_detection": 0.49,
                        },
                    ],
                },
            }
        },
    )

    with dashboard_app.app.test_client() as client:
        response = client.post(
            "/api/jobs/job_phase2/what-if",
            json={"branch_a": "branch_balanced", "branch_b": "branch_impact"},
        )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["comparison"]["recommended"] == "branch_balanced"
    assert payload["comparison"]["delta"]["score"] == 5.0
