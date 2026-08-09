"""Regression tests for dashboard backend and report viewer template behavior."""

from io import BytesIO
import json
from pathlib import Path

import app as dashboard_app
import intelligence.osint_hub as osint_hub_module


class _FakeOSINTHub:
    async def gather_intelligence(self, target: str, target_type: str = "domain"):
        return {
            "target": target,
            "target_type": target_type,
            "summary": {
                "total_sources_queried": 2,
                "successful_queries": 2,
                "total_ips_found": 1,
                "total_ports_found": 0,
            },
            "risk_indicators": [],
            "correlations": [],
        }


def test_osint_gather_returns_intelligence_payload(monkeypatch):
    """Configured OSINT routes should include gathered intelligence payload."""
    monkeypatch.setenv("SHODAN_API_KEY", "demo-key")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "demo-key")
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "demo-key")
    monkeypatch.setattr(osint_hub_module, "get_osint_hub", lambda api_keys=None: _FakeOSINTHub())

    with dashboard_app.app.test_client() as client:
        response = client.post("/api/osint/gather", json={"target": "example.com"})

    assert response.status_code == 200
    payload = response.get_json()

    assert payload["status"] == "ready"
    assert payload["target"] == "example.com"
    assert payload["target_type"] == "domain"
    assert payload["configured_count"] >= 3
    assert "intelligence" in payload
    assert payload["intelligence"]["summary"]["total_sources_queried"] == 2


def test_osint_gather_infers_url_target_type(monkeypatch):
    """URL input should be auto-classified as target_type=url when not provided."""
    monkeypatch.setenv("SHODAN_API_KEY", "demo-key")
    monkeypatch.setattr(osint_hub_module, "get_osint_hub", lambda api_keys=None: _FakeOSINTHub())

    with dashboard_app.app.test_client() as client:
        response = client.post("/api/osint/gather", json={"target": "https://example.com/login"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["target_type"] == "url"
    assert payload["intelligence"]["target_type"] == "url"


def test_report_viewer_has_timestamp_fallback():
    """Report viewer script should include robust fallback date parsing paths."""
    template_path = Path(__file__).resolve().parent / "templates" / "report_viewer.html"
    source = template_path.read_text(encoding="utf-8")

    assert "function formatReportDate(metadata)" in source
    assert "metadata?.date" in source
    assert "metadata?.timestamp" in source
    assert "return String(raw);" in source


def test_collect_tool_health_uses_cache(monkeypatch):
    """Tool health calls should reuse cached inventory during polling windows."""

    class _FakeFactory:
        def list_tools(self):
            return ["curl", "nmap"]

        def get_tool_descriptions(self):
            return {"curl": "curl", "nmap": "nmap"}

    calls = {"count": 0}

    def _fake_get_tool_factory(force_refresh=False):
        calls["count"] += 1
        return _FakeFactory()

    monkeypatch.setattr(dashboard_app, "_get_tool_factory", _fake_get_tool_factory)
    monkeypatch.setattr(dashboard_app, "tool_health_cache", {"expires_at": None, "data": None})

    first = dashboard_app._collect_tool_health()
    second = dashboard_app._collect_tool_health()

    assert first["summary"]["total"] == 2
    assert second["summary"]["total"] == 2
    assert calls["count"] == 1


def test_normalize_report_payload_derives_summary_and_finding_confidence():
    """Legacy reports should be normalized with derived summary and confidence values."""
    legacy_report = {
        "findings": [
            {
                "type": "xss",
                "severity": "high",
                "status": "confirmed",
                "location": "https://example.com",
                "description": "xss reflected",
                "evidence": "marker reflected",
            },
            {
                "type": "header_injection",
                "severity": "medium",
                "status": "potential",
                "location": "https://example.com/admin",
                "description": "header injection candidate",
                "evidence": "status changed",
            },
        ]
    }

    normalized = dashboard_app._normalize_report_payload(legacy_report, report_name="report_test.json")

    assert normalized["executive_summary"]["vulnerabilities_found"] == 2
    assert normalized["executive_summary"]["high_vulnerabilities"] == 1
    assert normalized["executive_summary"]["medium_vulnerabilities"] == 1
    assert normalized["metadata"]["report_file"] == "report_test.json"
    assert all(int(item.get("confidence_score", 0)) > 0 for item in normalized["findings"])


def test_import_report_endpoint_accepts_multipart_json(monkeypatch, tmp_path):
    """Report import endpoint should accept uploaded JSON and save it with a safe report name."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logs").mkdir(parents=True, exist_ok=True)

    report_data = {
        "metadata": {"target": "https://example.com", "date": "2026-04-01T10:00:00"},
        "findings": [
            {
                "type": "xss",
                "severity": "high",
                "status": "confirmed",
                "location": "https://example.com",
                "description": "Cross-site scripting",
                "evidence": "marker",
            }
        ],
    }

    with dashboard_app.app.test_client() as client:
        response = client.post(
            "/api/reports/import",
            data={
                "file": (BytesIO(json.dumps(report_data).encode("utf-8")), "assessment_legacy.json")
            },
            content_type="multipart/form-data",
        )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["filename"].startswith("report_")

    saved_path = tmp_path / "logs" / payload["filename"]
    assert saved_path.exists()


def test_report_viewer_has_confidence_and_business_logic_fallbacks():
    """Report viewer should derive confidence and include business-logic fallback heuristics."""
    template_path = Path(__file__).resolve().parent / "templates" / "report_viewer.html"
    source = template_path.read_text(encoding="utf-8")

    assert "function deriveFindingConfidence(finding)" in source
    assert "validation?.confirmed" in source
    assert "function isBusinessLogicFinding(finding)" in source
    assert "workflow|approval|privilege|authorization|role|idor|coupon|checkout|tenant" in source
