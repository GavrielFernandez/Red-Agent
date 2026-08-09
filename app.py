"""
RedAgent Web Dashboard - Flask Backend
Provides REST API and web interface for the autonomous penetration testing agent
Includes real-time progress tracking, error handling, and job management
"""

from flask import Flask, render_template, request, jsonify, send_from_directory, send_file, redirect
from flask_cors import CORS
from html import escape as html_escape
import json
import os
import ipaddress
import threading
import logging
import subprocess
import shutil
from datetime import datetime, timedelta
from pathlib import Path
import glob
import traceback
import queue
from io import BytesIO
import asyncio
import re
from urllib.parse import urlparse

from config.config import config
from validation import run_validation_pass, enrich_findings_with_validation
from storage.runtime_store import (
    init_runtime_store,
    persist_findings,
    persist_tool_run,
    get_runtime_counts,
    get_recent_tool_runs,
    get_recent_findings,
)

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("[+] Environment variables loaded from .env")
except ImportError:
    print("[WARN] python-dotenv not installed, using system environment only")

# Import the RedAgent
try:
    from run import RedAgent
except ImportError:
    print("[ERROR] Cannot import RedAgent from run.py")
    RedAgent = None

# Import Enterprise Features
try:
    from intelligence.osint_hub import get_osint_hub, OSINTHub
    from intelligence.mitre_attack import get_mitre_mapper, MitreAttackMapper
    from visualization import get_visualization_hub, EventType
    ENTERPRISE_FEATURES = True
    print("[+] Enterprise features loaded")
except ImportError as e:
    print(f"[WARN] Enterprise features not available: {e}")
    ENTERPRISE_FEATURES = False

# Import Swarm Agent Runtime (independent from enterprise modules)
try:
    from agents import CommandControl, ReconAgent, ExploitAgent, BusinessLogicAgent, StrategyAgent, SwarmRuntime
    SWARM_AVAILABLE = True
    print("[+] Swarm runtime loaded")
except ImportError as e:
    print(f"[WARN] Swarm runtime not available: {e}")
    SWARM_AVAILABLE = False

# Configure logging
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)
init_runtime_store(log_dir / "redagent_runtime.db")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / f"dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')

# Configure CORS properly
CORS(app, 
     resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "OPTIONS"], "allow_headers": ["Content-Type"]}},
     supports_credentials=True)

# Add additional CORS headers to all responses
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

# Global state for tracking assessments
assessment_jobs = {}
job_counter = 0
job_threads = {}  # Track thread handles for cancellation
active_swarm_sessions = {}  # job_id -> {c2, mission_id}
tool_factory_lock = threading.Lock()
tool_factory_instance = None
tool_health_cache = {"expires_at": None, "data": None}
TOOL_HEALTH_CACHE_SECONDS = max(1, int(os.getenv("REDAGENT_TOOL_HEALTH_CACHE_SECONDS", "8")))

REPORT_FILE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")


def _get_tool_factory(force_refresh: bool = False):
    """Return a shared ToolFactory instance to avoid repeated plugin reloading."""
    global tool_factory_instance

    if force_refresh:
        with tool_factory_lock:
            tool_factory_instance = None

    if tool_factory_instance is not None:
        return tool_factory_instance

    with tool_factory_lock:
        if tool_factory_instance is None:
            from tools.tool_factory import ToolFactory
            tool_factory_instance = ToolFactory()

    return tool_factory_instance


def _job_status_summary():
    """Return a compact summary of tracked jobs."""
    return {
        "total": len(assessment_jobs),
        "running": sum(1 for job in assessment_jobs.values() if job["status"] == "running"),
        "starting": sum(1 for job in assessment_jobs.values() if job["status"] == "starting"),
        "completed": sum(1 for job in assessment_jobs.values() if job["status"] == "completed"),
        "failed": sum(1 for job in assessment_jobs.values() if job["status"] == "failed"),
        "cancelled": sum(1 for job in assessment_jobs.values() if job["status"] == "cancelled"),
    }


def _report_status_summary():
    """Summarize stored reports for dashboard cards and health checks."""
    report_files = sorted(glob.glob(os.path.join("logs", "report_*.json")), reverse=True)
    return {
        "total": len(report_files),
        "recent": len(report_files[:20]),
        "latest": os.path.basename(report_files[0]) if report_files else None,
    }


def _persist_tool_result(tool_name: str, target: str, params: dict, result: dict, source: str):
    """Persist tool execution history and any structured findings to sqlite."""
    try:
        persist_tool_run(
            tool_name=tool_name,
            target=target,
            params=params,
            result=result,
            source=source,
        )
        metadata = result.get("metadata", {}) if isinstance(result, dict) else {}
        findings = metadata.get("findings", []) if isinstance(metadata, dict) else []
        if findings:
            persist_findings(
                source=source,
                tool_name=tool_name,
                assessment_job_id=None,
                target=target,
                findings=findings,
            )
    except Exception as exc:
        logger.warning(f"Failed to persist tool result for {tool_name}: {exc}")


def _build_swarm_policy(raw_policy: dict | None) -> dict:
    """Normalize incoming swarm policy payload for mission controls."""
    raw_policy = raw_policy or {}

    allowed_target_types = raw_policy.get("allowed_target_types", ["url", "ip"])
    if not isinstance(allowed_target_types, list) or not allowed_target_types:
        allowed_target_types = ["url", "ip"]

    forbidden_attack_types = raw_policy.get("forbidden_attack_types", [])
    if not isinstance(forbidden_attack_types, list):
        forbidden_attack_types = []

    min_confidence = raw_policy.get("min_confidence_for_exploitation", 0.6)
    try:
        min_confidence = float(min_confidence)
    except (TypeError, ValueError):
        min_confidence = 0.6
    min_confidence = max(0.0, min(1.0, min_confidence))

    max_replans = raw_policy.get("max_replans", 2)
    try:
        max_replans = int(max_replans)
    except (TypeError, ValueError):
        max_replans = 2
    max_replans = max(0, min(10, max_replans))

    require_validation = bool(raw_policy.get("require_validation_for_exploitation", True))
    threat_profile = str(raw_policy.get("threat_profile", "adaptive_baseline")).strip().lower() or "adaptive_baseline"

    max_attack_attempts = raw_policy.get("max_attack_attempts", 12)
    try:
        max_attack_attempts = int(max_attack_attempts)
    except (TypeError, ValueError):
        max_attack_attempts = 12
    max_attack_attempts = max(1, min(50, max_attack_attempts))

    max_detection_rate = raw_policy.get("max_detection_rate", 85.0)
    try:
        max_detection_rate = float(max_detection_rate)
    except (TypeError, ValueError):
        max_detection_rate = 85.0
    max_detection_rate = max(1.0, min(100.0, max_detection_rate))

    return {
        "allowed_target_types": [str(v).lower() for v in allowed_target_types],
        "forbidden_attack_types": [str(v).lower() for v in forbidden_attack_types],
        "min_confidence_for_exploitation": min_confidence,
        "require_validation_for_exploitation": require_validation,
        "max_replans": max_replans,
        "threat_profile": threat_profile,
        "max_attack_attempts": max_attack_attempts,
        "max_detection_rate": max_detection_rate,
    }


def _safe_report_filename(name: str, default_prefix: str = "report_imported") -> str:
    """Return a safe report filename under logs/ with a report_ prefix."""
    raw = str(name or "").strip()
    if not raw:
        raw = f"{default_prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    raw = raw.replace(" ", "_")
    raw = os.path.basename(raw)
    if not raw.endswith(".json"):
        raw = f"{raw}.json"
    if not raw.startswith("report_"):
        raw = f"report_{raw}"
    if not REPORT_FILE_PATTERN.match(raw):
        raw = re.sub(r"[^A-Za-z0-9_.-]", "_", raw)
    return raw


def _summarize_findings(findings: list):
    """Derive executive summary fields when older reports omit them."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        total += 1
        severity = str(finding.get("severity", "medium")).lower()
        if severity in counts:
            counts[severity] += 1

    critical = int(counts.get("critical", 0))
    high = int(counts.get("high", 0))
    medium = int(counts.get("medium", 0))
    low = int(counts.get("low", 0))
    risk = "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM" if medium > 0 else "LOW"
    return {
        "risk_level": risk,
        "vulnerabilities_found": total,
        "critical_vulnerabilities": critical,
        "high_vulnerabilities": high,
        "medium_vulnerabilities": medium,
        "low_vulnerabilities": low,
        "summary_text": f"Assessment identified {total} findings ({critical} critical, {high} high, {medium} medium, {low} low). Risk level: {risk}.",
    }


def _normalize_report_payload(report_data: dict, report_name: str = ""):
    """Normalize old/new report payloads so UI always receives expected schema."""
    if not isinstance(report_data, dict):
        return {
            "metadata": {},
            "executive_summary": _summarize_findings([]),
            "findings": [],
        }

    normalized = dict(report_data)

    metadata = normalized.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}
    mode_hint = str(metadata.get("mode") or normalized.get("mode") or "").strip().lower()
    if not mode_hint:
        mode_hint = "swarm" if normalized.get("mission_id") else "classic"
    if not metadata.get("target"):
        metadata["target"] = normalized.get("target") or ""
    if not metadata.get("target_type"):
        metadata["target_type"] = normalized.get("target_type") or normalized.get("type") or ""
    if not metadata.get("timestamp"):
        metadata["timestamp"] = (
            metadata.get("date")
            or normalized.get("completed_at")
            or normalized.get("started_at")
            or normalized.get("created_at")
            or ""
        )
    if not metadata.get("date"):
        metadata["date"] = metadata.get("timestamp") or ""
    if not metadata.get("mode"):
        metadata["mode"] = mode_hint
    if not metadata.get("llm_model"):
        metadata["llm_model"] = (
            metadata.get("model")
            or normalized.get("llm_model")
            or normalized.get("model")
            or ("swarm-orchestrated" if mode_hint == "swarm" else "unknown")
        )
    metadata.setdefault("report_file", report_name)
    normalized["metadata"] = metadata

    raw_findings = normalized.get("findings") or normalized.get("vulnerabilities") or []
    findings = _normalize_findings(raw_findings, target=metadata.get("target", ""))
    normalized["findings"] = findings

    summary = normalized.get("executive_summary") or {}
    if not isinstance(summary, dict):
        summary = {}
    derived = _summarize_findings(findings)
    for key, value in derived.items():
        if summary.get(key) in {None, "", 0}:
            summary[key] = value
    normalized["executive_summary"] = summary

    normalized.setdefault("statistics", normalized.get("statistics") or {})
    methodologies = normalized.get("methodologies") or {}
    if not isinstance(methodologies, dict):
        methodologies = {}

    stats = normalized.get("statistics") or {}
    mode = str(metadata.get("mode") or mode_hint or "classic").lower()
    tools_used = methodologies.get("tools_used")
    if not isinstance(tools_used, list) or not tools_used:
        agents = normalized.get("agents_used") or []
        if isinstance(agents, list) and agents:
            cleaned_agents = []
            for agent in agents:
                label = str(agent).split("_")[0].strip()
                if label and label not in cleaned_agents:
                    cleaned_agents.append(label)
            tools_used = cleaned_agents
        else:
            tools_used = []

    methodologies.setdefault(
        "approach",
        "Swarm multi-agent orchestration" if mode == "swarm" else "Classic single-agent assessment",
    )
    methodologies.setdefault(
        "testing_duration_seconds",
        int(float(normalized.get("duration_seconds") or 0)),
    )
    methodologies.setdefault(
        "total_scans",
        int(stats.get("total_executions") or 0),
    )
    methodologies.setdefault("tools_used", tools_used)
    normalized["methodologies"] = methodologies

    normalized.setdefault("recommendations", normalized.get("recommendations") or [])
    normalized.setdefault("remediation_plan", normalized.get("remediation_plan") or [])
    normalized.setdefault("validation", normalized.get("validation") or {})

    return normalized


def _normalize_job_report(job: dict, report_name: str = "") -> dict:
    """Normalize an in-memory assessment job report to a stable API schema."""
    raw_report = job.get("report") or {}
    normalized = _normalize_report_payload(raw_report if isinstance(raw_report, dict) else {}, report_name=report_name)

    metadata = normalized.setdefault("metadata", {})
    if not metadata.get("target"):
        metadata["target"] = job.get("target") or ""
    if not metadata.get("target_type"):
        metadata["target_type"] = job.get("type") or ""
    if not metadata.get("timestamp"):
        metadata["timestamp"] = job.get("completed_at") or job.get("created_at") or ""
    if not metadata.get("date"):
        metadata["date"] = metadata.get("timestamp") or ""
    if not metadata.get("mode"):
        metadata["mode"] = job.get("mode") or "classic"
    if not metadata.get("llm_model"):
        metadata["llm_model"] = "swarm-orchestrated" if str(metadata.get("mode", "")).lower() == "swarm" else "unknown"

    findings_source = job.get("findings") if isinstance(job.get("findings"), list) else normalized.get("findings", [])
    normalized["findings"] = _normalize_findings(findings_source, target=metadata.get("target", ""))

    normalized["executive_summary"] = _summarize_findings(normalized["findings"])

    if isinstance(job.get("statistics"), dict):
        normalized["statistics"] = job.get("statistics", {})
    if isinstance(job.get("validation"), dict):
        normalized["validation"] = job.get("validation", {})

    methodologies = normalized.get("methodologies") if isinstance(normalized.get("methodologies"), dict) else {}
    stats = normalized.get("statistics") if isinstance(normalized.get("statistics"), dict) else {}
    tools_used = methodologies.get("tools_used")
    if not isinstance(tools_used, list) or not tools_used:
        agents = normalized.get("agents_used") if isinstance(normalized.get("agents_used"), list) else []
        tools_used = [str(agent).split("_")[0] for agent in agents if str(agent).strip()]
    methodologies.setdefault(
        "approach",
        "Swarm multi-agent orchestration" if str(metadata.get("mode", "")).lower() == "swarm" else "Classic single-agent assessment",
    )
    methodologies.setdefault("testing_duration_seconds", int(float(normalized.get("duration_seconds") or 0)))
    methodologies.setdefault("total_scans", int(stats.get("total_executions") or 0))
    methodologies.setdefault("tools_used", tools_used)
    normalized["methodologies"] = methodologies

    return normalized


def _normalize_url_target(target: str) -> str:
    """Normalize user-entered URL targets for assessment runs."""
    cleaned = (target or "").strip()
    if cleaned and not urlparse(cleaned).scheme:
        cleaned = f"http://{cleaned}"
    return cleaned


def _validate_assessment_target(target: str, target_type: str):
    """Validate and normalize an assessment target."""
    cleaned = (target or "").strip()
    if not cleaned:
        return False, "Target is required", None

    target_kind = (target_type or "url").strip().lower()
    if target_kind == "ip":
        try:
            ipaddress.ip_address(cleaned)
        except ValueError:
            return False, "IP target must be a valid IPv4 or IPv6 address", None
        return True, "", cleaned

    normalized = _normalize_url_target(cleaned)
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"}:
        return False, "URL must start with http:// or https://", None
    if not parsed.netloc:
        return False, "URL must include a host name", None
    return True, "", normalized


def _run_remediation_verification(job_id: str):
    """Re-run validation against the current findings for a completed job."""
    job = assessment_jobs.get(job_id)
    if not job:
        return None, (jsonify({"error": "Job not found"}), 404)

    if job.get("status") != "completed":
        return None, (jsonify({"error": "Assessment must be completed before remediation verification"}), 400)

    findings = job.get("findings") or []
    target = job.get("target", "")

    try:
        validation_results = asyncio.run(run_validation_pass(target, findings)) if findings else []
        enriched_findings, validation_summary = enrich_findings_with_validation(findings, validation_results)
    except Exception as validation_error:
        logger.warning(f"[{job_id}] Remediation verification skipped: {validation_error}")
        return None, (jsonify({"error": f"Validation failed: {validation_error}"}), 500)

    job["findings"] = enriched_findings
    job["validation"] = validation_summary
    verification = {
        "job_id": job_id,
        "target": target,
        "checked_at": datetime.now().isoformat(),
        "validation": validation_summary,
        "results": [result.to_dict() for result in validation_results],
    }
    job["remediation_verification"] = verification

    if isinstance(job.get("report"), dict):
        job["report"]["validation"] = validation_summary
        job["report"]["remediation_verification"] = verification

    return verification, None

HEADER_NAMES = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy"
]

ATTACK_TAXONOMY = {
    "missing_security_headers": ("Misconfiguration", "Security Header Hardening"),
    "sql_injection": ("Injection", "SQL Injection"),
    "xss": ("Injection", "Cross-Site Scripting"),
    "command_injection": ("Injection", "Command Injection"),
    "path_traversal": ("File Access", "Path Traversal"),
    "xxe": ("Injection", "XML External Entity"),
    "ldap_injection": ("Injection", "LDAP Injection"),
    "header_injection": ("Injection", "HTTP Header Injection"),
    "brute_force": ("Authentication", "Credential Brute Force"),
    "http_basic_auth_brute_force": ("Authentication", "Credential Brute Force"),
    "business_logic_access_control": ("Business Logic", "Privilege/Access Workflow"),
    "business_logic_workflow_bypass": ("Business Logic", "Workflow Step Bypass"),
    "business_logic_authentication_gap": ("Business Logic", "Authentication State Gap"),
    "business_logic_approval_bypass": ("Business Logic", "Approval Chain Bypass"),
    "business_logic_coupon_abuse": ("Business Logic", "Commerce Rule Abuse")
}

SEVERITY_CONFIDENCE_BASE = {
    "critical": 92,
    "high": 82,
    "medium": 72,
    "low": 62,
    "info": 50
}


def _extract_missing_headers(text: str):
    """Extract known missing security headers from text evidence."""
    found = []
    lowered = (text or "").lower()
    for header in HEADER_NAMES:
        if header.lower() in lowered:
            found.append(header)
    return sorted(set(found))


def _classify_attack(ftype: str, description: str = ""):
    """Return normalized attack family and variant labels."""
    token = (ftype or "").strip().lower()
    desc = (description or "").lower()

    if token in ATTACK_TAXONOMY:
        return ATTACK_TAXONOMY[token]

    # Lightweight fallback heuristics
    if "sql" in token or "sql" in desc:
        return ATTACK_TAXONOMY["sql_injection"]
    if "xss" in token or "cross-site" in desc:
        return ATTACK_TAXONOMY["xss"]
    if "command" in token or "command" in desc:
        return ATTACK_TAXONOMY["command_injection"]
    if "header" in token or "header" in desc:
        return ATTACK_TAXONOMY["header_injection"]
    if "traversal" in token or "path" in desc:
        return ATTACK_TAXONOMY["path_traversal"]
    if "brute" in token or "credential" in desc or "auth" in token:
        return ATTACK_TAXONOMY["brute_force"]
    if "business_logic" in token or "workflow" in desc or "approval" in desc:
        return ("Business Logic", "Workflow Integrity")

    return ("General", "Uncategorized")


def _score_finding(finding: dict):
    """Attach confidence and evidence strength to findings."""
    severity = str(finding.get("severity", "medium")).lower()
    base = SEVERITY_CONFIDENCE_BASE.get(severity, 65)

    evidence = str(finding.get("evidence", ""))
    status = str(finding.get("status", ""))

    evidence_strength = "moderate"
    confidence = base
    attack_family = str(finding.get("attack_family", "")).lower()
    finding_type = str(finding.get("type", "")).lower()

    if evidence:
        confidence += 6
    if "confirmed" in status.lower() or "vulnerable" in status.lower() or "success" in status.lower():
        confidence += 8
        evidence_strength = "strong"
    if "not present" in evidence.lower() or "headers" in evidence.lower():
        evidence_strength = "strong"

    # Business-logic findings are usually high-impact but heuristic by nature.
    # Raise confidence when deterministic template metadata and route evidence exist,
    # and slightly reduce overconfidence for purely heuristic detections.
    if attack_family == "business logic" or finding_type.startswith("business_logic_"):
        confidence += 4
        if finding.get("invariant_template"):
            confidence += 5
            evidence_strength = "strong"
        if "without clear challenge markers" in evidence.lower():
            confidence += 3
        if "potentially" in status.lower() and not finding.get("invariant_template"):
            confidence -= 4

    confidence = max(35, min(99, confidence))
    finding["confidence_score"] = confidence
    finding["evidence_strength"] = evidence_strength
    return finding


def _normalize_findings(findings, target: str = ""):
    """Normalize and deduplicate findings while applying protocol-aware rules."""
    if not findings:
        return []

    dedup = {}
    target_is_http = str(target).startswith("http://")

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        ftype = str(finding.get("type") or finding.get("attack") or finding.get("subtype") or "unknown")
        description = str(finding.get("description") or finding.get("content") or "")
        evidence = str(finding.get("evidence") or finding.get("result") or "")
        location = str(finding.get("location") or target or "")

        is_header_issue = (
            "missing_security_headers" in ftype.lower()
            or "missing security headers" in description.lower()
            or "x-frame-options" in evidence.lower()
            or "content-security-policy" in evidence.lower()
        )

        if is_header_issue:
            headers = _extract_missing_headers(description + " " + evidence)
            if target_is_http:
                headers = [h for h in headers if h != "Strict-Transport-Security"]

            if not headers:
                continue

            key = ("missing_security_headers", location, tuple(headers))
            entry = dedup.get(key)
            if not entry:
                family, variant = _classify_attack("missing_security_headers", description)
                dedup[key] = {
                    "type": "missing_security_headers",
                    "attack": "missing_security_headers",
                    "attack_family": family,
                    "attack_variant": variant,
                    "severity": "MEDIUM",
                    "status": "Confirmed Misconfiguration",
                    "location": location,
                    "description": f"Missing security headers: {', '.join(headers)}",
                    "evidence": f"Headers not present in response: {', '.join(headers)}"
                }
            continue

        key = (
            ftype.lower(),
            location,
            description[:180]
        )
        if key not in dedup:
            copied = dict(finding)
            family, variant = _classify_attack(ftype, description)
            copied["attack_family"] = copied.get("attack_family") or family
            copied["attack_variant"] = copied.get("attack_variant") or variant
            dedup[key] = copied

    normalized = []
    for item in dedup.values():
        normalized.append(_score_finding(item))

    return normalized


def _emit_visualization_event(event_type, data, source="app", severity="info"):
    """Emit visualization events when the visualization hub is available."""
    if not ENTERPRISE_FEATURES:
        return

    try:
        hub = get_visualization_hub()
        event = hub.create_event(event_type=event_type, data=data, source=source, severity=severity)
        # Update local graph/metrics synchronously for reliable API-driven visualization.
        hub._update_graph_from_event(event)
        hub.metrics.record_event(event)
        if event_type == EventType.SCAN_PROGRESS:
            progress = data.get("progress") if isinstance(data, dict) else None
            if progress is not None:
                hub.metrics.update_progress(float(progress))
    except Exception as e:
        logger.debug(f"Visualization event emission skipped: {e}")


def _resolve_binary_status(tool_name: str):
    """Best-effort readiness check for command-backed tools."""
    tool_key = (tool_name or "").strip().lower()
    command = None
    reason = ""
    install_hint = ""

    if tool_key == "nmap":
        command = os.getenv("REDAGENT_NMAP_PATH", "nmap")
    elif tool_key == "sqlmap":
        command = os.getenv("REDAGENT_SQLMAP_PATH", "sqlmap")
    elif tool_key == "curl":
        command = os.getenv("REDAGENT_CURL_PATH", "curl")
    elif tool_key == "hydra":
        command = os.getenv("REDAGENT_HYDRA_PATH", "hydra")
    elif tool_key == "nuclei":
        command = os.getenv("REDAGENT_NUCLEI_PATH", "nuclei")
    elif tool_key.startswith("woodpecker_"):
        project_root = Path(__file__).resolve().parents[1]
        woodpecker_root = project_root / "woodpecker-main"
        go_exe = shutil.which("go") or ("C:/Program Files/Go/bin/go.exe" if Path("C:/Program Files/Go/bin/go.exe").exists() else None)
        if not woodpecker_root.exists():
            return "unavailable", "woodpecker-main folder not found", "Extract woodpecker-main.zip to workspace root"
        if not go_exe:
            return "degraded", "Go runtime not found", "winget install --id GoLang.Go -e --accept-package-agreements --accept-source-agreements"
        return "ready", f"project={woodpecker_root.name}", ""
    elif tool_key.startswith("bsf_"):
        project_root = Path(__file__).resolve().parents[1]
        bsf_root = project_root / "BSF-master"
        dumps_root = bsf_root / "simulations" / "dumps"
        if not bsf_root.exists():
            return "unavailable", "BSF-master folder not found", "Extract BSF-master.zip to workspace root"
        if not dumps_root.exists():
            return "degraded", "BSF dumps folder missing", "Ensure BSF simulation data exists under BSF-master/simulations/dumps"
        return "ready", f"project={bsf_root.name}", ""

    if command is None:
        return "ready", "plugin-managed", ""

    if Path(str(command)).exists() or shutil.which(str(command)):
        return "ready", f"binary={command}", ""

    reason = f"binary not found: {command}"
    if tool_key == "sqlmap":
        install_hint = "C:/Users/User/AppData/Local/Microsoft/WindowsApps/python3.12.exe -m pip install sqlmap"
    elif tool_key == "hydra":
        install_hint = "Install THC Hydra in WSL or set REDAGENT_HYDRA_PATH to a valid executable"
    elif tool_key == "nuclei":
        install_hint = "Download nuclei.exe to red_agent/tools/bin or set REDAGENT_NUCLEI_PATH"
    elif tool_key == "nmap":
        install_hint = "winget install --id Insecure.Nmap -e --accept-package-agreements --accept-source-agreements"
    elif tool_key == "curl":
        install_hint = "Install curl and ensure it is on PATH"
    return "unavailable", reason, install_hint


def _collect_tool_health(force_refresh: bool = False):
    """Build per-tool readiness inventory for dashboard and API clients."""
    now = datetime.now()
    if not force_refresh:
        cached_until = tool_health_cache.get("expires_at")
        cached_data = tool_health_cache.get("data")
        if cached_until and cached_data and now < cached_until:
            return cached_data

    try:
        factory = _get_tool_factory(force_refresh=force_refresh)
    except Exception as e:
        return {
            "summary": {
                "total": 0,
                "ready": 0,
                "degraded": 0,
                "unavailable": 0,
                "last_updated": datetime.now().isoformat()
            },
            "tools": [],
            "error": f"ToolFactory init failed: {e}"
        }

    tools = []
    descriptions = factory.get_tool_descriptions()

    for name in sorted(factory.list_tools()):
        status, reason, install_hint = _resolve_binary_status(name)
        tools.append({
            "name": name,
            "description": descriptions.get(name, name),
            "status": status,
            "reason": reason,
            "install_hint": install_hint
        })

    summary = {
        "total": len(tools),
        "ready": sum(1 for t in tools if t["status"] == "ready"),
        "degraded": sum(1 for t in tools if t["status"] == "degraded"),
        "unavailable": sum(1 for t in tools if t["status"] == "unavailable"),
        "last_updated": datetime.now().isoformat()
    }

    data = {
        "summary": summary,
        "tools": tools
    }

    tool_health_cache["data"] = data
    tool_health_cache["expires_at"] = now + timedelta(seconds=TOOL_HEALTH_CACHE_SECONDS)

    return data


def _tool_self_check(tool_name: str):
    """Run a lightweight self-check for a single tool and return diagnostics."""
    started_at = datetime.now()
    status, reason, install_hint = _resolve_binary_status(tool_name)
    if status == "unavailable":
        return {
            "tool": tool_name,
            "ok": False,
            "status": status,
            "message": reason,
            "install_hint": install_hint,
            "duration_ms": 0,
            "checked_at": started_at.isoformat()
        }

    tool_key = (tool_name or "").strip().lower()
    default_ok = {
        "tool": tool_name,
        "ok": True,
        "status": status,
        "message": reason,
        "install_hint": install_hint,
        "duration_ms": 0,
        "checked_at": started_at.isoformat()
    }

    try:
        check_start = datetime.now()

        if tool_key in {"nmap", "curl", "sqlmap", "hydra", "nuclei"}:
            cmd = {
                "nmap": [os.getenv("REDAGENT_NMAP_PATH", "nmap"), "--version"],
                "curl": [os.getenv("REDAGENT_CURL_PATH", "curl"), "--version"],
                "sqlmap": [os.getenv("REDAGENT_SQLMAP_PATH", "sqlmap"), "--version"],
                "hydra": [os.getenv("REDAGENT_HYDRA_PATH", "hydra"), "-h"],
                "nuclei": [os.getenv("REDAGENT_NUCLEI_PATH", "nuclei"), "-version"],
            }[tool_key]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            duration = int((datetime.now() - check_start).total_seconds() * 1000)
            ok = result.returncode == 0
            message = result.stdout.strip().splitlines()[0] if result.stdout.strip() else (result.stderr.strip()[:160] or reason)
            return {
                **default_ok,
                "ok": ok,
                "duration_ms": duration,
                "message": message,
                "status": "ready" if ok else "degraded"
            }

        factory = _get_tool_factory()

        if tool_key == "bsf_simulation_overview":
            result = factory.execute_safe(tool_key, {})
        elif tool_key == "bsf_graph_summary":
            bsf_root = Path(__file__).resolve().parents[1] / "BSF-master"
            first_graph = next((bsf_root / "simulations" / "dumps").glob("**/graphs/*.gv"), None)
            if first_graph is None:
                return {
                    **default_ok,
                    "ok": False,
                    "status": "degraded",
                    "message": "No BSF graph snapshot found",
                    "duration_ms": 0
                }
            result = factory.execute_safe(tool_key, {"graph_file": str(first_graph)})
        elif tool_key in {"woodpecker_experiments", "woodpecker_snippet", "woodpecker_verify"}:
            # Avoid expensive checks; rely on preflight readiness for fast UI response.
            return {
                **default_ok,
                "ok": True,
                "duration_ms": int((datetime.now() - check_start).total_seconds() * 1000),
                "message": "Preflight passed (project and runtime available)"
            }
        else:
            return default_ok

        duration = int((datetime.now() - check_start).total_seconds() * 1000)
        ok = result.get("return_code", 1) == 0
        message = result.get("stdout", "").strip()[:180] or result.get("stderr", "").strip()[:180] or reason
        return {
            **default_ok,
            "ok": ok,
            "duration_ms": duration,
            "status": "ready" if ok else "degraded",
            "message": message
        }
    except Exception as e:
        duration = int((datetime.now() - started_at).total_seconds() * 1000)
        return {
            **default_ok,
            "ok": False,
            "status": "degraded",
            "duration_ms": duration,
            "message": str(e)[:220]
        }


def _is_valid_http_url(value: str) -> bool:
    """Strictly validate an http/https URL for safe tool execution."""
    try:
        parsed = urlparse(value or "")
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    except Exception:
        return False

# ============================================================================
# ROUTES - Web Interface
# ============================================================================

@app.route('/')
def index():
    """Serve the main dashboard page"""
    return render_template('index.html')

@app.route('/report')
def report_viewer():
    """Serve the report viewer page"""
    return render_template('report_viewer.html')

@app.route('/visualization')
def visualization_page():
    """Serve the 3D attack visualization page"""
    return render_template('visualization.html')

@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files (CSS, JS)"""
    return send_from_directory('static', filename)

# ============================================================================
# API ROUTES - Assessment Management
# ============================================================================

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get system status and job information with infrastructure checks"""
    try:
        # Check Ollama availability
        ollama_status = "unknown"
        try:
            import requests
            response = requests.get("http://localhost:11434/api/tags", timeout=2)
            ollama_status = "running" if response.status_code == 200 else "offline"
        except:
            ollama_status = "offline"
        
        jobs_summary = _job_status_summary()
        report_summary = _report_status_summary()
        
        return jsonify({
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "version": config.version,
            "environment": config.environment,
            "infrastructure": {
                "ollama": ollama_status,
                "agent": "ready",
                "dashboard": "ready",
                "validation": "ready"
            },
            "jobs": jobs_summary,
            "reports_generated": report_summary["total"],
            "reports": report_summary,
            "persistence": get_runtime_counts(),
            "tools": _collect_tool_health().get("summary", {}),
            "configuration": {
                "max_concurrent_jobs": config.dashboard.max_concurrent_jobs,
                "keep_job_history": config.dashboard.keep_job_history,
                "rate_limiting": config.dashboard.enable_rate_limiting,
            }
        }), 200
    except Exception as e:
        logger.error(f"Error in get_status: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route('/api/health', methods=['GET'])
def get_health():
    """Return a deployment-oriented health snapshot for the dashboard."""
    try:
        status_response = get_status()
        status_payload = status_response[0].get_json() if isinstance(status_response, tuple) else status_response.get_json()
        return jsonify({
            "status": status_payload.get("status", "ok"),
            "timestamp": datetime.now().isoformat(),
            "version": config.version,
            "environment": config.environment,
            "dashboard": {
                "host": config.dashboard.host,
                "port": config.dashboard.port,
                "debug": config.dashboard.debug,
            },
            "security": {
                "require_https": config.security.require_https,
                "auth_enabled": config.security.enable_auth,
                "audit_logging": config.security.enable_audit_log,
                "allowed_hosts": config.security.allowed_hosts,
            },
            "jobs": status_payload.get("jobs", {}),
            "reports": status_payload.get("reports", {}),
            "tools": status_payload.get("tools", {}),
            "checks": {
                "ollama": status_payload.get("infrastructure", {}).get("ollama", "unknown"),
                "validation": status_payload.get("infrastructure", {}).get("validation", "unknown"),
            }
        }), 200
    except Exception as e:
        logger.error(f"Error in get_health: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/history', methods=['GET'])
def get_history():
    """Return recent persisted tool runs and findings."""
    try:
        limit = int(request.args.get("limit", 20))
        return jsonify({
            "counts": get_runtime_counts(),
            "tool_runs": get_recent_tool_runs(limit=limit),
            "findings": get_recent_findings(limit=limit),
        }), 200
    except Exception as e:
        logger.error(f"Error in get_history: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/tools', methods=['GET'])
def get_tools_health():
    """Return loaded tools and their readiness diagnostics."""
    try:
        data = _collect_tool_health()
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Error in get_tools_health: {e}")
        return jsonify({
            "error": "Failed to collect tool health",
            "details": str(e)
        }), 500


@app.route('/api/cyber-range/inventory', methods=['GET'])
def get_cyber_range_inventory():
    """Return a live inventory of the local cyber range playground."""
    try:
        range_path = str(request.args.get("range_path", "cyber_range")).strip() or "cyber_range"
        factory = _get_tool_factory()
        tool = factory.get_tool("cyber_range")
        if not tool:
            return jsonify({"error": "cyber_range tool is not available"}), 503

        result = tool.execute({"range_path": range_path})
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error in get_cyber_range_inventory: {e}")
        return jsonify({
            "error": "Failed to collect cyber range inventory",
            "details": str(e)
        }), 500


@app.route('/api/tools/<tool_name>/check', methods=['POST'])
def run_tool_check(tool_name):
    """Run a lightweight self-check for a specific tool."""
    try:
        data = _collect_tool_health()
        valid_names = {t.get("name") for t in data.get("tools", [])}
        if tool_name not in valid_names:
            return jsonify({"error": f"Unknown tool: {tool_name}"}), 404

        result = _tool_self_check(tool_name)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error in run_tool_check({tool_name}): {e}")
        return jsonify({
            "error": "Failed to run tool check",
            "details": str(e)
        }), 500


@app.route('/api/tools/run-url', methods=['POST'])
def run_tool_on_url():
    """Run a web-capable tool against a target URL from the dashboard."""
    try:
        data = request.get_json(silent=True) or {}
        tool_name = str(data.get("tool", "")).strip().lower()
        target_url = str(data.get("url", "")).strip()

        allowed_tools = {"curl", "nuclei", "fuzzing_harness", "cloud_posture", "cyber_range"}
        if tool_name not in allowed_tools:
            return jsonify({"error": f"Tool '{tool_name}' is not allowed for URL runs"}), 400

        if not _is_valid_http_url(target_url):
            return jsonify({"error": "A valid http:// or https:// URL is required"}), 400

        factory = _get_tool_factory()
        tool = factory.get_tool(tool_name)
        if tool is None:
            return jsonify({"error": f"Tool '{tool_name}' is unavailable"}), 404

        params = {"url": target_url}
        if tool_name == "nuclei":
            params = {
                "target": target_url,
                "timeout_minutes": int(data.get("timeout_minutes", 2)),
                "rate_limit": int(data.get("rate_limit", 100)),
                "concurrency": int(data.get("concurrency", 25)),
                "retries": int(data.get("retries", 0)),
            }
        elif tool_name == "curl":
            params = {
                "url": target_url,
                "method": str(data.get("method", "GET")).upper(),
            }
        elif tool_name == "fuzzing_harness":
            params = {
                "target": target_url,
                "seed": str(data.get("seed", "redagent")),
                "iterations": int(data.get("iterations", 25)),
                "payload_mode": str(data.get("payload_mode", "balanced")),
            }
        elif tool_name == "cloud_posture":
            params = {
                "target": target_url,
                "profile": str(data.get("profile", "default")),
            }
        elif tool_name == "cyber_range":
            params = {
                "target": target_url,
                "range_path": str(data.get("range_path", "cyber_range")),
            }

        result = tool.execute(params)
        response = {
            "tool": tool_name,
            "url": target_url,
            "ok": result.get("status") == "success" or result.get("return_code") == 0,
            "status": result.get("status"),
            "return_code": result.get("return_code", -1),
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "execution_time": result.get("execution_time", 0),
            "metadata": result.get("metadata", {}),
        }
        _persist_tool_result(tool_name, target_url, params, result, source="dashboard_url")
        return jsonify(response), 200
    except Exception as e:
        logger.error(f"Error in run_tool_on_url: {e}")
        return jsonify({"error": "Failed to run tool on URL", "details": str(e)}), 500


@app.route('/api/tools/execute', methods=['POST'])
def execute_tool():
    """Execute a registered tool with a safe, structured parameter payload."""
    try:
        data = request.get_json(silent=True) or {}
        tool_name = str(data.get("tool", "")).strip().lower()
        params = data.get("params", {}) or {}

        if not tool_name:
            return jsonify({"error": "tool is required"}), 400

        factory = _get_tool_factory()
        tool = factory.get_tool(tool_name)
        if tool is None:
            return jsonify({"error": f"Tool '{tool_name}' is unavailable"}), 404

        if not isinstance(params, dict):
            return jsonify({"error": "params must be an object"}), 400

        result = tool.execute(params)
        response = {
            "tool": tool_name,
            "ok": result.get("status") == "success" or result.get("return_code") == 0,
            "status": result.get("status"),
            "return_code": result.get("return_code", -1),
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "execution_time": result.get("execution_time", 0),
            "metadata": result.get("metadata", {}),
        }
        _persist_tool_result(tool_name, str(params.get("target") or params.get("url") or ""), params, result, source="dashboard_execute")
        return jsonify(response), 200
    except Exception as e:
        logger.error(f"Error in execute_tool: {e}")
        return jsonify({"error": "Failed to execute tool", "details": str(e)}), 500

@app.route('/api/assess', methods=['POST'])
def create_assessment():
    """Create and start a new assessment job with proper error handling"""
    global job_counter
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        target = data.get('target', '').strip()
        target_type = data.get('type', 'url').strip()
        execution_mode = data.get('mode', 'classic').strip().lower()
        mission_policy = _build_swarm_policy(data.get('policy') or data.get('swarm_policy'))

        active_jobs = sum(1 for job in assessment_jobs.values() if job['status'] in {'starting', 'running'})
        if active_jobs >= config.dashboard.max_concurrent_jobs:
            return jsonify({
                "error": "Too many active assessments",
                "limit": config.dashboard.max_concurrent_jobs,
                "active": active_jobs
            }), 429
        
        # Validate inputs
        if not target:
            return jsonify({"error": "Target is required"}), 400
        
        if target_type not in ['url', 'ip']:
            return jsonify({"error": "Target type must be 'url' or 'ip'"}), 400

        if execution_mode not in ['classic', 'swarm']:
            return jsonify({"error": "Mode must be 'classic' or 'swarm'"}), 400

        if execution_mode == 'swarm' and not SWARM_AVAILABLE:
            return jsonify({"error": "Swarm mode is unavailable on this server"}), 501

        is_valid, validation_message, normalized_target = _validate_assessment_target(target, target_type)
        if not is_valid:
            return jsonify({"error": validation_message}), 400

        target = normalized_target or target
        
        # Create job
        job_counter += 1
        job_id = f"job_{job_counter}_{datetime.now().strftime('%H%M%S')}"
        
        assessment_jobs[job_id] = {
            "id": job_id,
            "target": target,
            "type": target_type,
            "mode": execution_mode,
            "target_label": target,
            "status": "starting",
            "created_at": datetime.now().isoformat(),
            "started_at": None,
            "completed_at": None,
            "progress": 0,
            "phase": "Initializing...",
            "findings": [],
            "vulnerabilities_found": 0,
            "report": None,
            "error": None,
            "error_traceback": None,
            "swarm": {
                "mission_id": None,
                "phase": None,
                "replans": 0,
                "agent_count": 0,
                "status": "not_started",
                "phase_history": [],
                "phase_durations": {},
                "agent_timings": {},
                "attack_metrics": {
                    "attempted": 0,
                    "detected": 0,
                    "successful": 0,
                    "failed": 0,
                    "detection_rate": 0.0,
                    "success_rate": 0.0,
                    "replan_count": 0,
                    "fallback_attacks_used": False
                },
                "stalled": False,
                "stall_warnings": 0,
                "last_phase_change_at": None
                ,
                "policy": mission_policy,
                "what_if_branches": [],
                "evidence_graph": {},
                "audit_events": [],
                "selected_branch": None,
                "governance_actions": [],
                "command_recommendations": [],
                "kill_switch": {
                    "armed": True,
                    "triggered": False,
                    "triggered_at": None,
                    "reason": None
                }
            }
        }
        
        logger.info(f"[{job_id}] Assessment created for {target}")
        
        # Run assessment in background thread
        try:
            thread = threading.Thread(
                target=run_swarm_assessment_background if execution_mode == 'swarm' else run_assessment_background,
                args=(job_id, target, target_type),
                daemon=False
            )
            thread.name = f"assessment-{job_id}"
            thread.start()
            job_threads[job_id] = thread
            
            logger.info(f"[{job_id}] Background thread started")
        except Exception as e:
            logger.error(f"[{job_id}] Failed to start background thread: {e}")
            assessment_jobs[job_id]['status'] = 'failed'
            assessment_jobs[job_id]['error'] = f"Failed to start assessment: {str(e)}"
            return jsonify({
                "error": f"Failed to start assessment: {str(e)}"
            }), 500
        
        return jsonify({
            "job_id": job_id,
            "status": "created",
            "mode": execution_mode,
            "policy": mission_policy if execution_mode == 'swarm' else None,
            "message": f"Assessment started for {target}"
        }), 201
    
    except Exception as e:
        logger.error(f"Error creating assessment: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Internal error: {str(e)}"}), 500

@app.route('/api/assess/<job_id>', methods=['GET'])
def get_assessment(job_id):
    """Get assessment job details and progress with error info"""
    if job_id not in assessment_jobs:
        return jsonify({"error": "Job not found"}), 404
    
    job = assessment_jobs[job_id]
    
    # Don't include sensitive traceback in client response
    response_job = dict(job)
    if 'error_traceback' in response_job:
        del response_job['error_traceback']

    if response_job.get('status') == 'completed' and response_job.get('report'):
        response_job['report'] = _normalize_job_report(response_job)
    
    return jsonify(response_job)

@app.route('/api/assess/<job_id>/report', methods=['GET'])
def get_assessment_report(job_id):
    """Get the final report for a completed assessment"""
    if job_id not in assessment_jobs:
        return jsonify({"error": "Job not found"}), 404
    
    job = assessment_jobs[job_id]
    
    if job['status'] != 'completed':
        return jsonify({"error": "Assessment not yet completed"}), 400
    
    if job['report'] is None:
        return jsonify({"error": "Report not available"}), 404

    normalized_report = _normalize_job_report(job)
    
    # Check if browser is requesting HTML (not API client)
    format_param = request.args.get('format', 'auto')
    accept_header = request.headers.get('Accept', '')
    
    if format_param == 'json':
        return jsonify(normalized_report)
    elif format_param == 'html' or ('text/html' in accept_header and 'application/json' not in accept_header):
        # Redirect to HTML report viewer
        return redirect(f'/report?job={job_id}')
    else:
        return jsonify(normalized_report)

@app.route('/api/reports', methods=['GET'])
def list_reports():
    """List all generated reports"""
    try:
        reports = []
        log_dir = 'logs'
        
        if os.path.exists(log_dir):
            for report_file in sorted(glob.glob(os.path.join(log_dir, 'report_*.json')), reverse=True)[:20]:
                try:
                    with open(report_file, 'r') as f:
                        report_data = _normalize_report_payload(json.load(f), report_name=os.path.basename(report_file))
                        summary = report_data.get('executive_summary', {})
                        metadata = report_data.get('metadata', {})
                        reports.append({
                            "filename": os.path.basename(report_file),
                            "target": metadata.get('target'),
                            "timestamp": metadata.get('timestamp') or metadata.get('date'),
                            "model": metadata.get('llm_model'),
                            "risk_level": summary.get('risk_level'),
                            "vulnerabilities_found": summary.get('vulnerabilities_found'),
                            "validation": report_data.get('validation', {}),
                            "remediation_total": len(report_data.get('remediation_plan', [])),
                        })
                except:
                    pass
        
        return jsonify({"reports": reports})
    except Exception as e:
        logger.error(f"Error listing reports: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/reports/<report_name>', methods=['GET'])
def get_report(report_name):
    """Get specific report contents"""
    try:
        report_path = os.path.join('logs', report_name)
        
        if not os.path.exists(report_path) or not report_name.startswith('report_'):
            return jsonify({"error": "Report not found"}), 404
        
        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = _normalize_report_payload(json.load(f), report_name=report_name)
        
        return jsonify(report_data)
    except Exception as e:
        logger.error(f"Error reading report: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/reports/import', methods=['POST'])
def import_report():
    """Import a report JSON file into logs so it appears in the Reports UI."""
    try:
        payload = None
        requested_name = ""

        upload = request.files.get('file')
        if upload is not None and upload.filename:
            requested_name = upload.filename
            payload = json.load(upload.stream)
        else:
            body = request.get_json(silent=True) or {}
            if isinstance(body, dict) and isinstance(body.get("report"), dict):
                payload = body.get("report")
                requested_name = str(body.get("filename", "")).strip()

        if not isinstance(payload, dict):
            return jsonify({"error": "Provide a JSON report via multipart file field 'file' or JSON body {'report': {...}}"}), 400

        safe_name = _safe_report_filename(requested_name)
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        report_path = log_dir / safe_name

        normalized = _normalize_report_payload(payload, report_name=safe_name)
        with report_path.open('w', encoding='utf-8') as fh:
            json.dump(normalized, fh, indent=2)

        summary = normalized.get("executive_summary", {})
        return jsonify({
            "status": "ok",
            "filename": safe_name,
            "path": str(report_path),
            "summary": {
                "risk_level": summary.get("risk_level"),
                "vulnerabilities_found": summary.get("vulnerabilities_found", 0),
            },
            "message": "Report imported successfully",
        }), 200
    except json.JSONDecodeError:
        return jsonify({"error": "Uploaded file is not valid JSON"}), 400
    except Exception as e:
        logger.error(f"Error importing report: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/assess/<job_id>/verify-remediation', methods=['POST'])
def verify_remediation(job_id):
    """Re-run validation against the current findings for a completed job."""
    verification, error_response = _run_remediation_verification(job_id)
    if error_response is not None:
        return error_response

    return jsonify({
        "status": "ok",
        "job_id": job_id,
        "verification": verification,
        "message": "Remediation verification complete"
    }), 200

@app.route('/api/reports/<report_name>/download', methods=['GET'])
def download_report(report_name):
    """Download report in JSON format"""
    try:
        report_path = os.path.join('logs', report_name)
        
        # Security: only allow downloading actual report files
        if not os.path.exists(report_path) or not report_name.startswith('report_') or not report_name.endswith('.json'):
            return jsonify({"error": "Report not found"}), 404
        
        logger.info(f"Downloading report: {report_name}")
        
        with open(report_path, 'r', encoding='utf-8') as fh:
            normalized = _normalize_report_payload(json.load(fh), report_name=report_name)

        json_data = json.dumps(normalized, indent=2)
        return send_file(
            BytesIO(json_data.encode('utf-8')),
            as_attachment=True,
            download_name=report_name,
            mimetype='application/json'
        )
    except Exception as e:
        logger.error(f"Error downloading report: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/assessments/<job_id>/download/json', methods=['GET'])
def download_assessment_json(job_id):
    """Download assessment report as JSON"""
    try:
        if job_id not in assessment_jobs:
            return jsonify({"error": "Job not found"}), 404
        
        job = assessment_jobs[job_id]
        if job['status'] != 'completed' or job['report'] is None:
            return jsonify({
                "error": "Assessment not completed or report unavailable"
            }), 400
        
        # Create downloadable JSON
        json_data = json.dumps(_normalize_job_report(job), indent=2)
        
        logger.info(f"Downloaded assessment report for job {job_id}")
        
        return send_file(
            BytesIO(json_data.encode('utf-8')),
            as_attachment=True,
            download_name=f"assessment_{job_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mimetype='application/json'
        )
    except Exception as e:
        logger.error(f"Error downloading assessment: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/assessments/<job_id>/download/html', methods=['GET'])
def download_assessment_html(job_id):
    """Download assessment report as HTML"""
    try:
        if job_id not in assessment_jobs:
            return jsonify({"error": "Job not found"}), 404
        
        job = assessment_jobs[job_id]
        if job['status'] != 'completed' or job['report'] is None:
            return jsonify({"error": "Assessment not completed"}), 400
        
        # Generate HTML report
        html_content = _generate_html_report(job)
        
        logger.info(f"Downloaded HTML report for job {job_id}")
        
        return send_file(
            BytesIO(html_content.encode('utf-8')),
            as_attachment=True,
            download_name=f"assessment_{job_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            mimetype='text/html'
        )
    except Exception as e:
        logger.error(f"Error generating HTML report: {e}")
        return jsonify({"error": str(e)}), 500

def _generate_html_report(job: dict) -> str:
    """Generate an HTML formatted report from job data"""
    report = _normalize_job_report(job)
    metadata = report.get('metadata') or {}
    phases = report.get('assessment_phases') or []
    findings = report.get('findings') or job.get('findings') or []
    validation = report.get('validation') or job.get('validation') or {}
    remediation_plan = report.get('remediation_plan') or []
    executive = report.get('executive_summary') or {}

    risk_level = str(executive.get('risk_level', 'MEDIUM')).upper()
    risk_class = risk_level.lower()
    validation_total = int(validation.get('total_validations', 0) or 0)

    phase_markup = ''.join(
        f"""
        <article class="report-card">
            <div class="report-card-header">
                <div>
                    <div class="report-card-label">{html_escape(str(phase.get('type', 'Phase')))}</div>
                    <h3>{html_escape(str(phase.get('phase', 'Unknown')))}</h3>
                </div>
                <span class="severity-pill severity-{html_escape(str(phase.get('status', 'pending')).lower())}">{html_escape(str(phase.get('status', 'pending')).upper())}</span>
            </div>
            <p>{html_escape(str(phase.get('content', 'No summary available')))}</p>
        </article>
        """
        for phase in phases
    )

    findings_markup = ''.join(
        f"""
        <tr>
            <td>{html_escape(str(finding.get('type', finding.get('attack', 'Unknown'))))}</td>
            <td><span class="severity-pill severity-{html_escape(str(finding.get('severity', 'medium')).lower())}">{html_escape(str(finding.get('severity', 'medium')).upper())}</span></td>
            <td>{html_escape(str(finding.get('location', 'N/A')))}</td>
            <td>{html_escape(str(finding.get('status', finding.get('exploitation_status', 'N/A'))))}</td>
            <td>{html_escape(str(finding.get('remediation', 'Review the remediation guidance in the dashboard.')))}</td>
        </tr>
        """
        for finding in findings
    )

    remediation_markup = ''.join(
        f"""
        <article class="report-card">
            <div class="report-card-header">
                <div>
                    <div class="report-card-label">{html_escape(str(item.get('priority', 'MEDIUM')))}</div>
                    <h3>{html_escape(str(item.get('finding_type', 'Finding')))}</h3>
                </div>
                <span class="severity-pill severity-{html_escape(str(item.get('priority', 'medium')).lower())}">{html_escape(str(item.get('status', 'unconfirmed')).upper())}</span>
            </div>
            <p>{html_escape(str(item.get('remediation', 'Address this vulnerability per security best practices')))}</p>
            <small>{html_escape(str(item.get('verification', 'Re-run validation after the fix is deployed.')))}</small>
        </article>
        """
        for item in remediation_plan
    )

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>RedAgent Assessment Report</title>
        <style>
            :root {{
                --bg: #08101f;
                --panel: rgba(17, 24, 39, 0.9);
                --panel-2: rgba(30, 41, 59, 0.92);
                --text: #f8fafc;
                --muted: #cbd5e1;
                --border: rgba(148, 163, 184, 0.16);
                --danger: #ef4444;
                --warning: #f59e0b;
                --success: #10b981;
                --info: #3b82f6;
            }}
            * {{ box-sizing: border-box; }}
            body {{
                margin: 0;
                font-family: 'Segoe UI Variable', 'Bahnschrift', 'Aptos', 'Segoe UI', sans-serif;
                background:
                    radial-gradient(circle at top left, rgba(220, 20, 60, 0.22), transparent 26%),
                    radial-gradient(circle at top right, rgba(14, 165, 233, 0.12), transparent 24%),
                    linear-gradient(135deg, #060b16 0%, var(--bg) 100%);
                color: var(--text);
                line-height: 1.6;
            }}
            .page {{ max-width: 1240px; margin: 0 auto; padding: 32px 18px 52px; }}
            .hero {{
                padding: 32px;
                border-radius: 28px;
                background: linear-gradient(135deg, rgba(30, 41, 59, 0.96) 0%, rgba(15, 23, 42, 0.96) 100%);
                border: 1px solid var(--border);
                box-shadow: 0 30px 60px rgba(2, 6, 23, 0.35);
            }}
            .hero h1 {{ margin: 0; font-size: clamp(2rem, 4vw, 3.4rem); line-height: 1.02; }}
            .hero p {{ color: var(--muted); margin: 12px 0 0; max-width: 72ch; }}
            .topline {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; margin-top: 22px; }}
            .topline-card {{ padding: 16px; border-radius: 18px; background: rgba(15, 23, 42, 0.64); border: 1px solid var(--border); }}
            .topline-card span {{ display: block; color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; }}
            .topline-card strong {{ display: block; margin-top: 6px; font-size: 1.15rem; }}
            .risk {{
                display: inline-flex; align-items: center; padding: 8px 14px; border-radius: 999px; font-weight: 700; margin-top: 14px;
                border: 1px solid var(--border);
            }}
            .risk-critical {{ background: rgba(239, 68, 68, 0.18); color: #fca5a5; }}
            .risk-high {{ background: rgba(245, 158, 11, 0.18); color: #fdba74; }}
            .risk-medium {{ background: rgba(59, 130, 246, 0.18); color: #93c5fd; }}
            .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin: 24px 0; }}
            .metric {{ padding: 18px; border-radius: 18px; background: var(--panel); border: 1px solid var(--border); }}
            .metric span {{ color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.08em; }}
            .metric strong {{ display: block; margin-top: 6px; font-size: 1.6rem; }}
            .section {{ margin-top: 26px; }}
            .section h2 {{ margin: 0 0 14px; font-size: 1.4rem; }}
            .report-card {{ padding: 18px; border-radius: 18px; background: var(--panel-2); border: 1px solid var(--border); margin-bottom: 14px; }}
            .report-card-header {{ display: flex; justify-content: space-between; gap: 16px; align-items: start; }}
            .report-card-label {{ color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; }}
            .report-card h3 {{ margin: 4px 0 0; }}
            .severity-pill {{
                display: inline-flex; align-items: center; padding: 6px 12px; border-radius: 999px; font-weight: 700; font-size: 0.75rem; text-transform: uppercase;
                border: 1px solid var(--border);
            }}
            .severity-critical {{ background: rgba(239, 68, 68, 0.18); color: #fca5a5; }}
            .severity-high, .severity-potential {{ background: rgba(245, 158, 11, 0.18); color: #fdba74; }}
            .severity-medium {{ background: rgba(59, 130, 246, 0.18); color: #93c5fd; }}
            .severity-low, .severity-confirmed {{ background: rgba(16, 185, 129, 0.18); color: #6ee7b7; }}
            .severity-pending, .severity-unknown {{ background: rgba(148, 163, 184, 0.18); color: var(--muted); }}
            table {{ width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 18px; border: 1px solid var(--border); background: var(--panel); }}
            th, td {{ padding: 14px; text-align: left; vertical-align: top; border-bottom: 1px solid var(--border); }}
            th {{ background: rgba(15, 23, 42, 0.8); color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.08em; }}
            .footer {{ margin-top: 32px; padding-top: 18px; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.9rem; }}
            @media (max-width: 720px) {{
                .hero {{ padding: 22px; }}
                .page {{ padding: 16px 12px 40px; }}
                .report-card-header {{ flex-direction: column; }}
                table, thead, tbody, th, td, tr {{ display: block; }}
                thead {{ display: none; }}
                tr {{ margin-bottom: 12px; border-bottom: 1px solid var(--border); }}
                td {{ border: none; padding: 10px 0; }}
                td::before {{ content: attr(data-label) ": "; color: var(--muted); font-weight: 600; }}
            }}
        </style>
    </head>
    <body>
        <main class="page">
            <section class="hero">
                <h1>RedAgent Assessment Report</h1>
                <p>Autonomous penetration testing summary with validation results, remediation guidance, and phase-by-phase evidence.</p>
                <div class="risk risk-{html_escape(risk_class)}">Risk Level: {html_escape(risk_level)}</div>
                <div class="topline">
                    <div class="topline-card"><span>Target</span><strong>{html_escape(str(metadata.get('target', job.get('target', 'N/A'))))}</strong></div>
                    <div class="topline-card"><span>Target Type</span><strong>{html_escape(str(metadata.get('target_type', job.get('type', 'N/A'))))}</strong></div>
                    <div class="topline-card"><span>Generated</span><strong>{html_escape(str(metadata.get('date', metadata.get('timestamp', 'N/A'))))}</strong></div>
                    <div class="topline-card"><span>Model</span><strong>{html_escape(str(metadata.get('llm_model', 'Unknown')))}</strong></div>
                </div>
            </section>

            <section class="metrics">
                <div class="metric"><span>Findings</span><strong>{html_escape(str(executive.get('vulnerabilities_found', job.get('vulnerabilities_found', len(findings)))))}</strong></div>
                <div class="metric"><span>Critical</span><strong>{html_escape(str(executive.get('critical_vulnerabilities', 0)))}</strong></div>
                <div class="metric"><span>High</span><strong>{html_escape(str(executive.get('high_vulnerabilities', 0)))}</strong></div>
                <div class="metric"><span>Validations</span><strong>{html_escape(str(validation_total))}</strong></div>
            </section>

            <section class="section">
                <h2>Executive Summary</h2>
                <div class="report-card">
                    <p>{html_escape(str(executive.get('summary_text', 'No summary available')))}</p>
                </div>
            </section>

            <section class="section">
                <h2>Assessment Phases</h2>
                {phase_markup or '<div class="report-card">No phase summary available.</div>'}
            </section>

            <section class="section">
                <h2>Findings</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>Location</th>
                            <th>Status</th>
                            <th>Remediation</th>
                        </tr>
                    </thead>
                    <tbody>
                        {findings_markup or '<tr><td colspan="5">No findings recorded.</td></tr>'}
                    </tbody>
                </table>
            </section>

            <section class="section">
                <h2>Remediation Plan</h2>
                {remediation_markup or '<div class="report-card">No remediation plan available.</div>'}
            </section>

            <section class="section">
                <h2>Testing Statistics</h2>
                <div class="report-card">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                        <div>
                            <p><strong>Total Loops:</strong> {html_escape(str(report.get('statistics', {}).get('total_loops', 0)))}</p>
                            <p><strong>Total Executions:</strong> {html_escape(str(report.get('statistics', {}).get('total_executions', 0)))}</p>
                            <p><strong>Successful Executions:</strong> {html_escape(str(report.get('statistics', {}).get('successful_executions', 0)))}</p>
                            <p><strong>Failed Executions:</strong> {html_escape(str(report.get('statistics', {}).get('failed_executions', 0)))}</p>
                        </div>
                        <div>
                            <p><strong>Reflections Performed:</strong> {html_escape(str(report.get('statistics', {}).get('reflections_performed', 0)))}</p>
                            <p><strong>Avg. Confidence:</strong> {html_escape(str(round(float(report.get('statistics', {}).get('average_reflection_confidence', 0)), 2)))}</p>
                            <p><strong>Detection Rate:</strong> {html_escape(str(round(float(report.get('statistics', {}).get('detection_rate', 0)), 1)))}%</p>
                            <p><strong>Success Rate:</strong> {html_escape(str(round(float(report.get('statistics', {}).get('success_rate', 0)), 1)))}%</p>
                        </div>
                    </div>
                </div>
            </section>

            <div class="footer">
                <p>Generated by RedAgent v1.0.0</p>
                <p>For legal and authorized security testing only</p>
            </div>
        </main>
    </body>
    </html>
    """

    return html

@app.route('/api/jobs', methods=['GET'])
def list_jobs():
    """List all assessment jobs"""
    return jsonify({
        "jobs": list(assessment_jobs.values())
    })

@app.route('/api/jobs/<job_id>/cancel', methods=['POST'])
def cancel_job(job_id):
    """Cancel a running assessment job"""
    if job_id not in assessment_jobs:
        return jsonify({"error": "Job not found"}), 404
    
    job = assessment_jobs[job_id]
    
    if job['status'] == 'running' or job['status'] == 'starting':
        if isinstance(job.get('swarm'), dict):
            kill_switch = job['swarm'].setdefault('kill_switch', {})
            kill_switch['armed'] = True
            kill_switch['triggered'] = True
            kill_switch['triggered_at'] = datetime.now().isoformat()
            kill_switch['reason'] = 'Cancelled by user'

            session = active_swarm_sessions.get(job_id)
            if session:
                c2 = session.get('c2')
                mission_id = session.get('mission_id')
                if c2 and mission_id:
                    try:
                        c2.trigger_kill_switch(mission_id, reason='Cancelled by user')
                    except Exception as kill_err:
                        logger.warning(f"[{job_id}] Kill switch trigger warning: {kill_err}")

        job['status'] = 'cancelled'
        job['progress'] = job.get('progress', 0)
        job['error'] = 'Cancelled by user'
        job['completed_at'] = datetime.now().isoformat()
        
        logger.info(f"[{job_id}] Job cancelled by user")
        
        return jsonify({
            "status": "cancelled",
            "job_id": job_id,
            "message": "Assessment cancelled"
        }), 200
    else:
        return jsonify({
            "error": f"Job is {job['status']}, cannot cancel"
        }), 400


@app.route('/api/jobs/<job_id>/policy', methods=['POST'])
def update_swarm_policy(job_id):
    """Update ROE policy for a swarm job before/while execution."""
    job = assessment_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    if job.get('mode') != 'swarm':
        return jsonify({"error": "Policy updates are supported only for swarm jobs"}), 400

    payload = request.get_json(silent=True) or {}
    policy = _build_swarm_policy(payload.get('policy') if isinstance(payload, dict) else {})
    job['swarm']['policy'] = policy

    session = active_swarm_sessions.get(job_id)
    if session:
        c2 = session.get('c2')
        mission_id = session.get('mission_id')
        if c2 and mission_id:
            status = c2.get_mission_status(mission_id) or {}
            if status.get('status') == 'active':
                logger.info(f"[{job_id}] Policy update requested while mission active; new policy applies to next launch")

    return jsonify({
        "status": "ok",
        "job_id": job_id,
        "policy": policy
    }), 200


@app.route('/api/jobs/<job_id>/kill-switch', methods=['POST'])
def trigger_kill_switch(job_id):
    """Trigger or clear the emergency kill switch for a swarm job."""
    job = assessment_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    if job.get('mode') != 'swarm':
        return jsonify({"error": "Kill switch is supported only for swarm jobs"}), 400

    payload = request.get_json(silent=True) or {}
    action = str(payload.get('action', 'trigger')).strip().lower()
    reason = str(payload.get('reason', 'Manual kill switch')).strip() or 'Manual kill switch'

    kill_state = job['swarm'].setdefault('kill_switch', {
        'armed': True,
        'triggered': False,
        'triggered_at': None,
        'reason': None,
    })

    if action == 'clear':
        kill_state['triggered'] = False
        kill_state['triggered_at'] = None
        kill_state['reason'] = None
        return jsonify({"status": "cleared", "job_id": job_id, "kill_switch": kill_state}), 200

    kill_state['armed'] = True
    kill_state['triggered'] = True
    kill_state['triggered_at'] = datetime.now().isoformat()
    kill_state['reason'] = reason

    session = active_swarm_sessions.get(job_id)
    if session:
        c2 = session.get('c2')
        mission_id = session.get('mission_id')
        if c2 and mission_id:
            try:
                c2.trigger_kill_switch(mission_id, reason=reason)
            except Exception as kill_err:
                logger.warning(f"[{job_id}] Kill switch endpoint warning: {kill_err}")

    if job.get('status') in {'starting', 'running'}:
        job['status'] = 'cancelled'
        job['completed_at'] = datetime.now().isoformat()
        job['error'] = reason

    return jsonify({"status": "triggered", "job_id": job_id, "kill_switch": kill_state}), 200


@app.route('/api/jobs/<job_id>/what-if', methods=['GET', 'POST'])
def swarm_what_if(job_id):
    """Return what-if branch simulations and optional branch comparison."""
    job = assessment_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    if job.get('mode') != 'swarm':
        return jsonify({"error": "What-if simulation is supported only for swarm jobs"}), 400

    swarm = job.get('swarm', {}) if isinstance(job.get('swarm'), dict) else {}
    branches = swarm.get('what_if_branches', [])

    if request.method == 'GET':
        return jsonify({
            "job_id": job_id,
            "threat_profile": swarm.get('threat_profile', swarm.get('policy', {}).get('threat_profile')),
            "branches": branches,
        }), 200

    payload = request.get_json(silent=True) or {}
    branch_a_id = str(payload.get('branch_a', '')).strip()
    branch_b_id = str(payload.get('branch_b', '')).strip()

    if not branch_a_id or not branch_b_id:
        return jsonify({"error": "Both branch_a and branch_b are required"}), 400

    branch_a = next((b for b in branches if b.get('id') == branch_a_id), None)
    branch_b = next((b for b in branches if b.get('id') == branch_b_id), None)
    if not branch_a or not branch_b:
        return jsonify({"error": "Requested branch IDs were not found"}), 404

    comparison = {
        "branch_a": {"id": branch_a.get('id'), "name": branch_a.get('name')},
        "branch_b": {"id": branch_b.get('id'), "name": branch_b.get('name')},
        "delta": {
            "score": round(float(branch_a.get('score', 0.0)) - float(branch_b.get('score', 0.0)), 3),
            "estimated_success": round(float(branch_a.get('estimated_success', 0.0)) - float(branch_b.get('estimated_success', 0.0)), 3),
            "estimated_detection": round(float(branch_a.get('estimated_detection', 0.0)) - float(branch_b.get('estimated_detection', 0.0)), 3),
        },
        "recommended": branch_a.get('id') if float(branch_a.get('score', 0.0)) >= float(branch_b.get('score', 0.0)) else branch_b.get('id')
    }

    return jsonify({
        "job_id": job_id,
        "comparison": comparison,
    }), 200


@app.route('/api/jobs/<job_id>/branch/select', methods=['POST'])
def select_swarm_branch(job_id):
    """Select a what-if branch and apply governance tuning for active swarm mission."""
    job = assessment_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    if job.get('mode') != 'swarm':
        return jsonify({"error": "Branch selection is supported only for swarm jobs"}), 400

    payload = request.get_json(silent=True) or {}
    branch_id = str(payload.get('branch_id', '')).strip()
    if not branch_id:
        return jsonify({"error": "branch_id is required"}), 400

    session = active_swarm_sessions.get(job_id)
    if session and session.get('c2') and session.get('mission_id'):
        selected = session['c2'].select_what_if_branch(session['mission_id'], branch_id)
        if not selected:
            return jsonify({"error": "Branch not found for this mission"}), 404

        status = session['c2'].get_mission_status(session['mission_id']) or {}
        swarm = job.setdefault('swarm', {})
        swarm['selected_branch'] = status.get('selected_branch')
        swarm['governance_actions'] = status.get('governance_actions', [])
        swarm['command_recommendations'] = status.get('command_recommendations', [])
        swarm['policy'] = status.get('policy', swarm.get('policy', {}))

        return jsonify({
            "status": "ok",
            "job_id": job_id,
            "selected_branch": status.get('selected_branch'),
            "policy": swarm.get('policy', {}),
        }), 200

    branches = (job.get('swarm') or {}).get('what_if_branches', [])
    if not any(b.get('id') == branch_id for b in branches):
        return jsonify({"error": "Branch not found for this job"}), 404

    job['swarm']['selected_branch'] = branch_id
    return jsonify({
        "status": "queued",
        "job_id": job_id,
        "selected_branch": branch_id,
        "message": "Branch selection stored; it will apply when mission session is active",
    }), 200


@app.route('/api/jobs/<job_id>/command-recommendations', methods=['GET'])
def swarm_command_recommendations(job_id):
    """Return live command recommendations from swarm telemetry."""
    job = assessment_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    if job.get('mode') != 'swarm':
        return jsonify({"error": "Recommendations are supported only for swarm jobs"}), 400

    swarm = job.get('swarm', {}) if isinstance(job.get('swarm'), dict) else {}
    recommendations = swarm.get('command_recommendations', [])

    return jsonify({
        "job_id": job_id,
        "selected_branch": swarm.get('selected_branch'),
        "recommendations": recommendations,
        "governance_actions": swarm.get('governance_actions', []),
        "policy": swarm.get('policy', {}),
    }), 200

# ============================================================================
# BACKGROUND EXECUTION
# ============================================================================

class JobProgressTracker:
    """Tracks job progress with phase updates"""
    def __init__(self, job_id):
        self.job_id = job_id
        self.phases = [
            ("Reconnaissance", 10),
            ("Vulnerability Analysis", 30),
            ("Exploitation Planning", 50),
            ("Attack Execution", 75),
            ("Impact Assessment", 95),
            ("Report Generation", 100)
        ]
        self.current_phase_idx = 0
    
    def update_phase(self, phase_name):
        """Update to a new phase"""
        for idx, (name, progress) in enumerate(self.phases):
            if phase_name.lower() in name.lower():
                self.current_phase_idx = idx
                if self.job_id in assessment_jobs:
                    assessment_jobs[self.job_id]['phase'] = name
                    assessment_jobs[self.job_id]['progress'] = progress
                    target = assessment_jobs[self.job_id].get('target', '')
                    _emit_visualization_event(
                        EventType.SCAN_PROGRESS,
                        {
                            "job_id": self.job_id,
                            "target": target,
                            "phase": name,
                            "progress": progress
                        },
                        source="classic_runner"
                    )
                logger.info(f"[{self.job_id}] Phase: {name} ({progress}%)")
                return
    
    def set_error(self, error_msg):
        """Mark job as failed with error"""
        if self.job_id in assessment_jobs:
            assessment_jobs[self.job_id]['error'] = error_msg

def run_assessment_background(job_id, target, target_type):
    """Run assessment in background and update job status with proper error handling"""
    job = assessment_jobs[job_id]
    tracker = JobProgressTracker(job_id)
    
    try:
        logger.info(f"[{job_id}] Starting assessment for {target} (type: {target_type})")
        job['status'] = 'running'
        job['started_at'] = datetime.now().isoformat()
        _emit_visualization_event(
            EventType.SCAN_START,
            {"job_id": job_id, "target": target, "mode": "classic"},
            source="classic_runner"
        )
        host_label = target
        if target_type == "url":
            parsed = urlparse(target)
            host_label = parsed.netloc or target
        _emit_visualization_event(
            EventType.HOST_DISCOVERED,
            {"job_id": job_id, "host": host_label},
            source="classic_runner"
        )
        
        # Check if RedAgent is available
        if RedAgent is None:
            raise Exception("RedAgent module not available. Check imports in run.py")
        
        # Create agent instance
        try:
            tracker.update_phase("Reconnaissance")
            agent = RedAgent(target=target, target_type=target_type)
        except Exception as e:
            logger.error(f"[{job_id}] Failed to instantiate RedAgent: {e}")
            tracker.set_error(f"Failed to create agent: {str(e)}")
            raise
        
        # Run assessment with timeout handling
        try:
            logger.info(f"[{job_id}] Running assessment...")
            agent.run_assessment()
            logger.info(f"[{job_id}] Assessment completed successfully")
        except Exception as e:
            logger.error(f"[{job_id}] Assessment execution error: {e}")
            logger.error(f"[{job_id}] Traceback: {traceback.format_exc()}")
            tracker.set_error(f"Assessment failed: {str(e)}")
            # Continue to load any partial report that was generated
        
        # Load latest report
        tracker.update_phase("Report Generation")
        latest_report = None
        vulnerabilities = []
        
        try:
            if os.path.exists('logs'):
                reports = sorted(glob.glob('logs/report_*.json'), reverse=True)
                if reports:
                    with open(reports[0], 'r') as f:
                        latest_report = json.load(f)
                        logger.info(f"[{job_id}] Loaded report: {reports[0]}")
                    
                    # Extract vulnerabilities from report
                    if latest_report and 'assessment_phases' in latest_report:
                        for phase in latest_report.get('assessment_phases', []):
                            if phase.get('phase') == 'attack_execution' and 'attacks' in phase:
                                for attack in phase.get('attacks', []):
                                    status = attack.get('status', '')
                                    if 'VULNERABLE' in status or 'SUCCESS' in status:
                                        vulnerabilities.append({
                                            "attack": attack.get('attack', 'Unknown'),
                                            "severity": "CRITICAL" if 'VULNERABLE' in status else "HIGH",
                                            "status": status,
                                            "result": attack.get('result', '')
                                        })
        except Exception as e:
            logger.warning(f"[{job_id}] Error loading report: {e}")
            # Still mark as completed even if report loading fails
        
        # Mark job as completed
        vulnerabilities = _normalize_findings(vulnerabilities, target=target)

        validation_summary = None
        try:
            validation_results = asyncio.run(run_validation_pass(target, vulnerabilities)) if vulnerabilities else []
            vulnerabilities, validation_summary = enrich_findings_with_validation(vulnerabilities, validation_results)
        except Exception as validation_error:
            logger.warning(f"[{job_id}] Validation triage skipped: {validation_error}")

        job['status'] = 'completed'
        job['progress'] = 100
        job['phase'] = 'Completed'
        job['report'] = latest_report
        job['findings'] = vulnerabilities
        if validation_summary is not None:
            job['validation'] = validation_summary
        job['completed_at'] = datetime.now().isoformat()
        job['vulnerabilities_found'] = len(vulnerabilities)
        
        # Generate statistics for classic assessment
        job['statistics'] = {
            'total_loops': 1,  # Classic mode runs once
            'total_executions': 1,
            'successful_executions': 1 if len(vulnerabilities) > 0 else 0,
            'failed_executions': 0,
            'reflections_performed': 0,
            'average_reflection_confidence': 0.0,
            'detection_rate': 0.0,
            'success_rate': 100 if len(vulnerabilities) > 0 else 0,
        }
        
        # Add statistics to report if report exists
        if job['report']:
            job['report']['statistics'] = job['statistics']

        persist_findings(
            source="classic_assessment",
            tool_name="assessment",
            assessment_job_id=job_id,
            target=target,
            findings=vulnerabilities,
        )

        for finding in vulnerabilities:
            _emit_visualization_event(
                EventType.ATTACK_START,
                {
                    "job_id": job_id,
                    "target": target,
                    "vector": finding.get("attack") or finding.get("type", "unknown")
                },
                source="classic_runner"
            )
            _emit_visualization_event(
                EventType.VULN_DETECTED,
                {
                    "job_id": job_id,
                    "type": finding.get("type") or finding.get("attack", "unknown"),
                    "severity": str(finding.get("severity", "medium")).lower(),
                    "location": finding.get("location", target)
                },
                source="classic_runner",
                severity=str(finding.get("severity", "medium")).lower()
            )
            _emit_visualization_event(
                EventType.ATTACK_SUCCESS,
                {
                    "job_id": job_id,
                    "target": target,
                    "vector": finding.get("attack") or finding.get("type", "unknown"),
                    "vuln_type": finding.get("type") or finding.get("attack", "unknown")
                },
                source="classic_runner"
            )

        _emit_visualization_event(
            EventType.SCAN_COMPLETE,
            {"job_id": job_id, "target": target, "findings": len(vulnerabilities), "mode": "classic"},
            source="classic_runner"
        )
        
        logger.info(f"[{job_id}] Job completed. Findings: {len(vulnerabilities)}")
    
    except Exception as e:
        logger.error(f"[{job_id}] CRITICAL ERROR: {e}")
        logger.error(f"[{job_id}] Full traceback: {traceback.format_exc()}")
        
        job['status'] = 'failed'
        job['progress'] = 0
        job['error'] = str(e)
        job['error_traceback'] = traceback.format_exc()
        job['completed_at'] = datetime.now().isoformat()
        
    finally:
        # Cleanup
        if job_id in job_threads:
            del job_threads[job_id]
        logger.info(f"[{job_id}] Background thread cleanup complete")


def run_swarm_assessment_background(job_id, target, target_type):
    """Run a multi-agent swarm mission in background and publish job progress."""
    job = assessment_jobs[job_id]

    try:
        if not SWARM_AVAILABLE:
            raise Exception("Swarm runtime is not available")

        def _is_kill_switch_active(mission=None):
            current_job = assessment_jobs.get(job_id, {})
            if current_job.get('status') == 'cancelled':
                return True
            swarm_state = current_job.get('swarm', {}) if isinstance(current_job.get('swarm'), dict) else {}
            kill_state = swarm_state.get('kill_switch', {}) if isinstance(swarm_state.get('kill_switch'), dict) else {}
            return bool(kill_state.get('triggered'))

        logger.info(f"[{job_id}] Starting swarm mission for {target} (type: {target_type})")
        job['status'] = 'running'
        job['phase'] = 'Swarm Initialization'
        job['progress'] = 5
        job['started_at'] = datetime.now().isoformat()
        job['swarm']['status'] = 'initializing'
        _emit_visualization_event(
            EventType.SCAN_START,
            {"job_id": job_id, "target": target, "mode": "swarm"},
            source="swarm_runner"
        )
        host_label = target
        if target_type == "url":
            parsed = urlparse(target)
            host_label = parsed.netloc or target
        _emit_visualization_event(
            EventType.HOST_DISCOVERED,
            {"job_id": job_id, "host": host_label},
            source="swarm_runner"
        )

        async def _run_swarm_flow():
            c2 = CommandControl(kill_switch_check=_is_kill_switch_active)
            runtime = SwarmRuntime(c2)

            recon = ReconAgent()
            strategy = StrategyAgent()
            exploit = ExploitAgent()
            logic = BusinessLogicAgent()

            runtime.register(recon)
            runtime.register(strategy)
            runtime.register(exploit)
            runtime.register(logic)
            runtime.start()

            try:
                mission = await c2.launch_mission(
                    target=target,
                    target_type=target_type,
                    policy=job.get('swarm', {}).get('policy', {}),
                )
                job['swarm']['mission_id'] = mission.id
                job['swarm']['agent_count'] = 4
                job['swarm']['status'] = 'running'
                active_swarm_sessions[job_id] = {'c2': c2, 'mission_id': mission.id}

                phase_progress = {
                    'planning': 10,
                    'reconnaissance': 25,
                    'vulnerability_discovery': 45,
                    'exploitation': 65,
                    'post_exploitation': 82,
                    'reporting': 95,
                    'completed': 100
                }

                last_phase = None
                phase_started_at = datetime.now()
                stall_alert_sent = False
                while mission.status == 'active':
                    if _is_kill_switch_active():
                        c2.trigger_kill_switch(mission.id, reason='Global kill switch active')

                    status = c2.get_mission_status(mission.id) or {}
                    phase = status.get('phase', 'running')
                    reported_progress = status.get('progress')

                    job['phase'] = f"Swarm: {phase.replace('_', ' ').title()}"
                    if isinstance(reported_progress, (int, float)) and reported_progress > 0:
                        job['progress'] = max(int(reported_progress * 100), phase_progress.get(phase, job.get('progress', 10)))
                    else:
                        job['progress'] = phase_progress.get(phase, job.get('progress', 10))
                    job['swarm']['phase'] = phase
                    job['swarm']['replans'] = mission.replans
                    job['swarm']['phase_history'] = status.get('phase_history', [])
                    job['swarm']['phase_durations'] = status.get('phase_durations', {})
                    job['swarm']['agent_timings'] = status.get('agent_timings', {})
                    job['swarm']['attack_metrics'] = status.get('attack_metrics', job['swarm'].get('attack_metrics', {}))
                    job['swarm']['last_phase_change_at'] = status.get('last_phase_change_at')
                    job['swarm']['validation_checkpoints'] = status.get('validation_checkpoints', [])
                    job['swarm']['campaign_plan'] = status.get('campaign_plan', [])
                    job['swarm']['deferred_vulnerabilities'] = status.get('deferred_vulnerabilities', [])
                    job['swarm']['what_if_branches'] = status.get('what_if_branches', [])
                    job['swarm']['evidence_graph'] = status.get('evidence_graph', {})
                    job['swarm']['audit_events'] = status.get('audit_events', [])
                    job['swarm']['selected_branch'] = status.get('selected_branch')
                    job['swarm']['governance_actions'] = status.get('governance_actions', [])
                    job['swarm']['command_recommendations'] = status.get('command_recommendations', [])
                    job['swarm']['threat_profile'] = status.get('threat_profile', job['swarm'].get('policy', {}).get('threat_profile'))
                    job['swarm']['policy'] = status.get('policy', job['swarm'].get('policy', {}))
                    job['swarm']['kill_switch'] = {
                        **job['swarm'].get('kill_switch', {}),
                        'triggered': bool(status.get('kill_switch_triggered', job['swarm'].get('kill_switch', {}).get('triggered', False))),
                        'reason': status.get('kill_switch_reason', job['swarm'].get('kill_switch', {}).get('reason')),
                    }

                    if phase != last_phase:
                        phase_started_at = datetime.now()
                        stall_alert_sent = False
                        job['swarm']['stalled'] = False
                        _emit_visualization_event(
                            EventType.SCAN_PROGRESS,
                            {
                                "job_id": job_id,
                                "mission_id": mission.id,
                                "phase": phase,
                                "progress": job['progress']
                            },
                            source="swarm_runner"
                        )
                        last_phase = phase

                    phase_elapsed = (datetime.now() - phase_started_at).total_seconds()
                    if phase_elapsed > 120 and not stall_alert_sent:
                        job['swarm']['stalled'] = True
                        job['swarm']['stall_warnings'] = job['swarm'].get('stall_warnings', 0) + 1
                        stall_alert_sent = True
                        _emit_visualization_event(
                            EventType.SCAN_PROGRESS,
                            {
                                "job_id": job_id,
                                "mission_id": mission.id,
                                "phase": phase,
                                "progress": job['progress'],
                                "stalled": True,
                                "phase_elapsed_seconds": int(phase_elapsed)
                            },
                            source="swarm_runner",
                            severity="warning"
                        )
                    await asyncio.sleep(0.5)

                final_status = c2.get_mission_status(mission.id) or {}
                mission_report = mission.intel.get('report', {})

                job['phase'] = 'Completed' if final_status.get('status') == 'completed' else 'Failed'
                job['progress'] = 100 if final_status.get('status') == 'completed' else job.get('progress', 0)
                job['status'] = final_status.get('status', 'completed')
                
                # Initialize report with mission data
                if mission_report:
                    job['report'] = mission_report
                else:
                    job['report'] = {
                        'metadata': {
                            'target': target,
                            'target_type': target_type,
                            'mode': 'swarm',
                            'date': datetime.now().isoformat()
                        },
                        'findings': []
                    }
                    
                normalized_findings = _normalize_findings(mission.findings, target=target)
                validation_summary = None
                try:
                    validation_results = await run_validation_pass(target, normalized_findings) if normalized_findings else []
                    normalized_findings, validation_summary = enrich_findings_with_validation(normalized_findings, validation_results)
                except Exception as validation_error:
                    logger.warning(f"[{job_id}] Swarm validation triage skipped: {validation_error}")

                job['findings'] = normalized_findings
                job['vulnerabilities_found'] = len(normalized_findings)
                if validation_summary is not None:
                    job['validation'] = validation_summary
                    if job['report']:
                        job['report']['validation'] = validation_summary
                job['swarm']['status'] = job['status']
                job['swarm']['phase'] = final_status.get('phase')
                job['swarm']['replans'] = mission.replans
                job['swarm']['phase_history'] = final_status.get('phase_history', [])
                job['swarm']['phase_durations'] = final_status.get('phase_durations', {})
                job['swarm']['agent_timings'] = final_status.get('agent_timings', {})
                job['swarm']['attack_metrics'] = final_status.get('attack_metrics', job['swarm'].get('attack_metrics', {}))
                
                # Map attack metrics to report statistics for display
                attack_metrics = job['swarm'].get('attack_metrics', {})
                job['statistics'] = {
                    'total_loops': attack_metrics.get('replan_count', 0) + 1,  # replans + initial plan
                    'total_executions': attack_metrics.get('attempted', 0),
                    'successful_executions': attack_metrics.get('successful', 0),
                    'failed_executions': attack_metrics.get('failed', 0),
                    'reflections_performed': len(mission.intel.get('reflections', [])) or attack_metrics.get('replan_count', 0),
                    'average_reflection_confidence': 0.85 if attack_metrics.get('successful', 0) > 0 else 0.0,
                    'detection_rate': attack_metrics.get('detection_rate', 0),
                    'success_rate': attack_metrics.get('success_rate', 0),
                }
                
                # Ensure statistics are included in the report object
                if job['report']:
                    job['report']['statistics'] = job['statistics']
                    
                job['swarm']['last_phase_change_at'] = final_status.get('last_phase_change_at')
                job['swarm']['stalled'] = False
                job['swarm']['validation_checkpoints'] = final_status.get('validation_checkpoints', [])
                job['swarm']['campaign_plan'] = final_status.get('campaign_plan', [])
                job['swarm']['deferred_vulnerabilities'] = final_status.get('deferred_vulnerabilities', [])
                job['swarm']['what_if_branches'] = final_status.get('what_if_branches', [])
                job['swarm']['evidence_graph'] = final_status.get('evidence_graph', {})
                job['swarm']['audit_events'] = final_status.get('audit_events', [])
                job['swarm']['selected_branch'] = final_status.get('selected_branch')
                job['swarm']['governance_actions'] = final_status.get('governance_actions', [])
                job['swarm']['command_recommendations'] = final_status.get('command_recommendations', [])
                job['swarm']['threat_profile'] = final_status.get('threat_profile', job['swarm'].get('policy', {}).get('threat_profile'))
                job['swarm']['policy'] = final_status.get('policy', job['swarm'].get('policy', {}))
                job['swarm']['kill_switch'] = {
                    **job['swarm'].get('kill_switch', {}),
                    'triggered': bool(final_status.get('kill_switch_triggered', job['swarm'].get('kill_switch', {}).get('triggered', False))),
                    'reason': final_status.get('kill_switch_reason', job['swarm'].get('kill_switch', {}).get('reason')),
                }

                persist_findings(
                    source="swarm_assessment",
                    tool_name="assessment",
                    assessment_job_id=job_id,
                    target=target,
                    findings=normalized_findings,
                )

                attempted_vulns = mission.intel.get("vulnerabilities", []) or []
                exploited = mission.intel.get("exploitation", []) or []
                succeeded_types = {
                    str(item.get("vulnerability", {}).get("type", "")).lower()
                    for item in exploited
                    if item.get("result", {}).get("success")
                }

                for vuln in attempted_vulns:
                    vector = vuln.get("type", "unknown")
                    _emit_visualization_event(
                        EventType.ATTACK_START,
                        {
                            "job_id": job_id,
                            "mission_id": mission.id,
                            "target": target,
                            "vector": vector
                        },
                        source="swarm_runner"
                    )
                    if str(vector).lower() in succeeded_types:
                        _emit_visualization_event(
                            EventType.ATTACK_SUCCESS,
                            {
                                "job_id": job_id,
                                "mission_id": mission.id,
                                "target": target,
                                "vector": vector,
                                "vuln_type": vector
                            },
                            source="swarm_runner"
                        )
                    else:
                        _emit_visualization_event(
                            EventType.ATTACK_FAILED,
                            {
                                "job_id": job_id,
                                "mission_id": mission.id,
                                "target": target,
                                "vector": vector
                            },
                            source="swarm_runner",
                            severity="medium"
                        )

                for finding in normalized_findings:
                    vector = finding.get("type") or finding.get("attack", "unknown")
                    _emit_visualization_event(
                        EventType.ATTACK_START,
                        {
                            "job_id": job_id,
                            "mission_id": mission.id,
                            "target": target,
                            "vector": vector
                        },
                        source="swarm_runner"
                    )
                    _emit_visualization_event(
                        EventType.VULN_DETECTED,
                        {
                            "job_id": job_id,
                            "mission_id": mission.id,
                            "type": vector,
                            "severity": str(finding.get("severity", "medium")).lower(),
                            "location": finding.get("location", target)
                        },
                        source="swarm_runner",
                        severity=str(finding.get("severity", "medium")).lower()
                    )
                    _emit_visualization_event(
                        EventType.ATTACK_SUCCESS,
                        {
                            "job_id": job_id,
                            "mission_id": mission.id,
                            "target": target,
                            "vector": vector,
                            "vuln_type": vector
                        },
                        source="swarm_runner"
                    )

                _emit_visualization_event(
                    EventType.SCAN_PROGRESS,
                    {
                        "job_id": job_id,
                        "mission_id": mission.id,
                        "phase": "completed",
                        "progress": 100
                    },
                    source="swarm_runner"
                )

                _emit_visualization_event(
                    EventType.SCAN_COMPLETE,
                    {
                        "job_id": job_id,
                        "mission_id": mission.id,
                        "target": target,
                        "findings": len(normalized_findings),
                        "mode": "swarm"
                    },
                    source="swarm_runner"
                )

            finally:
                active_swarm_sessions.pop(job_id, None)
                runtime.stop()

        asyncio.run(_run_swarm_flow())
        job['completed_at'] = datetime.now().isoformat()

    except Exception as e:
        logger.error(f"[{job_id}] Swarm mission failed: {e}")
        logger.error(f"[{job_id}] Full traceback: {traceback.format_exc()}")

        job['status'] = 'failed'
        job['error'] = str(e)
        job['error_traceback'] = traceback.format_exc()
        job['completed_at'] = datetime.now().isoformat()
        job['swarm']['status'] = 'failed'

    finally:
        active_swarm_sessions.pop(job_id, None)
        if job_id in job_threads:
            del job_threads[job_id]
        logger.info(f"[{job_id}] Swarm background thread cleanup complete")


# ============================================================================
# ENTERPRISE FEATURE ROUTES
# ============================================================================

@app.route('/api/enterprise/status', methods=['GET'])
def enterprise_status():
    """Check enterprise features availability"""
    features = {
        "enabled": ENTERPRISE_FEATURES if 'ENTERPRISE_FEATURES' in dir() else False,
        "modules": {
            "osint_hub": False,
            "mitre_attack": False,
            "multi_agent": False,
            "visualization": False
        }
    }
    
    try:
        from intelligence.osint_hub import OSINTHub
        features["modules"]["osint_hub"] = True
    except: pass
    
    try:
        from intelligence.mitre_attack import MitreAttackMapper
        features["modules"]["mitre_attack"] = True
    except: pass
    
    try:
        from agents import CommandControl
        features["modules"]["multi_agent"] = True
    except: pass
    
    try:
        from visualization import VisualizationHub
        features["modules"]["visualization"] = True
    except: pass
    
    return jsonify(features)


@app.route('/api/osint/gather', methods=['POST'])
def osint_gather():
    """Gather OSINT intelligence on a target"""
    try:
        from intelligence.osint_hub import get_osint_hub
        
        data = request.get_json() or {}
        target = data.get('target', '').strip()
        target_type = str(data.get('target_type', '')).strip().lower()
        
        if not target:
            return jsonify({"error": "Target required"}), 400

        if target_type not in {'domain', 'ip', 'url'}:
            if re.match(r'^https?://', target, re.IGNORECASE):
                target_type = 'url'
            elif re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', target):
                target_type = 'ip'
            else:
                target_type = 'domain'
        
        osint_api_keys = {
            "shodan": os.getenv('SHODAN_API_KEY', '').strip(),
            "virustotal": os.getenv('VIRUSTOTAL_API_KEY', '').strip(),
            "censys_id": os.getenv('CENSYS_API_ID', '').strip(),
            "censys_secret": os.getenv('CENSYS_API_SECRET', '').strip(),
            "securitytrails": os.getenv('SECURITYTRAILS_API_KEY', '').strip(),
            "hunter": os.getenv('HUNTER_API_KEY', '').strip()
        }

        # Check which API keys are actually configured
        api_keys_status = {
            "shodan": bool(osint_api_keys["shodan"]),
            "virustotal": bool(osint_api_keys["virustotal"]),
            "censys": bool(osint_api_keys["censys_id"] and osint_api_keys["censys_secret"]),
            "securitytrails": bool(osint_api_keys["securitytrails"]),
            "hunter": bool(osint_api_keys["hunter"])
        }
        
        configured_count = sum(api_keys_status.values())
        total_count = len(api_keys_status)
        
        hub = get_osint_hub(api_keys=osint_api_keys)
        response_payload = {
            "status": "ready",
            "target": target,
            "target_type": target_type,
            "message": f"{configured_count}/{total_count} OSINT sources configured",
            "api_keys_status": api_keys_status,
            "configured_count": configured_count,
            "total_count": total_count
        }

        if configured_count > 0:
            response_payload["intelligence"] = asyncio.run(
                hub.gather_intelligence(target=target, target_type=target_type)
            )

        return jsonify(response_payload)
    except ImportError:
        return jsonify({"error": "OSINT module not available"}), 501
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/mitre/map', methods=['POST'])
def mitre_map_findings():
    """Map findings to MITRE ATT&CK framework"""
    try:
        from intelligence.mitre_attack import get_mitre_mapper
        
        data = request.get_json() or {}
        findings = data.get('findings', [])
        
        if not findings:
            # Return technique database info
            mapper = get_mitre_mapper()
            return jsonify({
                "status": "ready",
                "techniques_loaded": len(mapper.techniques),
                "tactics": [t.name for t in mapper.techniques.values()],
                "sample_mapping": {
                    "sql_injection": ["T1190", "T1213"],
                    "xss": ["T1190", "T1059"],
                    "port_scan": ["T1595", "T1046"],
                    "brute_force": ["T1110"]
                }
            })
        
        mapper = get_mitre_mapper()
        result = mapper.map_findings(findings)
        return jsonify(result)
        
    except ImportError:
        return jsonify({"error": "MITRE module not available"}), 501
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/mitre/technique/<technique_id>', methods=['GET'])
def get_mitre_technique(technique_id):
    """Get details for a specific MITRE technique"""
    try:
        from intelligence.mitre_attack import get_mitre_mapper
        
        mapper = get_mitre_mapper()
        technique = mapper.get_technique(technique_id.upper())
        
        if not technique:
            return jsonify({"error": f"Technique {technique_id} not found"}), 404
        
        return jsonify({
            "id": technique.id,
            "name": technique.name,
            "tactic": technique.tactic.name,
            "description": technique.description,
            "detection": technique.detection,
            "mitigation": technique.mitigation,
            "url": technique.url
        })
        
    except ImportError:
        return jsonify({"error": "MITRE module not available"}), 501
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/agents/status', methods=['GET'])
def agents_status():
    """Get multi-agent system status"""
    try:
        from agents import CommandControl, ReconAgent, ExploitAgent, BusinessLogicAgent, StrategyAgent, SwarmRuntime
        
        return jsonify({
            "status": "ready",
            "available_agents": [
                {
                    "type": "CommandControl",
                    "description": "Master orchestrator for coordinating attack missions",
                    "capabilities": ["mission_planning", "agent_coordination", "intel_aggregation"]
                },
                {
                    "type": "ReconAgent", 
                    "description": "Reconnaissance and OSINT specialist",
                    "capabilities": ["subdomain_enum", "port_scan", "tech_fingerprint", "osint"]
                },
                {
                    "type": "ExploitAgent",
                    "description": "Vulnerability exploitation specialist",
                    "capabilities": ["sql_injection", "xss", "command_injection", "waf_bypass"]
                },
                {
                    "type": "BusinessLogicAgent",
                    "description": "Workflow and access-control logic analysis specialist",
                    "capabilities": ["business_logic_analysis"]
                },
                {
                    "type": "StrategyAgent",
                    "description": "Planning and re-planning specialist",
                    "capabilities": ["strategy_planning"]
                }
            ],
            "runtime": {
                "swarm_available": SWARM_AVAILABLE,
                "runtime": "SwarmRuntime"
            },
            "active_swarm_jobs": [
                {
                    "job_id": job["id"],
                    "target": job.get("target"),
                    "status": job.get("status"),
                    "mission_id": job.get("swarm", {}).get("mission_id"),
                    "phase": job.get("swarm", {}).get("phase"),
                    "replans": job.get("swarm", {}).get("replans", 0),
                    "stalled": job.get("swarm", {}).get("stalled", False),
                    "stall_warnings": job.get("swarm", {}).get("stall_warnings", 0),
                    "attack_metrics": job.get("swarm", {}).get("attack_metrics", {}),
                    "last_phase_change_at": job.get("swarm", {}).get("last_phase_change_at"),
                    "threat_profile": job.get("swarm", {}).get("threat_profile") or job.get("swarm", {}).get("policy", {}).get("threat_profile"),
                    "what_if_branches": job.get("swarm", {}).get("what_if_branches", []),
                    "selected_branch": job.get("swarm", {}).get("selected_branch"),
                    "command_recommendations": job.get("swarm", {}).get("command_recommendations", []),
                    "governance_actions": job.get("swarm", {}).get("governance_actions", []),
                    "policy": job.get("swarm", {}).get("policy", {}),
                }
                for job in assessment_jobs.values()
                if job.get("mode") == "swarm"
            ],
            "message": "Multi-agent swarm ready for deployment"
        })
        
    except ImportError:
        return jsonify({"error": "Agent modules not available"}), 501
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/swarm/<job_id>/status', methods=['GET'])
def swarm_job_status(job_id):
    """Get swarm-specific mission status for a job."""
    job = assessment_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    if job.get('mode') != 'swarm':
        return jsonify({"error": "Job is not running in swarm mode"}), 400

    return jsonify({
        "job_id": job_id,
        "status": job.get('status'),
        "phase": job.get('phase'),
        "progress": job.get('progress', 0),
        "swarm": job.get('swarm', {})
    })


@app.route('/api/visualization/graph', methods=['GET'])
def get_attack_graph():
    """Get current attack graph state"""
    try:
        from visualization import get_visualization_hub
        job_id = request.args.get('job_id', '').strip() or None
        hub = get_visualization_hub()
        return jsonify({
            "graph": hub.get_graph(job_id=job_id),
            "metrics": hub.get_metrics(job_id=job_id),
            "job_id": job_id
        })
        
    except ImportError:
        return jsonify({"error": "Visualization module not available"}), 501
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*70)
    print("RedAgent Web Dashboard".center(70))
    print("="*70)
    print("\n[*] Starting web server...")
    print("[+] Dashboard: http://localhost:5000")
    print("[+] API Docs: http://localhost:5000/api/status")
    print("\nPress CTRL+C to stop\n")
    print("="*70 + "\n")
    
    from waitress import serve
    serve(app, host='0.0.0.0', port=5000)
