"""
RedAgent Web Dashboard - Flask Backend
Provides REST API and web interface for the autonomous penetration testing agent
Includes real-time progress tracking, error handling, and job management
"""

from flask import Flask, render_template, request, jsonify, send_from_directory, send_file, redirect
from flask_cors import CORS
import json
import os
import threading
import logging
from datetime import datetime
from pathlib import Path
import glob
import traceback
import queue
from io import BytesIO

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
    from agents import CommandControl, ReconAgent, ExploitAgent
    from visualization import get_visualization_hub, EventType
    ENTERPRISE_FEATURES = True
    print("[+] Enterprise features loaded")
except ImportError as e:
    print(f"[WARN] Enterprise features not available: {e}")
    ENTERPRISE_FEATURES = False

# Configure logging
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

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
        
        jobs_summary = {
            "total": len(assessment_jobs),
            "running": sum(1 for j in assessment_jobs.values() if j['status'] == 'running'),
            "starting": sum(1 for j in assessment_jobs.values() if j['status'] == 'starting'),
            "completed": sum(1 for j in assessment_jobs.values() if j['status'] == 'completed'),
            "failed": sum(1 for j in assessment_jobs.values() if j['status'] == 'failed'),
            "cancelled": sum(1 for j in assessment_jobs.values() if j['status'] == 'cancelled')
        }
        
        # Check recent reports
        recent_reports = 0
        if os.path.exists('logs'):
            recent_reports = len(glob.glob('logs/report_*.json'))
        
        return jsonify({
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "infrastructure": {
                "ollama": ollama_status,
                "agent": "ready",
                "dashboard": "ready"
            },
            "jobs": jobs_summary,
            "reports_generated": recent_reports,
            "version": "1.0.0"
        }), 200
    except Exception as e:
        logger.error(f"Error in get_status: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

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
        
        # Validate inputs
        if not target:
            return jsonify({"error": "Target is required"}), 400
        
        if target_type not in ['url', 'ip']:
            return jsonify({"error": "Target type must be 'url' or 'ip'"}), 400
        
        # Validate target format
        if target_type == 'url' and not (target.startswith('http://') or target.startswith('https://')):
            return jsonify({"error": "URL must start with http:// or https://"}), 400
        
        # Create job
        job_counter += 1
        job_id = f"job_{job_counter}_{datetime.now().strftime('%H%M%S')}"
        
        assessment_jobs[job_id] = {
            "id": job_id,
            "target": target,
            "type": target_type,
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
            "error_traceback": None
        }
        
        logger.info(f"[{job_id}] Assessment created for {target}")
        
        # Run assessment in background thread
        try:
            thread = threading.Thread(
                target=run_assessment_background,
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
    
    # Check if browser is requesting HTML (not API client)
    format_param = request.args.get('format', 'auto')
    accept_header = request.headers.get('Accept', '')
    
    if format_param == 'json':
        return jsonify(job['report'])
    elif format_param == 'html' or ('text/html' in accept_header and 'application/json' not in accept_header):
        # Redirect to HTML report viewer
        return redirect(f'/report?job={job_id}')
    else:
        return jsonify(job['report'])

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
                        report_data = json.load(f)
                        reports.append({
                            "filename": os.path.basename(report_file),
                            "target": report_data.get('metadata', {}).get('target'),
                            "timestamp": report_data.get('metadata', {}).get('timestamp'),
                            "model": report_data.get('metadata', {}).get('llm_model')
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
            report_data = json.load(f)
        
        return jsonify(report_data)
    except Exception as e:
        logger.error(f"Error reading report: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/reports/<report_name>/download', methods=['GET'])
def download_report(report_name):
    """Download report in JSON format"""
    try:
        report_path = os.path.join('logs', report_name)
        
        # Security: only allow downloading actual report files
        if not os.path.exists(report_path) or not report_name.startswith('report_') or not report_name.endswith('.json'):
            return jsonify({"error": "Report not found"}), 404
        
        logger.info(f"Downloading report: {report_name}")
        
        return send_file(
            report_path,
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
        json_data = json.dumps(job['report'], indent=2)
        
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
    report = job.get('report', {})
    metadata = report.get('metadata', {})
    phases = report.get('assessment_phases', [])
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>RedAgent Assessment Report</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 900px;
                margin: 0 auto;
                padding: 20px;
                background: #f5f5f5;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px;
                border-radius: 8px;
                margin-bottom: 30px;
            }}
            .header h1 {{ margin: 0; font-size: 2em; }}
            .metadata {{
                background: white;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .metadata p {{ margin: 10px 0; }}
            .metadata strong {{ color: #667eea; }}
            .phase {{
                background: white;
                padding: 20px;
                margin-bottom: 20px;
                border-left: 4px solid #667eea;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .phase h3 {{ margin-top: 0; color: #667eea; }}
            .finding {{
                background: #f9f9f9;
                padding: 15px;
                margin: 10px 0;
                border-radius: 4px;
                border-left: 3px solid #e74c3c;
            }}
            .finding.success {{ border-left-color: #27ae60; }}
            .finding.warning {{ border-left-color: #f39c12; }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 10px 0;
            }}
            th, td {{
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }}
            th {{
                background: #667eea;
                color: white;
            }}
            .footer {{
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px solid #ddd;
                text-align: center;
                color: #666;
                font-size: 0.9em;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔴 RedAgent Assessment Report</h1>
            <p>Autonomous Penetration Testing</p>
        </div>
        
        <div class="metadata">
            <h2>Assessment Details</h2>
            <p><strong>Target:</strong> {metadata.get('target', 'N/A')}</p>
            <p><strong>Type:</strong> {metadata.get('target_type', 'N/A')}</p>
            <p><strong>Date:</strong> {metadata.get('timestamp', 'N/A')}</p>
            <p><strong>Model:</strong> {metadata.get('llm_model', 'N/A')}</p>
            <p><strong>Total Vulnerabilities Found:</strong> <strong style="color: #e74c3c;">{job.get('vulnerabilities_found', 0)}</strong></p>
        </div>
    """
    
    # Add phases
    for phase in phases:
        phase_name = phase.get('phase', 'Unknown')
        phase_type = phase.get('type', '')
        content = phase.get('content', '')
        
        html += f"""
        <div class="phase">
            <h3>{phase_name}</h3>
            <p><strong>Type:</strong> {phase_type}</p>
            <p>{content[:500]}...</p>
        </div>
        """
    
    # Add findings
    findings = job.get('findings', [])
    if findings:
        html += """
        <div class="phase">
            <h3>Vulnerabilities Found</h3>
            <table>
                <tr>
                    <th>Attack Type</th>
                    <th>Severity</th>
                    <th>Status</th>
                </tr>
        """
        
        for finding in findings:
            severity = finding.get('severity', 'MEDIUM').upper()
            severity_class = 'success' if 'HIGH' in severity else 'warning'
            
            html += f"""
                <tr>
                    <td>{finding.get('attack', 'N/A')}</td>
                    <td><strong style="color: {'#e74c3c' if severity == 'CRITICAL' else '#f39c12'}">{severity}</strong></td>
                    <td>{finding.get('status', 'N/A')}</td>
                </tr>
            """
        
        html += """
            </table>
        </div>
        """
    
    html += """
        <div class="footer">
            <p>Generated by RedAgent v1.0.0</p>
            <p>For legal and authorized security testing only</p>
        </div>
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
        job['status'] = 'completed'
        job['progress'] = 100
        job['phase'] = 'Completed'
        job['report'] = latest_report
        job['findings'] = vulnerabilities
        job['completed_at'] = datetime.now().isoformat()
        job['vulnerabilities_found'] = len(vulnerabilities)
        
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
        
        if not target:
            return jsonify({"error": "Target required"}), 400
        
        # Check which API keys are actually configured
        api_keys_status = {
            "shodan": bool(os.getenv('SHODAN_API_KEY', '').strip()),
            "virustotal": bool(os.getenv('VIRUSTOTAL_API_KEY', '').strip()),
            "censys": bool(os.getenv('CENSYS_API_ID', '').strip() and os.getenv('CENSYS_API_SECRET', '').strip()),
            "securitytrails": bool(os.getenv('SECURITYTRAILS_API_KEY', '').strip()),
            "hunter": bool(os.getenv('HUNTER_API_KEY', '').strip())
        }
        
        configured_count = sum(api_keys_status.values())
        total_count = len(api_keys_status)
        
        hub = get_osint_hub()
        return jsonify({
            "status": "ready",
            "target": target,
            "message": f"{configured_count}/{total_count} OSINT sources configured",
            "api_keys_status": api_keys_status,
            "configured_count": configured_count,
            "total_count": total_count
        })
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
        from agents import CommandControl, ReconAgent, ExploitAgent
        
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
                }
            ],
            "message": "Multi-agent swarm ready for deployment"
        })
        
    except ImportError:
        return jsonify({"error": "Agent modules not available"}), 501
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/visualization/graph', methods=['GET'])
def get_attack_graph():
    """Get current attack graph state"""
    try:
        from visualization import get_visualization_hub
        
        hub = get_visualization_hub()
        return jsonify({
            "graph": hub.get_graph(),
            "metrics": hub.get_metrics()
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
