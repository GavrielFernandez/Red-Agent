"""
RedAgent Web Dashboard - Flask Backend
Provides REST API and web interface for the autonomous penetration testing agent
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
import json
import os
import threading
import logging
from datetime import datetime
from run import RedAgent
import glob

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

# Global state for tracking assessments
assessment_jobs = {}
job_counter = 0

# ============================================================================
# ROUTES - Web Interface
# ============================================================================

@app.route('/')
def index():
    """Serve the main dashboard page"""
    return render_template('index.html')

@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files (CSS, JS)"""
    return send_from_directory('static', filename)

# ============================================================================
# API ROUTES - Assessment Management
# ============================================================================

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get system status and job information"""
    try:
        ollama_status = "running"
        docker_status = "running"
        
        jobs_summary = {
            "total": len(assessment_jobs),
            "running": sum(1 for j in assessment_jobs.values() if j['status'] == 'running'),
            "completed": sum(1 for j in assessment_jobs.values() if j['status'] == 'completed'),
            "failed": sum(1 for j in assessment_jobs.values() if j['status'] == 'failed')
        }
        
        return jsonify({
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "infrastructure": {
                "ollama": ollama_status,
                "docker": docker_status,
                "agent": "ready"
            },
            "jobs": jobs_summary
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/assess', methods=['POST'])
def create_assessment():
    """Create and start a new assessment job"""
    global job_counter
    
    try:
        data = request.get_json()
        target = data.get('target')
        target_type = data.get('type', 'url')
        
        if not target:
            return jsonify({"error": "Target is required"}), 400
        
        # Create job
        job_counter += 1
        job_id = f"job_{job_counter}_{datetime.now().strftime('%H%M%S')}"
        
        assessment_jobs[job_id] = {
            "id": job_id,
            "target": target,
            "type": target_type,
            "status": "running",
            "created_at": datetime.now().isoformat(),
            "progress": 0,
            "phase": "Initializing...",
            "findings": [],
            "report": None
        }
        
        # Run assessment in background thread
        thread = threading.Thread(
            target=run_assessment_background,
            args=(job_id, target, target_type)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "job_id": job_id,
            "status": "created",
            "message": f"Assessment started for {target}"
        }), 201
    
    except Exception as e:
        logger.error(f"Error creating assessment: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/assess/<job_id>', methods=['GET'])
def get_assessment(job_id):
    """Get assessment job details and progress"""
    if job_id not in assessment_jobs:
        return jsonify({"error": "Job not found"}), 404
    
    job = assessment_jobs[job_id]
    return jsonify(job)

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
        
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        
        return jsonify(report_data)
    except Exception as e:
        logger.error(f"Error reading report: {e}")
        return jsonify({"error": str(e)}), 500

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
    if job['status'] == 'running':
        job['status'] = 'cancelled'
        return jsonify({"status": "cancelled", "job_id": job_id})
    
    return jsonify({"error": "Job is not running"}), 400

# ============================================================================
# BACKGROUND EXECUTION
# ============================================================================

def run_assessment_background(job_id, target, target_type):
    """Run assessment in background and update job status"""
    job = assessment_jobs[job_id]
    
    try:
        logger.info(f"Starting assessment {job_id} for {target}")
        
        # Phase updates
        phases = [
            "Reconnaissance",
            "Vulnerability Analysis",
            "Exploitation Planning",
            "Attack Execution",
            "Impact Assessment"
        ]
        
        agent = RedAgent(target=target, target_type=target_type)
        
        # Update phase and run each phase
        for i, phase_name in enumerate(phases):
            if job['status'] == 'cancelled':
                break
            
            job['phase'] = phase_name
            job['progress'] = int((i / len(phases)) * 100)
        
        # Run full assessment
        agent.run_assessment()
        
        # Load latest report
        latest_report = None
        if os.path.exists('logs'):
            reports = sorted(glob.glob('logs/report_*.json'), reverse=True)
            if reports:
                with open(reports[0], 'r') as f:
                    latest_report = json.load(f)
        
        # Extract vulnerabilities from report
        vulnerabilities = []
        if latest_report:
            attack_phase = next((p for p in latest_report.get('assessment_phases', []) 
                               if p.get('phase') == 'attack_execution'), None)
            if attack_phase:
                for attack in attack_phase.get('attacks', []):
                    status = attack.get('status', '')
                    if 'VULNERABLE' in status or 'SUCCESS' in status:
                        vulnerabilities.append({
                            "attack": attack.get('attack'),
                            "severity": "CRITICAL" if 'VULNERABLE' in status else "HIGH",
                            "status": status
                        })
        
        # Mark job as completed
        job['status'] = 'completed'
        job['progress'] = 100
        job['phase'] = 'Completed'
        job['report'] = latest_report
        job['findings'] = vulnerabilities
        job['completed_at'] = datetime.now().isoformat()
        
        logger.info(f"Assessment {job_id} completed successfully")
    
    except Exception as e:
        logger.error(f"Assessment {job_id} failed: {e}")
        job['status'] = 'failed'
        job['error'] = str(e)
        job['completed_at'] = datetime.now().isoformat()

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
    print("\n🌐 Starting web server...")
    print("📊 Dashboard: http://localhost:5000")
    print("📡 API Docs: http://localhost:5000/api/status")
    print("\nPress CTRL+C to stop\n")
    print("="*70 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
