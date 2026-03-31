"""
RedAgent Web Dashboard - Simplified Flask Backend (for debugging)
"""

from flask import Flask, render_template, jsonify
from flask_cors import CORS
import json

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

# Global state
assessment_jobs = {}

@app.route('/')
def index():
    """Serve the main dashboard page"""
    return render_template('index.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get system status"""
    return jsonify({
        "status": "ok",
        "jobs": {
            "total": len(assessment_jobs),
            "running": 0,
            "completed": 0,
            "failed": 0
        }
    })

@app.route('/api/jobs', methods=['GET'])
def list_jobs():
    """List all jobs"""
    return jsonify({"jobs": list(assessment_jobs.values())})

if __name__ == '__main__':
    print("\n" + "="*70)
    print("RedAgent Web Dashboard (Debug Mode)".center(70))
    print("="*70)
    print("\n[*] Starting web server...")
    print("[+] Dashboard: http://localhost:5000")
    print("[+] API: http://localhost:5000/api/status")
    print("\n" + "="*70 + "\n")
    
    from waitress import serve
    print("[*] Using Waitress WSGI server...")
    serve(app, host='0.0.0.0', port=5000)
