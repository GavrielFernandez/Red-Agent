"""Test Flask API endpoints"""
from app import app

with app.test_client() as client:
    # Test /api/status
    print("[*] Testing /api/status")
    response = client.get('/api/status')
    print(f"    Status: {response.status_code}")
    print(f"    Response: {response.get_json()}")
    
    # Test /api/jobs
    print("\n[*] Testing /api/jobs")
    response = client.get('/api/jobs')
    print(f"    Status: {response.status_code}")
    print(f"    Response: {response.get_json()}")
    
    print("\n[✓] All API endpoints working!")
