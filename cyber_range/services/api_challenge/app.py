from flask import Flask, jsonify, request
import os
from datetime import datetime

app = Flask(__name__)
TOKEN = os.getenv("RANGE_TOKEN", "range-api-token")
FLAG = os.getenv("RANGE_FLAG", "range{api_surface_for_safe_validation}")


@app.get("/")
def index():
    return jsonify({
        "service": os.getenv("RANGE_NAME", "api-challenge"),
        "hint": "Inspect /health, /scenario, and /admin/status with the local token.",
    })


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": os.getenv("RANGE_NAME", "api-challenge"),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@app.get("/scenario")
def scenario():
    return jsonify({
        "objective": "Validate safe API discovery and response handling inside a private range.",
        "routes": ["/", "/health", "/scenario", "/admin/status"],
        "token_header": "X-Range-Token",
    })


@app.get("/admin/status")
def admin_status():
    provided = request.headers.get("X-Range-Token", "")
    if provided != TOKEN:
        return jsonify({"error": "unauthorized", "message": "Provide the local training token."}), 401
    return jsonify({
        "status": "authorized",
        "flag": FLAG,
        "service": os.getenv("RANGE_NAME", "api-challenge"),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
