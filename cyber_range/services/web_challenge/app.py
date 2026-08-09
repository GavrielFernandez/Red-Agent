from flask import Flask, jsonify, render_template_string
import os
from datetime import datetime

app = Flask(__name__)

TEMPLATE = """
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>RedAgent Range Web</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; background: linear-gradient(135deg, #0e1726, #17324d); color: #f3f7fb; }
    main { max-width: 880px; margin: 0 auto; padding: 48px 24px; }
    .card { background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12); border-radius: 18px; padding: 24px; box-shadow: 0 20px 50px rgba(0,0,0,0.22); }
    h1 { margin-top: 0; font-size: 2.4rem; }
    code, pre { background: rgba(0,0,0,0.24); padding: 2px 6px; border-radius: 6px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-top: 20px; }
    .tile { background: rgba(255,255,255,0.05); border-radius: 14px; padding: 16px; }
    a { color: #8bd1ff; }
  </style>
</head>
<body>
  <main>
    <div class=\"card\">
      <h1>RedAgent Cyber Range</h1>
      <p>This landing page is part of a local-only training environment.</p>
      <div class=\"grid\">
        <div class=\"tile\"><strong>Service</strong><br>{{ name }}</div>
        <div class=\"tile\"><strong>Started</strong><br>{{ started_at }}</div>
        <div class=\"tile\"><strong>Flag</strong><br>{{ flag }}</div>
        <div class=\"tile\"><strong>Status</strong><br><a href=\"/health\">/health</a></div>
      </div>
      <p style=\"margin-top: 20px;\">Use this range to validate discovery, response, and reporting workflows without touching real infrastructure.</p>
    </div>
  </main>
</body>
</html>
"""


@app.get("/")
def index():
    return render_template_string(
        TEMPLATE,
        name=os.getenv("RANGE_NAME", "web-challenge"),
        started_at=datetime.utcnow().isoformat() + "Z",
        flag=os.getenv("RANGE_FLAG", "range{web_landings_are_for_training_only}"),
    )


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": os.getenv("RANGE_NAME", "web-challenge"),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@app.get("/manifest")
def manifest():
    return jsonify({
        "service": os.getenv("RANGE_NAME", "web-challenge"),
        "routes": ["/", "/health", "/manifest"],
        "notes": "Local training landing page"
    })


if __name__ == "__main__":
  app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
