from flask import Flask, jsonify, render_template_string, request
import os
from datetime import datetime

app = Flask(__name__)

USER = os.getenv("RANGE_USER", "lab-admin")
PASS = os.getenv("RANGE_PASS", "lab-ranger")
FLAG = os.getenv("RANGE_FLAG", "range{local_credentials_only}")

PAGE = """
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>Login Challenge</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; background: #111827; color: #e5e7eb; }
    main { max-width: 720px; margin: 0 auto; padding: 48px 20px; }
    .panel { background: #1f2937; border: 1px solid #374151; border-radius: 16px; padding: 24px; }
    input, button { width: 100%; padding: 12px 14px; margin: 10px 0; border-radius: 10px; border: 1px solid #4b5563; background: #0f172a; color: #fff; }
    button { background: #2563eb; border: none; cursor: pointer; }
    .hint { color: #93c5fd; }
    .flag { margin-top: 18px; padding: 14px; border-radius: 12px; background: #0b3b2e; border: 1px solid #10b981; }
  </style>
</head>
<body>
  <main>
    <div class=\"panel\">
      <h1>Training Login Portal</h1>
      <p class=\"hint\">Safe local exercise for auth review and workflow validation.</p>
      <form method=\"post\" action=\"/login\">
        <input name=\"username\" placeholder=\"Username\" autocomplete=\"off\" />
        <input name=\"password\" placeholder=\"Password\" type=\"password\" autocomplete=\"off\" />
        <button type=\"submit\">Sign in</button>
      </form>
      {% if message %}
      <div class=\"flag\">{{ message }}</div>
      {% endif %}
      {% if flag %}
      <div class=\"flag\"><strong>Admin access granted.</strong><br>{{ flag }}</div>
      {% endif %}
    </div>
  </main>
</body>
</html>
"""


@app.get("/")
def index():
    return render_template_string(PAGE, message=None, flag=None)


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username == USER and password == PASS:
        return render_template_string(PAGE, message="Credentials accepted.", flag=FLAG)
    return render_template_string(PAGE, message="Access denied. Check the local training credentials.", flag=None), 401


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": os.getenv("RANGE_NAME", "login-challenge"),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@app.get("/manifest")
def manifest():
    return jsonify({
        "service": os.getenv("RANGE_NAME", "login-challenge"),
        "routes": ["/", "/login", "/health", "/manifest"],
        "auth_mode": "local-training-creds"
    })


if __name__ == "__main__":
  app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
