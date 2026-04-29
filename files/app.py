"""
VulnFlask - Intentionally Vulnerable Flask Application
Used as a scan target for the DevSecOps pipeline demo.
DO NOT deploy in production.
"""

from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import os
import subprocess
import hashlib

app = Flask(__name__)
app.secret_key = "hardcoded_secret_key_123"  # VULNERABILITY: Hardcoded secret

DATABASE = "users.db"

# ------------------------------------------------------------------ #
#  Database helpers
# ------------------------------------------------------------------ #

def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email    TEXT
        )
    """)
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password, email) VALUES (1, 'admin', 'admin123', 'admin@vulnflask.local')"
    )
    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ------------------------------------------------------------------ #
#  Routes
# ------------------------------------------------------------------ #

HOME_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VulnFlask</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 800px; margin: 60px auto; background: #f5f5f5; }
    .card { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,.1); margin-bottom: 20px; }
    h1 { color: #c0392b; }
    a { color: #2980b9; }
    .badge { display: inline-block; background: #e74c3c; color: white;
             padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-left: 8px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>VulnFlask <span class="badge">INTENTIONALLY VULNERABLE</span></h1>
    <p>This app is a <strong>deliberate scan target</strong> for the DevSecOps pipeline demo.</p>
    <ul>
      <li><a href="/login">Login (SQL Injection demo)</a></li>
      <li><a href="/search?q=hello">Search (XSS demo)</a></li>
      <li><a href="/ping?host=localhost">Ping (Command Injection demo)</a></li>
      <li><a href="/health">Health check</a></li>
    </ul>
  </div>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HOME_TEMPLATE)


@app.route("/health")
def health():
    return {"status": "ok", "app": "VulnFlask", "version": "1.0.0"}


# VULNERABILITY 1 — SQL Injection
@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        # VULN: raw string interpolation → SQL injection
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            user = conn.execute(query).fetchone()
            message = f"Welcome, {user['username']}!" if user else "Invalid credentials."
        except Exception as e:
            message = f"DB error: {e}"
        finally:
            conn.close()

    form = """
    <!DOCTYPE html><html><head><title>Login</title></head><body>
    <h2>Login</h2>
    <form method="POST">
      <input name="username" placeholder="Username"><br><br>
      <input name="password" type="password" placeholder="Password"><br><br>
      <button type="submit">Login</button>
    </form>
    <p style="color:green">{{ message }}</p>
    <p><small>Hint: try <code>' OR '1'='1</code> as username</small></p>
    <a href="/">← Back</a>
    </body></html>
    """
    return render_template_string(form, message=message)


# VULNERABILITY 2 — Reflected XSS
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULN: user input reflected without escaping → XSS
    template = f"""
    <!DOCTYPE html><html><head><title>Search</title></head><body>
    <h2>Search results for: {q}</h2>
    <form><input name="q" value="{q}"><button>Search</button></form>
    <a href="/">← Back</a>
    </body></html>
    """
    return template


# VULNERABILITY 3 — Command Injection
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # VULN: shell=True with unsanitised input → command injection
    try:
        output = subprocess.check_output(
            f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT, timeout=5
        )
        result = output.decode()
    except Exception as e:
        result = str(e)

    template = f"""
    <!DOCTYPE html><html><head><title>Ping</title></head><body>
    <h2>Ping: {host}</h2>
    <pre>{result}</pre>
    <form><input name="host" value="{host}"><button>Ping</button></form>
    <a href="/">← Back</a>
    </body></html>
    """
    return template


# VULNERABILITY 4 — Weak password hashing
@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULN: MD5 is cryptographically broken
        hashed = hashlib.md5(password.encode()).hexdigest()
        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed)
        )
        conn.commit()
        conn.close()
        message = "Registered!"

    form = """
    <!DOCTYPE html><html><head><title>Register</title></head><body>
    <h2>Register</h2>
    <form method="POST">
      <input name="username" placeholder="Username"><br><br>
      <input name="password" type="password" placeholder="Password"><br><br>
      <button type="submit">Register</button>
    </form>
    <p>{{ message }}</p>
    <a href="/">← Back</a>
    </body></html>
    """
    return render_template_string(form, message=message)


# ------------------------------------------------------------------ #
#  Entrypoint
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    init_db()
    # VULNERABILITY: Debug mode ON, listening on all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
