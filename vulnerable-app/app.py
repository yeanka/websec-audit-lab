"""
WebSec Audit Lab — Intentionally Vulnerable Web Application
============================================================
WARNING: This application contains deliberate security vulnerabilities
for educational and research purposes ONLY.

DO NOT deploy this in production or on any public server.

Vulnerabilities present (intentional):
  - SQL Injection (login, search)
  - Reflected & Stored XSS
  - Broken Access Control
  - CSRF (no token)
  - IDOR
  - Missing security headers
  - Sensitive data exposure
  - Hardcoded credentials
  - Directory traversal
"""

from flask import Flask, request, render_template_string, redirect, session, jsonify, send_file
import sqlite3
import os
import hashlib

app = Flask(__name__)

# VULNERABILITY #9: Hardcoded secret key and credentials
app.secret_key = "supersecretkey123"
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"  # hardcoded credential

DB_PATH = "users.db"

# ─── Database Setup ────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT,
            email TEXT,
            ssn TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            content TEXT,
            title TEXT
        )
    """)
    # Seed users — passwords stored as plaintext (VULNERABILITY #8)
    users = [
        (1, "admin", "admin123", "admin", "admin@corp.com", "123-45-6789"),
        (2, "alice",  "alice2024", "user", "alice@corp.com", "987-65-4321"),
        (3, "bob",    "bob2024",   "user", "bob@corp.com",   "555-12-3456"),
    ]
    for u in users:
        try:
            c.execute("INSERT INTO users VALUES (?,?,?,?,?,?)", u)
        except sqlite3.IntegrityError:
            pass
    # Seed notes
    notes = [
        (1, 1, "Server root password: R00tP@ss!", "Admin Credentials"),
        (2, 2, "My personal diary entry for today.", "Alice's Note"),
        (3, 3, "Reminder: submit expense report.", "Bob's Reminder"),
    ]
    for n in notes:
        try:
            c.execute("INSERT INTO notes VALUES (?,?,?,?)", n)
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

# ─── Templates ─────────────────────────────────────────────────────────────────

BASE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>CorpPortal — {% block title %}Home{% endblock %}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background: #f4f4f4; }
        nav { background: #2c3e50; padding: 12px 24px; color: white; display: flex; gap: 20px; align-items: center; }
        nav a { color: #ecf0f1; text-decoration: none; }
        nav a:hover { color: #3498db; }
        .container { max-width: 900px; margin: 40px auto; background: white; padding: 30px; border-radius: 6px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        input, textarea { width: 100%; padding: 8px; margin: 6px 0 14px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button, .btn { background: #2980b9; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        button:hover, .btn:hover { background: #1a6491; }
        .error { color: red; background: #ffe5e5; padding: 8px; border-radius: 4px; margin-bottom: 10px; }
        .success { color: green; background: #e5ffe5; padding: 8px; border-radius: 4px; margin-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background: #2c3e50; color: white; }
        tr:nth-child(even) { background: #f9f9f9; }
        .badge { padding: 3px 8px; border-radius: 12px; font-size: 12px; }
        .badge-admin { background: #e74c3c; color: white; }
        .badge-user { background: #27ae60; color: white; }
    </style>
</head>
<body>
    <nav>
        <strong>🏢 CorpPortal</strong>
        <a href="/">Home</a>
        <a href="/search">Search</a>
        <a href="/notes">My Notes</a>
        <a href="/profile">Profile</a>
        {% if session.get('user') %}
            <a href="/logout" style="margin-left:auto">Logout ({{ session.user }})</a>
        {% else %}
            <a href="/login" style="margin-left:auto">Login</a>
        {% endif %}
    </nav>
    <div class="container">
        {% block content %}{% endblock %}
    </div>
</body>
</html>
"""

# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(BASE_HTML + """
{% block title %}Home{% endblock %}
{% block content %}
    <h1>Welcome to CorpPortal</h1>
    <p>Internal employee portal. Please <a href="/login">log in</a> to continue.</p>
    <hr>
    <h3>Features</h3>
    <ul>
        <li><a href="/search">Employee Search</a></li>
        <li><a href="/notes">Personal Notes</a></li>
        <li><a href="/profile">Your Profile</a></li>
        <li><a href="/admin">Admin Panel</a></li>
    </ul>
{% endblock %}
""")


# VULNERABILITY #1: SQL Injection — no parameterized queries
@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # VULN: Direct string interpolation — injectable!
        # Bypass with: username = ' OR '1'='1'--
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            c.execute(query)
            user = c.fetchone()
        except Exception as e:
            error = f"DB Error: {e}"  # VULN: exposes DB error details
            user = None
        conn.close()
        if user:
            session["user"] = user[1]
            session["user_id"] = user[0]
            session["role"] = user[3]
            return redirect("/profile")
        else:
            error = "Invalid credentials."
    return render_template_string(BASE_HTML + """
{% block title %}Login{% endblock %}
{% block content %}
    <h2>Login</h2>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form method="POST">
        <label>Username</label>
        <input name="username" placeholder="Enter username">
        <label>Password</label>
        <input name="password" type="password" placeholder="Enter password">
        <button type="submit">Login</button>
    </form>
    <p style="margin-top:16px;font-size:13px;color:#888">Hint: Try admin / admin123</p>
{% endblock %}
""", error=error)


# VULNERABILITY #2: Reflected XSS — query param reflected without escaping
@app.route("/search")
def search():
    query = request.args.get("q", "")
    results = []
    if query:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # VULN: SQL injection via search
        sql = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{query}%'"
        try:
            c.execute(sql)
            results = c.fetchall()
        except Exception as e:
            results = []
        conn.close()
    # VULN: query reflected directly into template without escaping
    return render_template_string(BASE_HTML + """
{% block title %}Search{% endblock %}
{% block content %}
    <h2>Employee Search</h2>
    <form method="GET">
        <input name="q" value="{{ query|safe }}" placeholder="Search employees...">
        <button type="submit">Search</button>
    </form>
    {% if query %}
        <p>Results for: <strong>{{ query|safe }}</strong></p>
    {% endif %}
    {% if results %}
    <table>
        <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>
        {% for r in results %}
        <tr>
            <td><a href="/user/{{ r[0] }}">{{ r[0] }}</a></td>
            <td>{{ r[1] }}</td>
            <td>{{ r[2] }}</td>
            <td><span class="badge badge-{{ r[3] }}">{{ r[3] }}</span></td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}
{% endblock %}
""", query=query, results=results)


# VULNERABILITY #5 & #6: IDOR + no auth check on user profiles
@app.route("/user/<int:user_id>")
def view_user(user_id):
    # VULN: No authentication check — anyone can view any user profile
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # VULN: Returns SSN (sensitive data) for any user
    c.execute("SELECT id, username, email, role, ssn FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    conn.close()
    if not user:
        return "User not found", 404
    return render_template_string(BASE_HTML + """
{% block title %}User Profile{% endblock %}
{% block content %}
    <h2>User Profile</h2>
    <table>
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>ID</td><td>{{ user[0] }}</td></tr>
        <tr><td>Username</td><td>{{ user[1] }}</td></tr>
        <tr><td>Email</td><td>{{ user[2] }}</td></tr>
        <tr><td>Role</td><td>{{ user[3] }}</td></tr>
        <tr><td>SSN</td><td style="color:red">{{ user[4] }}</td></tr>
    </table>
    <br><a href="/search" class="btn">Back to Search</a>
{% endblock %}
""", user=user)


# VULNERABILITY #3: Stored XSS — note content stored and re-rendered without escaping
@app.route("/notes", methods=["GET", "POST"])
def notes():
    if not session.get("user"):
        return redirect("/login")
    msg = ""
    if request.method == "POST":
        title = request.form.get("title", "")
        content = request.form.get("content", "")
        # VULN: No sanitization before storing
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO notes (user_id, content, title) VALUES (?,?,?)",
                  (session["user_id"], content, title))
        conn.commit()
        conn.close()
        msg = "Note saved!"
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # VULN: No ownership check — shows all notes (IDOR)
    c.execute("SELECT id, title, content FROM notes")
    all_notes = c.fetchall()
    conn.close()
    return render_template_string(BASE_HTML + """
{% block title %}Notes{% endblock %}
{% block content %}
    <h2>Notes</h2>
    {% if msg %}<div class="success">{{ msg }}</div>{% endif %}
    <!-- VULNERABILITY: No CSRF token on this form -->
    <form method="POST">
        <label>Title</label>
        <input name="title" placeholder="Note title">
        <label>Content</label>
        <textarea name="content" rows="4" placeholder="Write your note..."></textarea>
        <button type="submit">Save Note</button>
    </form>
    <hr>
    <h3>All Notes</h3>
    {% for note in notes %}
    <div style="border:1px solid #ddd; padding:12px; margin:10px 0; border-radius:4px">
        <strong>{{ note[1] }}</strong>
        <!-- VULN: Stored XSS — content rendered with |safe -->
        <p>{{ note[2]|safe }}</p>
        <small>Note ID: {{ note[0] }} — <a href="/note/{{ note[0] }}">View</a> | <a href="/delete_note/{{ note[0] }}">Delete</a></small>
    </div>
    {% endfor %}
{% endblock %}
""", notes=all_notes, msg=msg)


# VULNERABILITY #4: Broken Access Control — admin panel has no real auth
@app.route("/admin")
def admin_panel():
    # VULN: Only checks if 'admin' string is in session, trivially bypassed
    # by setting session manually or via cookie manipulation
    if session.get("role") != "admin":
        return render_template_string(BASE_HTML + """
{% block title %}Admin{% endblock %}
{% block content %}
    <div class="error">Access Denied. <a href="/login">Login as admin.</a></div>
    <!-- Hint: Can you bypass this? -->
{% endblock %}
""")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, username, email, role, ssn FROM users")
    users = c.fetchall()
    conn.close()
    return render_template_string(BASE_HTML + """
{% block title %}Admin Panel{% endblock %}
{% block content %}
    <h2>🔐 Admin Panel</h2>
    <p style="color:green">✅ Authenticated as admin</p>
    <h3>All Users (incl. SSNs)</h3>
    <table>
        <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>SSN</th></tr>
        {% for u in users %}
        <tr>
            <td>{{ u[0] }}</td><td>{{ u[1] }}</td><td>{{ u[2] }}</td>
            <td>{{ u[3] }}</td><td style="color:red">{{ u[4] }}</td>
        </tr>
        {% endfor %}
    </table>
{% endblock %}
""", users=users)


# VULNERABILITY #10: Directory Traversal
@app.route("/file")
def serve_file():
    # VULN: No path sanitization
    filename = request.args.get("name", "")
    try:
        # Attacker can use: /file?name=../../etc/passwd
        return send_file(filename)
    except Exception as e:
        return f"Error: {e}", 404


@app.route("/profile")
def profile():
    if not session.get("user"):
        return redirect("/login")
    return render_template_string(BASE_HTML + """
{% block title %}Profile{% endblock %}
{% block content %}
    <h2>Your Profile</h2>
    <p><strong>Username:</strong> {{ session.user }}</p>
    <p><strong>Role:</strong> <span class="badge badge-{{ session.role }}">{{ session.role }}</span></p>
    <p><strong>User ID:</strong> {{ session.user_id }}</p>
    <br>
    <a href="/notes" class="btn">My Notes</a>
    <a href="/admin" class="btn" style="background:#e74c3c;margin-left:10px">Admin Panel</a>
{% endblock %}
""")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/delete_note/<int:note_id>")
def delete_note(note_id):
    # VULN: No ownership check — any logged-in user can delete any note
    if not session.get("user"):
        return redirect("/login")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM notes WHERE id=?", (note_id,))
    conn.commit()
    conn.close()
    return redirect("/notes")


# VULNERABILITY: No security headers set anywhere in the app

if __name__ == "__main__":
    init_db()
    print("\n" + "="*60)
    print("  ⚠️  VULNERABLE APP — FOR SECURITY RESEARCH ONLY  ⚠️")
    print("="*60)
    print("  Running on: http://localhost:5000")
    print("  Credentials: admin/admin123, alice/alice2024")
    print("="*60 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
