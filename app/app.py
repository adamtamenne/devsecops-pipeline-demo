"""
Intentionally Vulnerable Flask App
===================================
This app contains deliberate OWASP Top 10 vulnerabilities for demonstrating
a DevSecOps CI/CD pipeline with automated security scanning.

DO NOT deploy this application in any real environment.

Vulnerabilities embedded:
  - A01: SQL Injection (raw query construction)
  - A03: Cross-Site Scripting / XSS (unescaped user input in response)
  - A07: Hardcoded credentials (API key in source)
  - A09: Insufficient logging (no audit trail on auth)
"""

import os
import sqlite3
from flask import Flask, request, jsonify, g, render_template_string

app = Flask(__name__)

# --- A07:2021 Identification and Authentication Failures ---
# Hardcoded secret: Gitleaks and Semgrep should flag this
API_KEY = "sk_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
DATABASE_PASSWORD = "SuperSecret123!"


def get_db():
    """Get a database connection, creating the DB if needed."""
    if "db" not in g:
        g.db = sqlite3.connect(":memory:")
        g.db.row_factory = sqlite3.Row
        _init_db(g.db)
    return g.db


def _init_db(db):
    db.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT
        )"""
    )
    db.execute(
        """CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            title TEXT,
            content TEXT
        )"""
    )
    # Seed data
    db.execute(
        "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        ("admin", "admin123", "admin@example.com"),
    )
    db.execute(
        "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        ("testuser", "password", "test@example.com"),
    )
    db.execute(
        "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
        (1, "Secret Note", "This contains sensitive data"),
    )
    db.commit()


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.route("/")
def index():
    return jsonify({
        "app": "DevSecOps Demo",
        "version": "1.0.0",
        "endpoints": ["/login", "/search", "/profile", "/notes", "/health"],
    })


@app.route("/health")
def health():
    return jsonify({"status": "healthy"})


# --- A01:2021 Broken Access Control / SQL Injection ---
# Raw string formatting in SQL query: SAST should catch this
@app.route("/search")
def search():
    query = request.args.get("q", "")
    db = get_db()
    # VULNERABLE: SQL injection via string concatenation
    sql = "SELECT username, email FROM users WHERE username LIKE '%" + query + "%'"
    try:
        results = db.execute(sql).fetchall()
        return jsonify({"results": [dict(r) for r in results]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- A03:2021 Injection / Cross-Site Scripting ---
# User input rendered directly into HTML without escaping
@app.route("/profile")
def profile():
    username = request.args.get("name", "Guest")
    # VULNERABLE: Reflected XSS via unescaped template rendering
    template = "<h1>Welcome, " + username + "!</h1><p>Your profile page.</p>"
    return render_template_string(template)


# --- A07:2021 Identification and Authentication Failures ---
# Plaintext password comparison, no rate limiting, no logging
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()

    if user:
        # No session management, returning raw user data
        return jsonify({"message": "Login successful", "user_id": user["id"]})
    else:
        return jsonify({"message": "Invalid credentials"}), 401


# --- A01:2021 Broken Access Control ---
# No authorization check: any user can access any user's notes
@app.route("/notes/<int:user_id>")
def get_notes(user_id):
    db = get_db()
    notes = db.execute(
        "SELECT title, content FROM notes WHERE user_id = ?", (user_id,)
    ).fetchall()
    return jsonify({"notes": [dict(n) for n in notes]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
