"""
INTENTIONALLY VULNERABLE Flask API — scanner target for the DevSecOps pipeline.

DO NOT deploy this anywhere reachable. It exists so the CI security gates
(Semgrep, Trivy, Gitleaks, OWASP ZAP) have something real to catch. Each flaw is
tagged with the OWASP Top 10 (2021) category it demonstrates. The remediated
version lives in ../app (see security/remediation.md for the before/after).

Planted issues:
  A01 Broken Access Control     -> GET /users/<id> (IDOR, no authz)
  A02 Cryptographic Failures    -> MD5 password hashing; hardcoded SECRET_KEY
  A03 Injection (SQL)           -> /login and /search string-built SQL
  A03 Injection (OS command)    -> /ping os.system with user input
  A07 Auth Failures             -> JWT signed with a hardcoded secret, no expiry
  A10 SSRF                      -> POST /fetch requests any user-supplied URL
  A05 Security Misconfiguration -> debug=True, bind 0.0.0.0, secrets in code
"""
import hashlib
import os
import sqlite3

import jwt  # PyJWT
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

# A02/A05: hardcoded secrets committed to source (Gitleaks + Semgrep will flag).
SECRET_KEY = "sup3r-s3cr3t-jwt-signing-key-do-not-share"
DB_PASSWORD = "admin123"
AWS_ACCESS_KEY_ID = "AKIA5Z7Q3XN2VJ9WD4LP"
AWS_SECRET_ACCESS_KEY = "hV8pNc2FqLmR7yT3wZ0aQ9xB4dK1sJ6eG5uI2oP"

DB_PATH = os.environ.get("DB_PATH", "app.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")

    # A02: MD5 is unfit for password hashing.
    pw_hash = hashlib.md5(password.encode()).hexdigest()

    # A03: SQL injection via string concatenation.
    conn = get_db()
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
        username, pw_hash)
    row = conn.execute(query).fetchone()
    if not row:
        return jsonify({"error": "invalid credentials"}), 401

    # A07: JWT with hardcoded secret and no expiry.
    token = jwt.encode({"sub": row["id"], "role": row["role"]}, SECRET_KEY,
                       algorithm="HS256")
    return jsonify({"token": token})


@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    # A01: IDOR — returns any user's record with no authorization check.
    conn = get_db()
    row = conn.execute("SELECT id, username, email, role FROM users WHERE id = %d"
                       % user_id).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/search", methods=["GET"])
def search():
    # A03: SQL injection in a search filter.
    q = request.args.get("q", "")
    conn = get_db()
    query = "SELECT id, username, email FROM users WHERE username LIKE '%" + q + "%'"
    rows = conn.execute(query).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/fetch", methods=["POST"])
def fetch():
    # A10: SSRF — fetches any URL the caller supplies (no allowlist).
    url = request.get_json(force=True).get("url", "")
    resp = requests.get(url, timeout=5)  # nosec: intentionally vulnerable
    return jsonify({"status": resp.status_code, "body": resp.text[:500]})


@app.route("/ping", methods=["GET"])
def ping():
    # A03: OS command injection.
    host = request.args.get("host", "127.0.0.1")
    output = os.popen("ping -c 1 " + host).read()
    return jsonify({"output": output})


if __name__ == "__main__":
    # A05: debug mode + binding to all interfaces in "production".
    app.run(host="0.0.0.0", port=5000, debug=True)
