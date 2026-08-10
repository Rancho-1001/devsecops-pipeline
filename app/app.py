"""
Secure Flask API — the remediated version of ../vulnerable-app.

Every OWASP issue from the vulnerable app is fixed here; see
security/remediation.md for the before/after mapping. This is what lives on
`main`, and the CI security gates pass against it.

Fixes:
  A01 -> /users/<id> requires a valid token; non-admins may only read themselves
  A02 -> bcrypt password hashing; signing key loaded from the environment
  A03 -> parameterized SQL everywhere; no shell for ping (arg list + strict input)
  A07 -> JWT verified with explicit algorithm + expiry
  A10 -> /fetch restricted by a scheme + host allowlist
  A05 -> debug off by default, secrets from env, hardened Dockerfile
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import sqlite3
import subprocess
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse

import bcrypt
import jwt
import requests
from flask import Flask, g, jsonify, request

app = Flask(__name__)

# A02/A05: no secrets in source — load from the environment, fail closed.
SECRET_KEY = os.environ["JWT_SECRET"]  # required; app refuses to start without it
DB_PATH = os.environ.get("DB_PATH", "app.db")
JWT_ALG = "HS256"
JWT_TTL_MIN = 30

# A10: only these destinations may be fetched by /fetch.
FETCH_ALLOWED_HOSTS = {"api.github.com", "example.com"}
HOST_RE = re.compile(r"^[a-zA-Z0-9.\-]{1,253}$")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def make_token(user_id: int, role: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": user_id, "role": role, "iat": now,
         "exp": now + timedelta(minutes=JWT_TTL_MIN)},
        SECRET_KEY, algorithm=JWT_ALG)


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing token"}), 401
        try:
            claims = jwt.decode(auth[7:], SECRET_KEY, algorithms=[JWT_ALG])
        except jwt.PyJWTError:
            return jsonify({"error": "invalid token"}), 401
        g.user_id = claims["sub"]
        g.role = claims.get("role", "user")
        return fn(*args, **kwargs)
    return wrapper


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # A03: parameterized query.
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    # A02: constant-time bcrypt verification; same response on any failure.
    if not row or not bcrypt.checkpw(password.encode(), row["password"]):
        return jsonify({"error": "invalid credentials"}), 401

    return jsonify({"token": make_token(row["id"], row["role"])})


@app.route("/users/<int:user_id>", methods=["GET"])
@require_auth
def get_user(user_id: int):
    # A01: authorization — only self, unless admin.
    if g.role != "admin" and g.user_id != user_id:
        return jsonify({"error": "forbidden"}), 403
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, email, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/search", methods=["GET"])
@require_auth
def search():
    # A03: parameterized LIKE with escaped wildcards.
    q = request.args.get("q", "")
    like = "%" + q.replace("%", r"\%").replace("_", r"\_") + "%"
    conn = get_db()
    rows = conn.execute(
        "SELECT id, username, email FROM users WHERE username LIKE ? ESCAPE '\\'",
        (like,)).fetchall()
    return jsonify([dict(r) for r in rows])


def _is_public_host(hostname: str) -> bool:
    """Resolve and reject private/loopback/link-local addresses (SSRF defense)."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    return True


@app.route("/fetch", methods=["POST"])
@require_auth
def fetch():
    # A10: SSRF defense — https only, host allowlist, and no private IPs.
    url = (request.get_json(silent=True) or {}).get("url", "")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in FETCH_ALLOWED_HOSTS:
        return jsonify({"error": "url not allowed"}), 400
    if not _is_public_host(parsed.hostname):
        return jsonify({"error": "host not allowed"}), 400
    resp = requests.get(url, timeout=5, allow_redirects=False)
    return jsonify({"status": resp.status_code, "body": resp.text[:500]})


@app.route("/ping", methods=["GET"])
@require_auth
def ping():
    # A03: no shell. Validate host, pass args as a list (shell=False).
    host = request.args.get("host", "127.0.0.1")
    if not HOST_RE.match(host):
        return jsonify({"error": "invalid host"}), 400
    try:
        out = subprocess.run(
            ["ping", "-c", "1", "-w", "2", host],
            capture_output=True, text=True, timeout=5, check=False)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "timeout"}), 504
    return jsonify({"output": out.stdout[:500]})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # A05: debug off unless explicitly enabled; bind configurable, default localhost.
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    host = os.environ.get("BIND_HOST", "127.0.0.1")
    app.run(host=host, port=5000, debug=debug)
