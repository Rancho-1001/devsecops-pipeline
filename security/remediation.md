# Remediation — Before / After

Each planted finding with the vulnerable code and the fix. The full diff is
`git diff vulnerable main -- app` (or compare `vulnerable-app/` with `app/`).
Every fix has a regression test in `app/tests/test_security.py`.

---

## DSO-01/02 — SQL Injection (A03)

**Before** (`vulnerable-app/app.py`):
```python
query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, pw_hash)
row = conn.execute(query).fetchone()
```

**After** (`app/app.py`):
```python
row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
if not row or not bcrypt.checkpw(password.encode(), row["password"]):
    return jsonify({"error": "invalid credentials"}), 401
```
Parameterized queries everywhere; the `/search` `LIKE` escapes wildcards.
Test: `test_sqli_in_login_does_not_bypass_auth`.

---

## DSO-03 — OS Command Injection (A03)

**Before:**
```python
output = os.popen("ping -c 1 " + host).read()
```

**After:**
```python
if not HOST_RE.match(host):
    return jsonify({"error": "invalid host"}), 400
out = subprocess.run(["ping", "-c", "1", "-w", "2", host],
                     capture_output=True, text=True, timeout=5, check=False)
```
No shell, argument list, strict host validation. Test:
`test_command_injection_input_rejected`.

---

## DSO-04 — Broken Access Control / IDOR (A01)

**Before:** `/users/<id>` returned any record, no auth.

**After:**
```python
@require_auth
def get_user(user_id):
    if g.role != "admin" and g.user_id != user_id:
        return jsonify({"error": "forbidden"}), 403
```
Tests: `test_idor_blocked`, `test_admin_can_read_others`,
`test_unauthenticated_access_rejected`.

---

## DSO-05 — SSRF (A10)

**Before:**
```python
resp = requests.get(url, timeout=5)   # any URL
```

**After:** https-only, host allowlist, and DNS-resolution check that rejects
private / loopback / link-local addresses (blocks the cloud metadata IP
`169.254.169.254`). Test: `test_ssrf_blocked_for_internal_host`.

---

## DSO-06 — Weak JWT (A07)

**Before:** `jwt.encode({...}, SECRET_KEY, algorithm="HS256")` with a hardcoded
key and no expiry.

**After:** signing key from `os.environ["JWT_SECRET"]`, `exp` claim (30 min),
and decode pins `algorithms=["HS256"]` (rejects `alg: none`).

---

## DSO-07 — MD5 Password Hashing (A02)

**Before:** `hashlib.md5(password.encode()).hexdigest()`
**After:** `bcrypt.hashpw` on seed, `bcrypt.checkpw` on login.

---

## DSO-08 — Hardcoded Secrets (A02/A05)

**Before:** `SECRET_KEY`, AWS keys, and a committed `vulnerable-app/.env`.
**After:** all secrets from the environment; `.env` gitignored; `.env.example`
ships placeholders only; Gitleaks config allowlists just the placeholders.

---

## DSO-09 — Vulnerable Dependencies (A06)

**Before:** Flask 0.12.2, Werkzeug 0.14.1, Jinja2 2.10, PyYAML 3.13,
urllib3 1.24.1, requests 2.19.1, PyJWT 1.5.0 (all with known CVEs).
**After:** current patched pins (Flask 3.0.3, Werkzeug 3.0.4, PyYAML 6.0.2,
urllib3 2.2.2, requests 2.32.3, PyJWT 2.9.0, bcrypt 4.2.0). Trivy SCA clean at
High/Critical.

---

## DSO-10 — Insecure Container + Debug Mode (A05)

**Before:** `FROM python:latest`, root user, `ENV JWT_SECRET=...` baked in,
`app.run(debug=True, host="0.0.0.0")`.
**After:** `python:3.12-slim`, non-root `appuser`, no secrets in layers,
healthcheck, gunicorn; app debug off by default and binds localhost unless
configured. Trivy config scan clean; Semgrep `flask-debug-true` no longer fires.

---

## The remediation loop

```
vulnerable branch ──► CI security gates RED (10 findings)
        │
        ▼
   fix each finding on main ──► regression tests pin them
        │
        ▼
   CI security gates GREEN ──► PR diff = the remediation
```
