"""
Regression tests that pin the security fixes in place. These assert the app
BEHAVES securely, so a future change that reintroduces a vuln fails CI.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("JWT_SECRET", "test-secret-not-for-prod")
os.environ["DB_PATH"] = "test.db"

import seed  # noqa: E402
seed.DB_PATH = "test.db"
seed.main()

import app as secure_app  # noqa: E402

client = secure_app.app.test_client()


def _token(username, password):
    r = client.post("/login", json={"username": username, "password": password})
    return r.get_json().get("token")


def test_login_success_and_bad_password():
    assert _token("alice", "password1")                      # correct creds
    assert client.post("/login",
                       json={"username": "alice", "password": "x"}).status_code == 401


def test_sqli_in_login_does_not_bypass_auth():
    # Classic injection payload must NOT authenticate.
    r = client.post("/login", json={"username": "alice' OR '1'='1", "password": "x"})
    assert r.status_code == 401


def test_idor_blocked():
    # bob (id=2, user) must not read alice (id=1).
    tok = _token("bob", "hunter2")
    r = client.get("/users/1", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


def test_admin_can_read_others():
    tok = _token("alice", "password1")  # admin
    r = client.get("/users/2", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200


def test_unauthenticated_access_rejected():
    assert client.get("/users/1").status_code == 401


def test_ssrf_blocked_for_internal_host():
    tok = _token("alice", "password1")
    r = client.post("/fetch", json={"url": "http://169.254.169.254/latest/meta-data/"},
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 400


def test_command_injection_input_rejected():
    tok = _token("alice", "password1")
    r = client.get("/ping?host=127.0.0.1;whoami",
                   headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 400
