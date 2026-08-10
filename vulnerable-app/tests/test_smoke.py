"""Minimal smoke test so CI has something to run. Not a security test."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import seed  # noqa: E402
import app as flask_app  # noqa: E402


def setup_module(_):
    os.environ["DB_PATH"] = "test.db"
    seed.DB_PATH = "test.db"
    seed.main()


def test_login_route_exists():
    client = flask_app.app.test_client()
    resp = client.post("/login", json={"username": "nope", "password": "nope"})
    assert resp.status_code in (401, 200)
