# login brute-force throttle. needs a database because login reads Users.
from __future__ import annotations

import os
import uuid

import pytest

import server as server_module

pytestmark = pytest.mark.skipif(
    not os.environ.get("TATOU_DB_TEST"), reason="needs a live MariaDB"
)


@pytest.fixture
def app(monkeypatch, tmp_path):
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path))
    monkeypatch.setenv("SECRET_KEY", "throttle-test-key")
    monkeypatch.setenv("LOGIN_FAIL_LIMIT", "3")
    monkeypatch.setenv("LOGIN_IP_LIMIT", "50")
    monkeypatch.setenv("LOGIN_WINDOW_SECONDS", "300")
    monkeypatch.setenv("LOGIN_LOCKOUT_SECONDS", "300")
    return server_module.create_app()


def _new_user(client):
    u = "t" + uuid.uuid4().hex[:10]
    email = f"{u}@throttle.local"
    r = client.post("/api/create-user",
                    json={"email": email, "login": u, "password": "right-pw"})
    assert r.status_code == 201, r.get_data(as_text=True)
    return email


def test_guessing_passwords_gets_locked_out(app):
    c = app.test_client()
    email = _new_user(c)
    for _ in range(3):  # up to the limit these are normal failures
        r = c.post("/api/login", json={"email": email, "password": "wrong"})
        assert r.status_code == 401
    # the next guess is refused outright
    r = c.post("/api/login", json={"email": email, "password": "wrong"})
    assert r.status_code == 429
    assert r.headers.get("Retry-After")


def test_lockout_also_blocks_the_correct_password(app):
    # otherwise an attacker could still confirm a password once they hit it
    c = app.test_client()
    email = _new_user(c)
    for _ in range(4):
        c.post("/api/login", json={"email": email, "password": "wrong"})
    r = c.post("/api/login", json={"email": email, "password": "right-pw"})
    assert r.status_code == 429


def test_a_good_login_clears_the_counter(app):
    c = app.test_client()
    email = _new_user(c)
    for _ in range(2):  # stay under the limit
        assert c.post("/api/login", json={"email": email, "password": "wrong"}).status_code == 401
    assert c.post("/api/login", json={"email": email, "password": "right-pw"}).status_code == 200
    # counter was reset, so two more wrong tries are still just 401
    for _ in range(2):
        assert c.post("/api/login", json={"email": email, "password": "wrong"}).status_code == 401


def test_one_locked_account_does_not_lock_another(app):
    c = app.test_client()
    victim, other = _new_user(c), _new_user(c)
    for _ in range(4):
        c.post("/api/login", json={"email": victim, "password": "wrong"})
    assert c.post("/api/login", json={"email": victim, "password": "right-pw"}).status_code == 429
    # a different account from the same host still works
    assert c.post("/api/login", json={"email": other, "password": "right-pw"}).status_code == 200


def test_throttle_ignores_spoofed_forwarded_header(app):
    # X-Forwarded-For is caller controlled; changing it must not reset the count
    c = app.test_client()
    email = _new_user(c)
    for i in range(4):
        c.post("/api/login", json={"email": email, "password": "wrong"},
               headers={"X-Forwarded-For": f"10.0.0.{i}"})
    r = c.post("/api/login", json={"email": email, "password": "wrong"},
               headers={"X-Forwarded-For": "10.0.0.99"})
    assert r.status_code == 429
