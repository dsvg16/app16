# Route tests for /api/list-versions and /api/list-all-versions.
# These were the two routes with no coverage. Both are auth-required and
# scoped to the caller's own documents (ownerid), so we check:
#   - 401 without a bearer token
#   - list-versions needs a document id
#   - a valid token returns only the rows the query hands back

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from server import create_app


@pytest.fixture
def app(monkeypatch, tmp_path):
    
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path))
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-12345")
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def _token(app, uid=1):
    from itsdangerous import URLSafeTimedSerializer
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
    return s.dumps({"uid": uid, "login": "tester", "email": "t@example.com"})


def _mock_version_row():
    r = MagicMock()
    r.id = 7
    r.documentid = 3
    r.link = "abc123"
    r.intended_for = "Group_03"
    r.secret = "Group_03:abc123"
    r.method = "Method 5"
    return r


# --- auth is required ---

def test_list_versions_requires_auth(client):
    assert client.get("/api/list-versions/3").status_code == 401


def test_list_all_versions_requires_auth(client):
    assert client.get("/api/list-all-versions").status_code == 401


# --- list-versions ---

def test_list_versions_needs_document_id(client, app):
    r = client.get(
        "/api/list-versions",
        headers={"Authorization": f"Bearer {_token(app)}"},
    )
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_list_versions_returns_scoped_rows(client, app):
    with patch("server.create_engine") as mock_engine:
        conn = MagicMock()
        mock_engine.return_value.connect.return_value.__enter__.return_value = conn
        conn.execute.return_value.all.return_value = [_mock_version_row()]

        r = client.get(
            "/api/list-versions/3",
            headers={"Authorization": f"Bearer {_token(app)}"},
        )
    assert r.status_code == 200
    body = r.get_json()
    assert body["versions"][0]["documentid"] == 3
    assert body["versions"][0]["link"] == "abc123"

    # the query must be scoped by the authenticated user id
    sql = conn.execute.call_args[0][0].text
    assert "ownerid" in sql
    assert "u.id = :uid" in sql


# --- list-all-versions ---

def test_list_all_versions_returns_scoped_rows(client, app):
    with patch("server.create_engine") as mock_engine:
        conn = MagicMock()
        mock_engine.return_value.connect.return_value.__enter__.return_value = conn
        conn.execute.return_value.all.return_value = [_mock_version_row()]

        r = client.get(
            "/api/list-all-versions",
            headers={"Authorization": f"Bearer {_token(app)}"},
        )
    assert r.status_code == 200
    body = r.get_json()
    assert len(body["versions"]) == 1
    assert body["versions"][0]["intended_for"] == "Group_03"

    # "all" means all of the caller's own versions: still scoped by ownerid + uid
    sql = conn.execute.call_args[0][0].text
    assert "ownerid" in sql
    assert "u.id = :uid" in sql


def test_list_all_versions_does_not_return_secret(client, app):
    # list-all-versions must not expose the embedded secret
    with patch("server.create_engine") as mock_engine:
        conn = MagicMock()
        mock_engine.return_value.connect.return_value.__enter__.return_value = conn
        conn.execute.return_value.all.return_value = [_mock_version_row()]

        r = client.get(
            "/api/list-all-versions",
            headers={"Authorization": f"Bearer {_token(app)}"},
        )
    assert "secret" not in r.get_json()["versions"][0]
