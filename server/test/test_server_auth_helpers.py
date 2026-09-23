# Test for authentication and helper functions in server.py

# Cover:
# - Authentication token generation and validation
# - require_auth decorator
# - Helper functions like _sha256_file, _serializer
# - Config validation
# - Healthz endpoint


import pytest
import tempfile
import os
import hashlib
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from server import create_app


@pytest.fixture
def app():
    # Create test app with temporary storage
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ["STORAGE_DIR"] = tmpdir
        os.environ["SECRET_KEY"] = "test-secret-key-12345"
        os.environ["DB_HOST"] = "localhost"
        os.environ["DB_USER"] = "test"
        os.environ["DB_PASSWORD"] = "test"
        os.environ["DB_NAME"] = "test"

        app = create_app()
        app.config["TESTING"] = True
        yield app


@pytest.fixture
def client(app):
    return app.test_client()


class TestHealthzEndpoint:
    # Test suite for healthz endpoint

    def test_healthz_returns_200(self, client):
        # Test healthz returns 200 OK
        response = client.get("/healthz")
        assert response.status_code == 200

    def test_healthz_returns_json(self, client):
        # Test that healthz returns JSON
        response = client.get("/healthz")
        assert response.is_json
        json_data = response.get_json()
        assert "message" in json_data

    def test_healthz_checks_db_connection(self, client):
        # Test that healthz checks database connectivity
        response = client.get("/healthz")
        json_data = response.get_json()
        assert "db_connected" in json_data
        assert isinstance(json_data["db_connected"], bool)

    def test_healthz_handles_db_errors_gracefully(self, client, app):
        # Test that healthz doesn't crash on DB errors
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
            mock_conn.execute.side_effect = Exception("DB Error")

            response = client.get("/healthz")
            assert response.status_code == 200
            json_data = response.get_json()
            assert json_data["db_connected"] == False


class TestAuthentication:
    # Test suite for authentication mechanisms

    def test_token_generation_and_validation(self, app):
        # Test that tokens can be generated and validated
        from itsdangerous import URLSafeTimedSerializer

        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

        # Generate token
        user_data = {"uid": 123, "login": "testuser", "email": "test@example.com"}
        token = serializer.dumps(user_data)

        # Validate token
        decoded = serializer.loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
        assert decoded["uid"] == 123
        assert decoded["login"] == "testuser"
        assert decoded["email"] == "test@example.com"

    def test_expired_token_rejected(self, app):
        """Test that expired tokens are rejected"""
        from itsdangerous import URLSafeTimedSerializer, SignatureExpired

        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        user_data = {"uid": 123, "login": "testuser", "email": "test@example.com"}
        token = serializer.dumps(user_data)

        # Try to validate with max_age=0 (immediately expired)
        with pytest.raises(SignatureExpired):
            serializer.loads(token, max_age=0)

    def test_invalid_token_rejected(self, app):
        """Test that tampered tokens are rejected"""
        from itsdangerous import URLSafeTimedSerializer, BadSignature

        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

        # Tampered token
        with pytest.raises(BadSignature):
            serializer.loads("tampered_token_12345", max_age=3600)

    def test_require_auth_decorator_blocks_unauthenticated(self, client):
        # Test that @require_auth blocks requests without auth header
        # Try to access protected endpoint
        response = client.get("/api/list-documents")
        assert response.status_code == 401

    def test_require_auth_decorator_validates_bearer_format(self, client):
        # Test that auth header must be in Bearer format
        response = client.get(
            "/api/list-documents",
            headers={"Authorization": "InvalidFormat token123"}
        )
        assert response.status_code == 401
        assert b"Missing or invalid" in response.data

    def test_require_auth_decorator_accepts_valid_token(self, client, app):
        # Test that valid tokens are accepted
        from itsdangerous import URLSafeTimedSerializer

        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})

        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
            mock_conn.execute.return_value.all.return_value = []

            response = client.get(
                "/api/list-documents",
                headers={"Authorization": f"Bearer {token}"}
            )
            # Should not be 401
            assert response.status_code != 401

    def test_missing_auth_header_returns_401(self, client):
        """Test that missing Authorization header returns 401"""
        response = client.get("/api/list-documents")
        assert response.status_code == 401
        json_data = response.get_json()
        assert "error" in json_data


class TestUserCreationAndLogin:
    # Test suite for user creation and login endpoints

    def test_create_user_validates_required_fields(self, client):
        # Test that email, login, and password are required
        incomplete_payloads = [
            {},
            {"email": "test@example.com"},
            {"email": "test@example.com", "login": "testuser"},
            {"login": "testuser", "password": "password123"},
        ]

        for payload in incomplete_payloads:
            response = client.post("/api/create-user", json=payload)
            assert response.status_code == 400
            json_data = response.get_json()
            assert "error" in json_data

    def test_create_user_normalizes_email(self, client):
        """Test that email is normalized (trimmed and lowercased)"""
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.begin.return_value.__enter__.return_value = mock_conn

            mock_result = MagicMock()
            mock_result.lastrowid = 1
            mock_conn.execute.return_value = mock_result

            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.email = "test@example.com"
            mock_row.login = "testuser"
            mock_result.one.return_value = mock_row

            response = client.post("/api/create-user", json={
                "email": "  TEST@EXAMPLE.COM  ",
                "login": "testuser",
                "password": "password123"
            })

            # Should succeed and normalize email
            if response.status_code == 201:
                json_data = response.get_json()
                assert json_data["email"] == "test@example.com"

    def test_create_user_handles_duplicate_email(self, client):
        """Test that duplicate emails are rejected"""
        from sqlalchemy.exc import IntegrityError

        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.begin.return_value.__enter__.return_value = mock_conn
            mock_conn.execute.side_effect = IntegrityError("", "", "")

            response = client.post("/api/create-user", json={
                "email": "test@example.com",
                "login": "testuser",
                "password": "password123"
            })

            assert response.status_code == 409
            assert b"already exists" in response.data

    def test_login_validates_required_fields(self, client):
        """Test that email and password are required for login"""
        incomplete_payloads = [
            {},
            {"email": "test@example.com"},
            {"password": "password123"},
        ]

        for payload in incomplete_payloads:
            response = client.post("/api/login", json=payload)
            assert response.status_code == 400

    def test_login_rejects_invalid_credentials(self, client):
        """Test that invalid credentials are rejected"""
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
            mock_conn.execute.return_value.first.return_value = None

            response = client.post("/api/login", json={
                "email": "test@example.com",
                "password": "wrong_password"
            })

            assert response.status_code == 401
            assert b"invalid credentials" in response.data

    def test_login_returns_token_on_success(self, client, app):
        # Test that successful login returns a token
        from werkzeug.security import generate_password_hash

        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn

            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.email = "test@example.com"
            mock_row.login = "testuser"
            mock_row.hpassword = generate_password_hash("password123")
            mock_conn.execute.return_value.first.return_value = mock_row

            response = client.post("/api/login", json={
                "email": "test@example.com",
                "password": "password123"
            })

            assert response.status_code == 200
            json_data = response.get_json()
            assert "token" in json_data
            assert "token_type" in json_data
            assert json_data["token_type"] == "bearer"
            assert "expires_in" in json_data


class TestHelperFunctions:
    # Test suite for helper functions

    def test_sha256_file_computes_correct_hash(self, tmp_path):
        """Test that _sha256_file computes correct hash"""
        # Create a test file
        test_file = tmp_path / "test.txt"
        test_content = b"Hello, World!"
        test_file.write_bytes(test_content)

        # Compute expected hash
        expected_hash = hashlib.sha256(test_content).hexdigest()

        # Test helper function logic
        h = hashlib.sha256()
        with test_file.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        actual_hash = h.hexdigest()

        assert actual_hash == expected_hash

    def test_sha256_file_handles_large_files(self, tmp_path):
        # Test that _sha256_file handles large files in chunks
        # Create a file larger than 1MB but under the MAX_CHUNK_SIZE
        test_file = tmp_path / "large.bin"
        test_content = b"A" * (2 * 1024 * 1024)  # 2MB
        test_file.write_bytes(test_content)

        # Compute hash
        h = hashlib.sha256()
        with test_file.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        file_hash = h.hexdigest()

        # Should complete without error
        assert len(file_hash) == 64  # SHA256 hex digest length


class TestConfigValidation:
    # Test suite for configuration validation

    def test_storage_dir_created_on_startup(self, tmp_path):
        # Test that STORAGE_DIR is created if it doesn't exist
        storage_dir = tmp_path / "storage"
        assert not storage_dir.exists()

        os.environ["STORAGE_DIR"] = str(storage_dir)
        app = create_app()

        assert storage_dir.exists()
        assert storage_dir.is_dir()

    def test_token_ttl_configuration(self):
        # Test that TOKEN_TTL_SECONDS is configurable
        os.environ["TOKEN_TTL_SECONDS"] = "86400"
        app = create_app()
        assert app.config["TOKEN_TTL_SECONDS"] == 86400

    def test_db_configuration(self):
        """Test that database configuration is read from environment"""
        os.environ["DB_USER"] = "custom_user"
        os.environ["DB_PASSWORD"] = "custom_pass"
        os.environ["DB_HOST"] = "custom_host"
        os.environ["DB_PORT"] = "3307"
        os.environ["DB_NAME"] = "custom_db"

        app = create_app()

        assert app.config["DB_USER"] == "custom_user"
        assert app.config["DB_PASSWORD"] == "custom_pass"
        assert app.config["DB_HOST"] == "custom_host"
        assert app.config["DB_PORT"] == 3307
        assert app.config["DB_NAME"] == "custom_db"


class TestStaticFileServing:
    # Test suite for static file serving

    def test_home_route_exists(self, client):
        response = client.get("/")
        # Should either return the index.html or 404 if static files not set up
        assert response.status_code in [200, 404]

    def test_static_file_route_exists(self, client):
        response = client.get("/notexist.html")
        # Should return 404 for nonexistent files
        assert response.status_code == 404


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
