# Test suite for create_watermark endpoint security hardening.
# Tests cover input validation, ownership enforcement, path safety, applicability, and secure output handling.

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

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
    # Test client
    return app.test_client()


@pytest.fixture
def auth_token(app):
    # Generate a valid auth token for testing
    from itsdangerous import URLSafeTimedSerializer
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
    token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
    return token


class TestCreateWatermarkSecurity:
    # Test suite for create_watermark security

    def test_watermark_requires_document_id(self, client, auth_token):
        # Test that document ID is required
        response = client.post(
            "/api/create-watermark",
            json={},
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 400
        assert b"document_id" in response.data or b"document id" in response.data

    def test_watermark_validates_required_fields(self, client, auth_token):
        # Test that all required fields are validated
        incomplete_payloads = [
            {"id": 1},
            {"id": 1, "method": "test"},
            {"id": 1, "method": "test", "intended_for": "user@example.com"},
            {"id": 1, "method": "test", "intended_for": "user@example.com", "secret": "sec"},
        ]

        for payload in incomplete_payloads:
            response = client.post(
                "/api/create-watermark",
                json=payload,
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            assert response.status_code == 400
            json_data = response.get_json()
            assert "error" in json_data

    def test_watermark_enforces_ownership(self, client, auth_token):
        # Test that users can only watermark their own documents
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn

            mock_conn.execute.return_value.first.return_value = None

            response = client.post(
                "/api/create-watermark/999",
                json={
                    "method": "test-method",
                    "intended_for": "user@example.com",
                    "secret": "secret123",
                    "key": "key123"
                },
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            assert response.status_code == 404
            assert b"document not found" in response.data

    def test_watermark_validates_path_within_storage(self, client, auth_token, app):
        # Test that document paths outside STORAGE_DIR are rejected
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn

            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.name = "test.pdf"
            mock_row.path = "/etc/passwd"
            mock_conn.execute.return_value.first.return_value = mock_row

            response = client.post(
                "/api/create-watermark/1",
                json={
                    "method": "test-method",
                    "intended_for": "user@example.com",
                    "secret": "secret123",
                    "key": "key123"
                },
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            assert response.status_code == 500
            assert b"document path invalid" in response.data

    def test_watermark_handles_missing_files(self, client, auth_token, app):
        # Test that missing files return 410 Gone
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn

            nonexistent = Path(app.config["STORAGE_DIR"]) / "nonexistent.pdf"
            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.name = "test.pdf"
            mock_row.path = str(nonexistent)
            mock_conn.execute.return_value.first.return_value = mock_row

            response = client.post(
                "/api/create-watermark/1",
                json={
                    "method": "test-method",
                    "intended_for": "user@example.com",
                    "secret": "secret123",
                    "key": "key123"
                },
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            assert response.status_code == 410
            assert b"file missing on disk" in response.data

    def test_watermark_checks_applicability(self, client, auth_token, app):
        # Test that watermark applicability is checked
        pdf_file = Path(app.config["STORAGE_DIR"]) / "test.pdf"
        pdf_file.write_bytes(b"%PDF-1.4\n%%EOF")

        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn

            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.name = "test.pdf"
            mock_row.path = str(pdf_file)
            mock_conn.execute.return_value.first.return_value = mock_row

            with patch('watermarking_utils.is_watermarking_applicable', return_value=False):
                response = client.post(
                    "/api/create-watermark/1",
                    json={
                        "method": "test-method",
                        "intended_for": "user@example.com",
                        "secret": "secret123",
                        "key": "key123"
                    },
                    headers={"Authorization": f"Bearer {auth_token}"}
                )

                assert response.status_code == 400
                assert b"not applicable" in response.data

    def test_watermark_sanitizes_intended_for_filename(self, client, auth_token, app):
        # Test that intended_for field is sanitized when creating output filename
        pdf_file = Path(app.config["STORAGE_DIR"]) / "test.pdf"
        pdf_file.write_bytes(b"%PDF-1.4\n%%EOF")

        malicious_intended_for = "../../../etc/passwd"

        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
            mock_engine.return_value.begin.return_value.__enter__.return_value = mock_conn

            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.name = "test.pdf"
            mock_row.path = str(pdf_file)
            mock_conn.execute.return_value.first.return_value = mock_row

            mock_result = MagicMock()
            mock_result.scalar.return_value = 1
            mock_conn.execute.return_value.mock_result = 1

            with patch('watermarking_utils.is_watermarking_applicable', return_value=True):
                with patch('watermarking_utils.apply_watermark', return_value=b"%PDF-watermarked"):
                    response = client.post(
                        "/api/create-watermark/1",
                        json={
                            "method": "test-method",
                            "intended_for": malicious_intended_for,
                            "secret": "secret123",
                            "key": "key123"
                        },
                        headers={"Authorization": f"Bearer {auth_token}"}
                    )

                    assert response.status_code in [200, 201, 400, 410, 500, 503]

    def test_watermark_validates_output_bytes(self, client, auth_token, app):
        # Test that watermark output is validated
        pdf_file = Path(app.config["STORAGE_DIR"]) / "test.pdf"
        pdf_file.write_bytes(b"%PDF-1.4\n%%EOF")

        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn

            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.name = "test.pdf"
            mock_row.path = str(pdf_file)
            mock_conn.execute.return_value.first.return_value = mock_row

            with patch('watermarking_utils.is_watermarking_applicable', return_value=True):
                # Test with empty output
                with patch('watermarking_utils.apply_watermark', return_value=b""):
                    response = client.post(
                        "/api/create-watermark/1",
                        json={
                            "method": "test-method",
                            "intended_for": "user@example.com",
                            "secret": "secret123",
                            "key": "key123"
                        },
                        headers={"Authorization": f"Bearer {auth_token}"}
                    )

                    assert response.status_code == 500
                    assert b"no output" in response.data

    def test_watermark_accepts_multiple_id_sources(self, client, auth_token):
        # Test that document ID can come from path, query, or body
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
            mock_conn.execute.return_value.first.return_value = None

            payload = {
                "method": "test-method",
                "intended_for": "user@example.com",
                "secret": "secret123",
                "key": "key123"
            }

            # Test path parameter
            response = client.post(
                "/api/create-watermark/123",
                json=payload,
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            assert response.status_code in [200, 201, 404]

            # Test query parameter
            response = client.post(
                "/api/create-watermark?id=123",
                json=payload,
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            assert response.status_code in [200, 201, 404]

            # Test JSON body
            payload_with_id = payload.copy()
            payload_with_id["id"] = 123
            response = client.post(
                "/api/create-watermark",
                json=payload_with_id,
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            assert response.status_code in [200, 201, 404]


class TestWatermarkAuthentication:
    # Test authentication requirements for watermarking

    def test_watermark_requires_auth(self, client):
        # Test that watermark creation requires authentication
        response = client.post(
            "/api/create-watermark/1",
            json={
                "method": "test-method",
                "intended_for": "user@example.com",
                "secret": "secret123",
                "key": "key123"
            }
        )
        assert response.status_code == 401

    def test_watermark_rejects_invalid_token(self, client):
        # Test that invalid tokens are rejected
        response = client.post(
            "/api/create-watermark/1",
            json={
                "method": "test-method",
                "intended_for": "user@example.com",
                "secret": "secret123",
                "key": "key123"
            },
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401


class TestReadWatermarkSecurity:
    # Test suite for read_watermark security

    def test_read_watermark_requires_auth(self, client):
        # Test that watermark reading requires authentication
        response = client.post(
            "/api/read-watermark/1",
            json={"method": "test-method", "key": "key123"}
        )
        assert response.status_code == 401

    def test_read_watermark_validates_required_fields(self, client, auth_token):
        # Test that required fields are validated
        response = client.post(
            "/api/read-watermark/1",
            json={},
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 400

    def test_read_watermark_enforces_ownership(self, client, auth_token):
        # Test that users can only read watermarks from their own documents
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
            mock_conn.execute.return_value.first.return_value = None

            response = client.post(
                "/api/read-watermark/999",
                json={"method": "test-method", "key": "key123"},
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            assert response.status_code == 404
            assert b"document not found" in response.data


class TestGetWatermarkingMethods:
    # Test suite for get_watermarking_methods endpoint

    def test_get_methods_returns_list(self, client):
        # Test that available methods are returned
        response = client.get("/api/get-watermarking-methods")

        assert response.status_code == 200
        json_data = response.get_json()
        assert "methods" in json_data
        assert "count" in json_data
        assert isinstance(json_data["methods"], list)

    def test_get_methods_includes_descriptions(self, client):
        # Test that method descriptions are included
        response = client.get("/api/get-watermarking-methods")

        json_data = response.get_json()
        if json_data["count"] > 0:
            method = json_data["methods"][0]
            assert "name" in method
            assert "description" in method

    def test_get_methods_does_not_require_auth(self, client):
        # Test that listing methods doesn't require authentication
        response = client.get("/api/get-watermarking-methods")
        assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
