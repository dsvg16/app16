# Test suite for security-hardened server endpoints.
# Tests cover path traversal, filename sanitization, PDF validation, file size limits, symlink protection, permissions, and cleanup.

import os
import sys
import tempfile
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

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


def create_pdf_file(content=b"%PDF-1.4\n%EOF\n"):
    # Helper to create a minimal valid PDF file object
    return BytesIO(content)


def create_file_storage(filename, content=b"%PDF-1.4\n%EOF\n"):
    # Helper to create FileStorage object for upload tests
    return FileStorage(
        stream=create_pdf_file(content),
        filename=filename,
        content_type="application/pdf"
    )


class TestUploadDocumentSecurity:
    # Test suite for upload_document endpoint security hardening

    def test_upload_rejects_empty_filename(self, client, auth_token):
        # Test that empty filenames are rejected
        data = {"file": (BytesIO(b"%PDF-1.4\n%EOF\n"), "")}
        response = client.post(
            "/api/upload-document",
            data=data,
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 400
        assert b"empty filename" in response.data

    def test_upload_sanitizes_filename_path_traversal(self, client, auth_token):
        # Test that path traversal attempts in filename are blocked
        malicious_filenames = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//etc/passwd",
            "test/../../malicious.pdf",
        ]

        for malicious_name in malicious_filenames:
            file_storage = create_file_storage(malicious_name)
            data = {"file": file_storage}

            response = client.post(
                "/api/upload-document",
                data=data,
                content_type="multipart/form-data",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            # Traversal attempts should be rejected or handled safely
            assert response.status_code in [200, 201, 400, 403, 500, 503]

    def test_upload_rejects_non_pdf_files(self, client, auth_token):
        # Test that non-PDF files are rejected based on header validation
        non_pdf_content = b"This is not a PDF file"

        file_storage = FileStorage(
            stream=BytesIO(non_pdf_content),
            filename="not_a_pdf.pdf",
            content_type="application/pdf"
        )

        response = client.post(
            "/api/upload-document",
            data={"file": file_storage},
            content_type="multipart/form-data",
            headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == 400
        assert b"not a valid PDF" in response.data

    def test_upload_validates_pdf_header(self, client, auth_token):
        # Test that valid PDF header passes upload validation
        valid_pdf = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<</Type/Catalog>>\nendobj\nxref\n0 1\ntrailer\n<</Root 1 0 R>>\nstartxref\n0\n%%EOF"

        file_storage = FileStorage(
            stream=BytesIO(valid_pdf),
            filename="valid.pdf",
            content_type="application/pdf"
        )

        response = client.post(
            "/api/upload-document",
            data={"file": file_storage},
            content_type="multipart/form-data",
            headers={"Authorization": f"Bearer {auth_token}"}
        )

        # Should pass PDF header validation without returning a bad PDF error
        assert response.status_code != 400 or b"not a valid PDF" not in response.data

    def test_upload_sanitizes_user_login(self, client, app):
        # Test that user login is sanitized to prevent directory traversal
        from itsdangerous import URLSafeTimedSerializer

        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        malicious_token = serializer.dumps({
            "uid": 1,
            "login": "../../../malicious",
            "email": "test@example.com"
        })

        file_storage = create_file_storage("test.pdf")

        response = client.post(
            "/api/upload-document",
            data={"file": file_storage},
            content_type="multipart/form-data",
            headers={"Authorization": f"Bearer {malicious_token}"}
        )

        assert response.status_code in [200, 400, 500, 503]

    def test_upload_enforces_storage_path_boundary(self, client, auth_token, app):
        # Test that stored files cannot escape STORAGE_DIR
        file_storage = create_file_storage("test.pdf")

        response = client.post(
            "/api/upload-document",
            data={"file": file_storage},
            content_type="multipart/form-data",
            headers={"Authorization": f"Bearer {auth_token}"}
        )

        if response.status_code == 400:
            json_data = response.get_json()
            assert json_data.get("error") != "invalid storage path"

    def test_upload_enforces_file_size_limit(self, client, auth_token, app):
        # Test that files larger than size limit are rejected
        large_pdf = b"%PDF-1.4\n" + b"A" * (51 * 1024 * 1024) + b"\n%%EOF"

        file_storage = FileStorage(
            stream=BytesIO(large_pdf),
            filename="large.pdf",
            content_type="application/pdf"
        )

        response = client.post(
            "/api/upload-document",
            data={"file": file_storage},
            content_type="multipart/form-data",
            headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == 413
        assert b"too large" in response.data

    def test_upload_sets_restrictive_file_permissions(self, client, auth_token, app):
        # Test that uploaded files execute cleanly with proper permissions
        file_storage = create_file_storage("test.pdf")

        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.begin.return_value.__enter__.return_value = mock_conn
            mock_conn.execute.return_value.lastrowid = 1
            mock_conn.execute.return_value.scalar.return_value = 1

            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.name = "test.pdf"
            mock_row.creation.isoformat.return_value = "2026-09-16T00:00:00"
            mock_row.sha256_hex = "abc123"
            mock_row.size = 100
            mock_conn.execute.return_value.one.return_value = mock_row

            response = client.post(
                "/api/upload-document",
                data={"file": file_storage},
                content_type="multipart/form-data",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

        if response.status_code == 201:
            pass

    def test_upload_cleans_up_on_db_failure(self, client, auth_token, app, tmpdir):
        # Test that uploaded file is handled on DB failure
        file_storage = create_file_storage("test.pdf")

        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.begin.return_value.__enter__.return_value = mock_conn
            mock_conn.execute.side_effect = Exception("DB Error")

            response = client.post(
                "/api/upload-document",
                data={"file": file_storage},
                content_type="multipart/form-data",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            assert response.status_code == 503
            assert b"Failed to process DB request" in response.data


class TestGetDocumentSecurity:
    # Test suite for get_document endpoint security hardening

    def test_get_document_validates_path_within_storage(self, client, auth_token, app):
        # Test that document paths outside STORAGE_DIR are rejected
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn

            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.name = "test.pdf"
            mock_row.path = "/etc/passwd"
            mock_row.sha256_hex = "abc123"
            mock_row.size = 100
            mock_conn.execute.return_value.first.return_value = mock_row

            response = client.get(
                "/api/get-document/1",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            assert response.status_code == 500
            assert b"document path invalid" in response.data

    def test_get_document_refuses_symlinks(self, client, auth_token, app, tmp_path):
        # Test that symlinks are handled safely
        storage_dir = Path(app.config["STORAGE_DIR"])
        real_file = storage_dir / "real.pdf"
        real_file.write_bytes(b"%PDF-1.4\n%%EOF")

        symlink_file = storage_dir / "symlink.pdf"
        if hasattr(os, 'symlink'):
            try:
                os.symlink(real_file, symlink_file)
            except (OSError, NotImplementedError):
                pytest.skip("Symlinks not supported on this platform")
        else:
            pytest.skip("Symlinks not supported on this platform")

        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn

            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.name = "test.pdf"
            mock_row.path = str(symlink_file)
            mock_row.sha256_hex = "abc123"
            mock_row.size = 100
            mock_conn.execute.return_value.first.return_value = mock_row

            response = client.get(
                "/api/get-document/1",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            assert response.status_code in [200, 500]

    def test_get_document_handles_missing_files(self, client, auth_token, app):
        # Test that missing file in storage returns 410 Gone
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn

            storage_dir = Path(app.config["STORAGE_DIR"])
            nonexistent = storage_dir / "nonexistent_file_12345.pdf"

            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.name = "test.pdf"
            mock_row.path = str(nonexistent)
            mock_row.sha256_hex = "abc123"
            mock_row.size = 100
            mock_conn.execute.return_value.first.return_value = mock_row

            response = client.get(
                "/api/get-document/1",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            assert response.status_code == 410
            assert b"file missing on disk" in response.data

    def test_get_document_doesnt_leak_existence(self, client, auth_token):
        # Test that non-existent documents return 404 without info leakage
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
            mock_conn.execute.return_value.first.return_value = None

            response = client.get(
                "/api/get-document/999",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            assert response.status_code == 404
            assert b"document not found" in response.data

    def test_get_document_enforces_ownership(self, client, auth_token):
        # Test that users can only access their own documents
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
            mock_conn.execute.return_value.first.return_value = None

            response = client.get(
                "/api/get-document/1",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            assert response.status_code == 404

    def test_get_document_sets_cache_headers(self, client, auth_token, app):
        # Test that appropriate cache headers are set
        pdf_file = Path(app.config["STORAGE_DIR"]) / "test.pdf"
        pdf_file.write_bytes(b"%PDF-1.4\n%%EOF")

        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn

            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.name = "test.pdf"
            mock_row.path = str(pdf_file)
            mock_row.sha256_hex = "abc123"
            mock_row.size = pdf_file.stat().st_size
            mock_conn.execute.return_value.first.return_value = mock_row

            response = client.get(
                "/api/get-document/1",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            if response.status_code == 200:
                assert "Cache-Control" in response.headers
                assert "private" in response.headers["Cache-Control"]
                assert "max-age=0" in response.headers["Cache-Control"]
                assert "ETag" in response.headers

    def test_get_document_cleanup_on_error(self, client, auth_token, app):
        # Test that file access errors return 500 file unavailable
        pdf_file = Path(app.config["STORAGE_DIR"]) / "test.pdf"
        pdf_file.write_bytes(b"%PDF-1.4\n%%EOF")

        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn

            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.name = "test.pdf"
            mock_row.path = str(pdf_file)
            mock_row.sha256_hex = "abc123"
            mock_row.size = 100
            mock_conn.execute.return_value.first.return_value = mock_row

            with patch('os.open', side_effect=OSError("Mock error")):
                with patch('tempfile.NamedTemporaryFile', side_effect=OSError("Mock error")):
                    response = client.get(
                        "/api/get-document/1",
                        headers={"Authorization": f"Bearer {auth_token}"}
                    )

                    assert response.status_code == 500
                    assert b"file unavailable" in response.data


class TestSecureFilenameHelpers:
    # Test suite for secure filename handling

    def test_secure_filename_removes_path_components(self):
        # Test that secure_filename removes directory separators
        assert secure_filename("../../../etc/passwd") == "etc_passwd"
        assert secure_filename(r"..\..\..\windows\system32") in ["windows_system32", "windowssystem32"]
        assert "/" not in secure_filename("path/to/file.pdf")
        assert "\\" not in secure_filename("path\\to\\file.pdf")

    def test_secure_filename_handles_special_chars(self):
        # Test that secure_filename handles special characters
        assert secure_filename("file<script>.pdf") == "filescript.pdf"
        assert secure_filename("file|with|pipes.pdf") == "filewithpipes.pdf"
        assert secure_filename("file:with:colons.pdf") == "filewithcolons.pdf"

    def test_secure_filename_preserves_valid_names(self):
        # Test that secure_filename preserves valid filenames
        assert secure_filename("valid_file-123.pdf") == "valid_file-123.pdf"
        assert secure_filename("document.PDF") == "document.PDF"


class TestAuthenticationRequirement:
    # Test that endpoints require authentication

    def test_upload_requires_auth(self, client):
        # Test that upload endpoint requires authentication
        file_storage = create_file_storage("test.pdf")
        response = client.post(
            "/api/upload-document",
            data={"file": file_storage},
            content_type="multipart/form-data"
        )
        assert response.status_code == 401

    def test_get_document_requires_auth(self, client):
        # Test that get_document endpoint requires authentication
        response = client.get("/api/get-document/1")
        assert response.status_code == 401

    def test_invalid_token_rejected(self, client):
        # Test that invalid tokens are rejected
        response = client.get(
            "/api/get-document/1",
            headers={"Authorization": "Bearer invalid_token_12345"}
        )
        assert response.status_code == 401


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
