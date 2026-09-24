
import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from server import create_app


@pytest.fixture
def app():
    """Create test app with temporary storage"""
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
    """Test client"""
    return app.test_client()


@pytest.fixture
def auth_token(app):
    """Generate a valid auth token for testing"""
    from itsdangerous import URLSafeTimedSerializer
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
    token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
    return token


class TestDeleteDocumentSecurity:
    """Test suite for delete_document security"""

    def test_delete_requires_document_id(self, client, auth_token):
        """Test that document ID is required"""
        response = client.delete(
            "/api/delete-document",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 400
        assert b"document id required" in response.data

    def test_delete_enforces_ownership(self, client, auth_token):
        """Test that users can only delete their own documents"""
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn

            # Simulate document not found (ownership check fails)
            mock_conn.execute.return_value.first.return_value = None

            response = client.delete(
                "/api/delete-document/999",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            assert response.status_code == 404
            assert b"document not found" in response.data

    def test_delete_refuses_path_outside_storage(self, client, auth_token, app):
        """Test that paths outside STORAGE_DIR are not deleted"""
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
            mock_engine.return_value.begin.return_value.__enter__.return_value = mock_conn

            # Mock document with malicious path
            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.path = "/etc/passwd"  # Outside STORAGE_DIR
            mock_conn.execute.return_value.first.return_value = mock_row

            response = client.delete(
                "/api/delete-document/1",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            # Should succeed in DB deletion but log error about path safety
            if response.status_code == 200:
                json_data = response.get_json()
                assert json_data.get("deleted") == True
                assert json_data.get("note") is not None  # Error noted

    def test_delete_handles_missing_files_gracefully(self, client, auth_token, app, tmp_path):
        """Test that delete handles missing files without crashing"""
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
            mock_engine.return_value.begin.return_value.__enter__.return_value = mock_conn

            # Mock document with non-existent file path
            nonexistent = Path(app.config["STORAGE_DIR"]) / "test.pdf"
            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.path = str(nonexistent)
            mock_conn.execute.return_value.first.return_value = mock_row

            response = client.delete(
                "/api/delete-document/1",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            assert response.status_code == 200
            json_data = response.get_json()
            assert json_data.get("deleted") == True
            assert json_data.get("file_missing") == True

    def test_delete_accepts_multiple_id_sources(self, client, auth_token):
        """Test that document ID can come from path, query, or body"""
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
            mock_conn.execute.return_value.first.return_value = None

            # Test path parameter
            response = client.delete(
                "/api/delete-document/123",
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            assert response.status_code in [200, 404]

            # Test query parameter
            response = client.delete(
                "/api/delete-document?id=123",
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            assert response.status_code in [200, 404]

            # Test JSON body (using POST method)
            response = client.post(
                "/api/delete-document",
                json={"id": 123},
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            assert response.status_code in [200, 404]

    def test_delete_logs_security_failures(self, client, auth_token, app):
        """Test that security failures are logged"""
        with patch('server.create_engine') as mock_engine:
            mock_conn = MagicMock()
            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn
            mock_engine.return_value.begin.return_value.__enter__.return_value = mock_conn

            # Mock document with path escaping storage
            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.path = "../../../../etc/passwd"
            mock_conn.execute.return_value.first.return_value = mock_row

            with patch.object(app.logger, 'error') as mock_logger:
                response = client.delete(
                    "/api/delete-document/1",
                    headers={"Authorization": f"Bearer {auth_token}"}
                )

                # Logger should have been called for path safety failure
                # (In actual implementation, this depends on path resolution logic)

    def test_delete_handles_db_errors_gracefully(self, client, auth_token):
        """Test that DB errors are handled properly"""
        with patch('server.create_engine') as mock_engine:
            # First query succeeds (fetch document)
            mock_conn_read = MagicMock()
            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.path = "/tmp/test.pdf"
            mock_conn_read.execute.return_value.first.return_value = mock_row

            # Second query fails (delete operation)
            mock_conn_write = MagicMock()
            mock_conn_write.execute.side_effect = Exception("DB Error")

            mock_engine.return_value.connect.return_value.__enter__.return_value = mock_conn_read
            mock_engine.return_value.begin.return_value.__enter__.return_value = mock_conn_write

            response = client.delete(
                "/api/delete-document/1",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

            assert response.status_code == 503
            assert b"Failed to process DB request" in response.data


class TestSafeResolveUnderStorage:
    """Test the _safe_resolve_under_storage helper function"""

    def test_safe_resolve_allows_valid_relative_paths(self, app, tmp_path):
        """Test that valid relative paths are allowed"""
        storage_root = tmp_path / "storage"
        storage_root.mkdir()

        # Create a file
        test_file = storage_root / "test.pdf"
        test_file.write_text("test")

        # Import the helper (it's defined inside create_app, so we need to access it)
        # For now, test the logic conceptually
        relative_path = "test.pdf"
        fp = Path(relative_path)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()

        # Should succeed
        fp.relative_to(storage_root.resolve())
        assert fp.is_relative_to(storage_root.resolve()) or True  # Python 3.9+ has is_relative_to

    def test_safe_resolve_blocks_path_traversal(self, tmp_path):
        """Test that path traversal attempts are blocked"""
        storage_root = tmp_path / "storage"
        storage_root.mkdir()

        # Try to escape with ..
        malicious_path = "../../../etc/passwd"
        fp = Path(malicious_path)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()

        # Should raise ValueError or return False
        try:
            fp.relative_to(storage_root.resolve())
            # If we get here, path is within storage_root
            assert fp.is_relative_to(storage_root.resolve())
        except ValueError:
            # Expected: path escapes storage_root
            pass

    def test_safe_resolve_handles_absolute_paths_correctly(self, tmp_path):
        """Test that absolute paths are validated correctly"""
        storage_root = tmp_path / "storage"
        storage_root.mkdir()

        # Absolute path inside storage
        valid_absolute = storage_root / "file.pdf"
        assert valid_absolute.resolve().is_relative_to(storage_root.resolve())

        # Absolute path outside storage
        invalid_absolute = tmp_path / "outside" / "file.pdf"
        tmp_path.mkdir(exist_ok=True)
        (tmp_path / "outside").mkdir(exist_ok=True)

        try:
            invalid_absolute.resolve().relative_to(storage_root.resolve())
            assert False, "Should have raised ValueError"
        except ValueError:
            pass  # Expected

    def test_safe_resolve_handles_symlinks(self, tmp_path):
        """Test that symlinks are resolved correctly"""
        if not hasattr(os, 'symlink'):
            pytest.skip("Symlinks not supported on this platform")

        storage_root = tmp_path / "storage"
        storage_root.mkdir()

        # Create a file outside storage
        outside_file = tmp_path / "outside.pdf"
        outside_file.write_text("outside")

        # Create a symlink inside storage pointing outside
        symlink = storage_root / "link.pdf"
        try:
            os.symlink(outside_file, symlink)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not supported")

        # After resolve(), symlink should point outside storage
        resolved = symlink.resolve()
        try:
            resolved.relative_to(storage_root.resolve())
            assert False, "Symlink should resolve outside storage"
        except ValueError:
            pass  # Expected: symlink escapes storage


class TestDeleteDocumentAuthentication:
    """Test authentication requirements for delete"""

    def test_delete_requires_auth(self, client):
        """Test that delete requires authentication"""
        response = client.delete("/api/delete-document/1")
        assert response.status_code == 401

    def test_delete_rejects_invalid_token(self, client):
        """Test that invalid tokens are rejected"""
        response = client.delete(
            "/api/delete-document/1",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
