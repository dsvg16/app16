# Security Hardening Tests for server.py

This directory contains comprehensive test suites for the security-hardened endpoints in `server.py`.

## Test Files Overview

### 1. `test_server_security_hardening.py`
Tests for **upload_document** and **get_document** endpoints focusing on:
- **Path traversal prevention**: Validates that malicious filenames and paths cannot escape STORAGE_DIR
- **Filename sanitization**: Tests `secure_filename()` usage for user inputs
- **PDF validation**: Ensures only valid PDF files are accepted (header check)
- **File size limits**: Enforces MAX_PARSE_SIZE (50MB) limit
- **Symlink protection**: Tests O_NOFOLLOW flag to prevent symlink attacks
- **File permissions**: Validates 0o600 (owner read/write only) permissions
- **Resource cleanup**: Ensures temp files and file descriptors are cleaned up
- **Authentication**: Validates auth requirements and token validation

### 2. `test_server_delete_security.py`
Tests for **delete_document** endpoint focusing on:
- **_safe_resolve_under_storage()** helper function validation
- **Ownership enforcement**: Users can only delete their own documents
- **Path boundary checks**: Prevents deletion of files outside STORAGE_DIR
- **Graceful error handling**: Missing files, DB errors, path traversal attempts
- **Security logging**: Ensures security failures are logged appropriately

### 3. `test_server_watermark_security.py`
Tests for **create_watermark** and **read_watermark** endpoints focusing on:
- **Input validation**: All required fields (method, intended_for, secret, key)
- **Ownership enforcement**: Users can only watermark their own documents
- **Path safety**: Document paths must be within STORAGE_DIR
- **Output sanitization**: `intended_for` field sanitized for filename generation
- **Watermark applicability**: Checks before applying watermark
- **Output validation**: Ensures watermark produces valid output bytes

### 4. `test_server_auth_helpers.py`
Tests for authentication and helper functions:
- **Token generation/validation**: ITSDangerous URLSafeTimedSerializer
- **@require_auth decorator**: Blocks unauthorized requests
- **User creation**: Email normalization, duplicate handling
- **Login**: Credential validation, token issuance
- **Helper functions**: _sha256_file, config validation
- **Healthz endpoint**: DB connectivity checks

## Security Features Tested

### Path Traversal Prevention
```python
# Malicious attempts blocked:
"../../../etc/passwd"
"..\\..\\..\\windows\\system32"
"....//....//etc/passwd"
```

### Filename Sanitization
```python
from werkzeug.utils import secure_filename

# All user-provided filenames and paths sanitized:
- secure_filename(file.filename)
- secure_filename(g.user["login"])
- secure_filename(intended_for)
```

### Path Boundary Validation
```python
# Enforces files stay within STORAGE_DIR:
stored_path.relative_to(app.config["STORAGE_DIR"].resolve())

# Raises ValueError if path escapes
```

### PDF Validation
```python
# Header validation:
header = file.read(4)
if header != b"%PDF":
    return error
```

### Symlink Protection
```python
# Uses O_NOFOLLOW flag:
flags = os.O_RDONLY | os.O_NOFOLLOW
fd = os.open(str(file_path), flags)
```

## Running the Tests

### Prerequisites
```bash
cd server
pip install -r requirements.txt
pip install pytest pytest-cov
```

### Run All Security Tests
```bash
# Run all tests
pytest test/test_server_security_hardening.py -v
pytest test/test_server_delete_security.py -v
pytest test/test_server_watermark_security.py -v
pytest test/test_server_auth_helpers.py -v

# Or run all at once
pytest test/test_server_*.py -v
```

### Run with Coverage
```bash
# Generate coverage report
pytest test/test_server_*.py --cov=src/server --cov-report=html --cov-report=term

# View HTML report
open htmlcov/index.html
```

### Run Specific Test Classes
```bash
# Test only upload security
pytest test/test_server_security_hardening.py::TestUploadDocumentSecurity -v

# Test only delete security
pytest test/test_server_delete_security.py::TestDeleteDocumentSecurity -v

# Test only watermark security
pytest test/test_server_watermark_security.py::TestCreateWatermarkSecurity -v
```

### Run Specific Tests
```bash
# Test path traversal prevention
pytest test/test_server_security_hardening.py::TestUploadDocumentSecurity::test_upload_sanitizes_filename_path_traversal -v

# Test symlink protection
pytest test/test_server_security_hardening.py::TestGetDocumentSecurity::test_get_document_refuses_symlinks -v
```

## Test Coverage

The test suites cover:
- ✅ **Authentication & Authorization**: Token validation, ownership checks
- ✅ **Input Validation**: Required fields, type checking, format validation
- ✅ **Path Security**: Traversal prevention, boundary enforcement, symlink protection
- ✅ **File Handling**: PDF validation, size limits, secure permissions
- ✅ **Resource Management**: Cleanup on errors, file descriptor handling
- ✅ **Error Handling**: Graceful degradation, appropriate error codes
- ✅ **Security Logging**: Failed attempts, suspicious activity

## Mock Strategy

Tests use mocking to avoid requiring:
- Real database connections (mocked with `patch('server.create_engine')`)
- Actual file uploads (using `BytesIO` and `FileStorage`)
- Real watermarking operations (mocked `watermarking_utils`)

## Expected Test Results

All tests should **PASS** if security hardening is properly implemented. Common failure modes:

### Path Traversal Not Prevented
```
FAILED test_upload_sanitizes_filename_path_traversal
AssertionError: Path traversal was not blocked
```
**Fix**: Ensure `secure_filename()` is used on all user inputs.

### Symlink Protection Missing
```
FAILED test_get_document_refuses_symlinks
AssertionError: Symlink was followed
```
**Fix**: Ensure `O_NOFOLLOW` flag is used when opening files.

### Authentication Not Enforced
```
FAILED test_upload_requires_auth
AssertionError: 200 != 401
```
**Fix**: Ensure `@require_auth` decorator is applied to protected endpoints.

## Security Hardening Checklist

Based on these tests, your `server.py` should implement:

- [x] `secure_filename()` on all user-provided filenames
- [x] `secure_filename()` on user login for directory names
- [x] Path boundary validation (`.relative_to()` checks)
- [x] PDF header validation (check for `%PDF`)
- [x] File size limits (MAX_PARSE_SIZE)
- [x] Restrictive file permissions (0o600)
- [x] Symlink protection (O_NOFOLLOW)
- [x] Resource cleanup (temp files, file descriptors)
- [x] Ownership enforcement (uid checks in queries)
- [x] Authentication on all protected endpoints
- [x] Input validation (required fields, types)
- [x] Error handling (don't leak info, clean up resources)
- [x] Security logging (failed attempts, suspicious activity)

## Contributing

When adding new endpoints to `server.py`:
1. Add corresponding tests to appropriate test file
2. Test all security aspects: auth, input validation, path safety
3. Ensure 100% code coverage for security-critical paths
4. Run full test suite before committing

## References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Werkzeug secure_filename](https://werkzeug.palletsprojects.com/en/2.0.x/utils/#werkzeug.utils.secure_filename)
- [Python os.O_NOFOLLOW](https://docs.python.org/3/library/os.html#os.O_NOFOLLOW)
- [Flask Testing](https://flask.palletsprojects.com/en/2.0.x/testing/)

## Questions?

For questions about these tests or security hardening, contact the security team or review the commit that added hardening: `83285e7`
