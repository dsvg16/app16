# Quick Start Guide - Running Security Tests

## Quick Test Run

Test that everything is set up correctly:

```bash
# 1. Navigate to server directory
cd server

# 2. Check Python version (should be 3.9+)
python3 --version

# 3. Install pytest if not already installed
pip install pytest

# 4. Run a simple test to verify setup
pytest test/test_api.py -v
```

Expected output:
```
test_healthz_route PASSED
```

## Run Security Tests

### Option 1: Run All Security Tests
```bash
pytest test/test_server_security_hardening.py \
       test/test_server_delete_security.py \
       test/test_server_watermark_security.py \
       test/test_server_auth_helpers.py -v
```

### Option 2: Run One File at a Time
```bash
# Upload/Download security
pytest test/test_server_security_hardening.py -v

# Delete security  
pytest test/test_server_delete_security.py -v

# Watermark security
pytest test/test_server_watermark_security.py -v

# Auth and helpers
pytest test/test_server_auth_helpers.py -v
```

### Option 3: Run Specific Test
```bash
# Test path traversal prevention
pytest test/test_server_security_hardening.py::TestUploadDocumentSecurity::test_upload_sanitizes_filename_path_traversal -v
```

## Expected Results

### ✅ All Tests Pass
```
test/test_server_security_hardening.py::TestUploadDocumentSecurity::test_upload_rejects_empty_filename PASSED
test/test_server_security_hardening.py::TestUploadDocumentSecurity::test_upload_sanitizes_filename_path_traversal PASSED
...
======================== 70 passed in 2.45s ========================
```

### ⚠️ Some Tests Fail
If tests fail, it indicates missing security hardening. Example:

```
FAILED test/test_server_security_hardening.py::TestUploadDocumentSecurity::test_upload_rejects_non_pdf_files
AssertionError: assert 200 == 400
```

**What to do**:
1. Read the assertion error message
2. Check the corresponding function in `server.py`
3. Ensure security hardening is implemented
4. Re-run the test

## Common Issues

### Issue: Import Error
```
ImportError: No module named 'server'
```

**Fix**: Ensure you're in the `server/` directory and `src/` is in Python path:
```bash
cd server
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
pytest test/test_server_*.py -v
```

### Issue: Database Connection Error
```
sqlalchemy.exc.OperationalError: Can't connect to MySQL server
```

**Fix**: Tests mock database connections, so this shouldn't happen. If it does:
```bash
# Ensure mock is working
pytest test/test_server_security_hardening.py::TestUploadDocumentSecurity::test_upload_rejects_empty_filename -v -s
```

### Issue: Missing Dependencies
```
ModuleNotFoundError: No module named 'pytest'
```

**Fix**: Install dependencies:
```bash
pip install pytest pytest-cov
pip install -r requirements.txt  # If exists
```

## Test Structure

Each test file follows this pattern:

```python
@pytest.fixture
def app():
    """Create test app with temp storage"""
    ...

@pytest.fixture  
def client(app):
    """Test client"""
    return app.test_client()

@pytest.fixture
def auth_token(app):
    """Valid auth token"""
    ...

class TestSomething:
    def test_feature(self, client, auth_token):
        """Test description"""
        response = client.post(..., headers={"Authorization": f"Bearer {auth_token}"})
        assert response.status_code == expected
```

## Debugging Tests

### Run with verbose output
```bash
pytest test/test_server_security_hardening.py -v -s
```

### Run with pdb debugger
```bash
pytest test/test_server_security_hardening.py --pdb
```

### Show print statements
```bash
pytest test/test_server_security_hardening.py -v -s --capture=no
```

## Coverage Report

### Generate coverage HTML report
```bash
pytest test/test_server_*.py --cov=src/server --cov-report=html
open htmlcov/index.html
```

### Show coverage in terminal
```bash
pytest test/test_server_*.py --cov=src/server --cov-report=term-missing
```

Expected output:
```
Name                 Stmts   Miss  Cover   Missing
--------------------------------------------------
src/server.py          850     42    95%   123-125, 234-236, ...
--------------------------------------------------
TOTAL                  850     42    95%
```

## Next Steps After Tests Pass

1. ✅ Commit test files
```bash
git add server/test/test_server_*.py
git add server/test/README_SECURITY_TESTS.md
git commit -m "Add comprehensive security tests for hardened server.py"
```

2. ✅ Merge latest main branch
```bash
git fetch origin
git merge origin/main
```

3. ✅ Push your branch
```bash
git push origin irsad
```

4. ✅ Create Pull Request with test results

## Integration with CI/CD

Add to `.github/workflows/test.yml` or `.gitlab-ci.yml`:

```yaml
test-security:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v2
    - uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    - name: Install dependencies
      run: |
        cd server
        pip install pytest pytest-cov
        pip install -r requirements.txt
    - name: Run security tests
      run: |
        cd server
        pytest test/test_server_*.py --cov=src/server --cov-report=xml
    - name: Upload coverage
      uses: codecov/codecov-action@v2
```

## Questions?

- Review `README_SECURITY_TESTS.md` for detailed documentation
- Check `SECURITY_TESTS_SUMMARY.md` for overview
- Review actual test code for implementation details

---

**Quick Command Reference**:
```bash
# All tests
pytest test/test_server_*.py -v

# With coverage
pytest test/test_server_*.py --cov=src/server --cov-report=term

# Single file
pytest test/test_server_security_hardening.py -v

# Single test
pytest test/test_server_security_hardening.py::TestUploadDocumentSecurity::test_upload_rejects_non_pdf_files -v
```
