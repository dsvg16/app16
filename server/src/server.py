import os
import io
import hashlib
import secrets
import tempfile
import shutil
import datetime as dt
from pathlib import Path
from functools import wraps
import logging, time, uuid, json, threading

from flask import Flask, jsonify, request, g, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

import pickle as _std_pickle
try:
    import dill as _pickle  # allows loading classes not importable by module path
except Exception:  # dill is optional
    _pickle = _std_pickle


import watermarking_utils as WMUtils
from watermarking_method import WatermarkingMethod
from rmap_endpoints import register_rmap
#from watermarking_utils import METHODS, apply_watermark, read_watermark, explore_pdf, is_watermarking_applicable, get_method


# ------- Structured JSON logging ---------- #
class JsonFormatter(logging.Formatter):
    def format(self, record):
        base = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        # allow extra dict
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            base.update(record.extra)
        return json.dumps(base, ensure_ascii=False)

def _json_log(logger, level, msg, **extra):
    logger.log(level, msg, extra={"extra": extra})
# ------- End structured logging helpers ------- ""


def create_app():
    app = Flask(__name__)

    SECURITY_PATHS = {
        "/api/login", "/api/upload-document", "/api/delete-document",
        "/api/create-watermark", "/api/read-watermark",
        "/api/rmap-initiate", "/api/rmap-get-link"
    }

    @app.before_request
    def _start_timer():
        g._t0 = time.time()
        g.request_id = str(uuid.uuid4())

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault(
            "Referrer-Policy",
            "strict-origin-when-cross-origin",
        )
        _log_request(response)
        return response
    def _log_request(resp):
        try:
            # never log healthz
            if request.path == "/healthz":
                return resp

            # only log errors OR sensitive endpoints
            if resp.status_code < 400 and request.path not in SECURITY_PATHS:
                return resp

            start = getattr(g, "_t0", None)
            latency = int((time.time() - start) * 1000) if start else 0
            u = getattr(g, "user", None)
            user_id = int(u.get("id")) if isinstance(u, dict) and u.get("id") is not None else -1

            _json_log(
                app.logger, logging.INFO, "http_access",
                ts=int(time.time()),
                request_id=getattr(g, "request_id", None),
                ip=request.headers.get("X-Forwarded-For", request.remote_addr),
                method=request.method,
                path=request.path,
                status=int(resp.status_code),
                latency_ms=latency,
                user=user_id,
            )
        except Exception:
            pass
        return resp
    # ---- end JSON logger wiring ---- #


    # --- Config ---
    # a random key per boot invalidates old tokens, but is never a known value
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)
    app.config["MAX_CONTENT_LENGTH"] = 3 * 1024 * 1024

    STORAGE_ROOT = app.config["STORAGE_DIR"].resolve()

    # ------- Install JSON logger & request logging ---- #
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())

    #File handler (shared volume for SIEM)
    _log_file = Path(app.config["STORAGE_DIR"]) / "server.log"
    _file_handler = logging.FileHandler(_log_file, encoding="utf-8")
    _file_handler.setFormatter(JsonFormatter())

    # app logger: INFO (security events); root + noisy libs: WARNING
    app.logger.handlers = [handler, _file_handler]
    app.logger.setLevel(logging.INFO)
    app.logger.propagate = False

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.WARNING)

    for _noisy in ("werkzeug", "urllib3", "requests", "sqlalchemy.engine", "sqlalchemy.pool"):
        logging.getLogger(_noisy).setLevel(logging.WARNING)

    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.pool").setLevel(logging.WARNING)


    # --- DB engine only (no Table metadata) ---
    def db_url() -> str:
        return (
            f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
            f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}?charset=utf8mb4"
        )

    def get_engine():
        eng = app.config.get("_ENGINE")
        if eng is None:
            eng = create_engine(db_url(), pool_pre_ping=True, future=True)
            app.config["_ENGINE"] = eng
        return eng

    # --- Login throttle (slows password guessing) ---
    # kept in memory on purpose: we run a single gunicorn worker, so a dict is
    # enough and it adds no new dependency.
    LOGIN_FAIL_LIMIT = int(os.environ.get("LOGIN_FAIL_LIMIT", "5"))    # per ip+account
    LOGIN_IP_LIMIT = int(os.environ.get("LOGIN_IP_LIMIT", "20"))       # per ip (spraying)
    LOGIN_WINDOW = int(os.environ.get("LOGIN_WINDOW_SECONDS", "300"))
    LOGIN_LOCKOUT = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "300"))

    _login_fails: dict = {}          # key -> (fails, window_start, locked_until)
    _login_fails_lock = threading.Lock()

    def _client_ip() -> str:
        # deliberately NOT X-Forwarded-For: the caller controls that header and
        # could send a new one each try to walk around the throttle.
        return request.remote_addr or "unknown"

    def _login_keys(email: str):
        ip = _client_ip()
        return [(f"ip:{ip}", LOGIN_IP_LIMIT), (f"acct:{ip}|{email}", LOGIN_FAIL_LIMIT)]

    def _login_locked_for(keys) -> int:
        now = time.time()
        with _login_fails_lock:
            waits = [int(_login_fails[k][2] - now) for k, _ in keys
                     if k in _login_fails and _login_fails[k][2] > now]
        return max(waits) if waits else 0

    def _login_note_fail(keys) -> None:
        now = time.time()
        with _login_fails_lock:
            if len(_login_fails) > 10000:   # keep memory bounded
                for k, v in list(_login_fails.items()):
                    if v[2] < now and now - v[1] > LOGIN_WINDOW:
                        _login_fails.pop(k, None)
            for key, limit in keys:
                fails, start, until = _login_fails.get(key, (0, now, 0.0))
                if now - start > LOGIN_WINDOW:
                    fails, start = 0, now
                fails += 1
                if fails >= limit:
                    until, fails, start = now + LOGIN_LOCKOUT, 0, now
                _login_fails[key] = (fails, start, until)

    def _login_note_success(keys) -> None:
        # clear the account counter only; the per-ip one still decays on its own
        with _login_fails_lock:
            for key, _ in keys:
                if key.startswith("acct:"):
                    _login_fails.pop(key, None)

    # --- Helpers ---
    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except SignatureExpired:
                return _auth_error("Token expired")
            except BadSignature:
                return _auth_error("Invalid token")
            g.user = {"id": int(data["uid"]), "login": data["login"], "email": data.get("email")}
            return f(*args, **kwargs)
        return wrapper

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _safe_storage_path(raw_path: str | Path) -> Path:
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = STORAGE_ROOT / candidate

        # Do not allow symlinks anywhere in the path.
        current = candidate
        while current != STORAGE_ROOT and current != current.parent:
            if current.is_symlink():
                raise ValueError("symlink paths are not allowed")
            current = current.parent

        resolved = candidate.resolve(strict=False)

        try:
            resolved.relative_to(STORAGE_ROOT)
        except ValueError as exc:
            raise ValueError("path escapes storage root") from exc

        if resolved != STORAGE_ROOT and resolved.is_symlink():
            raise ValueError("symlink paths are not allowed")

        return resolved
    # # --- Routes ---

    @app.route("/<path:filename>")
    def static_files(filename):
        return app.send_static_file(filename)

    @app.route("/")
    def home():
        return app.send_static_file("index.html")

    @app.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

    # POST /api/create-user {email, login, password}
    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        RESERVED_LOGINS = {"plugins", "watermarks", "sources", "system", "admin", "root"}
        if login.lower() in RESERVED_LOGINS:
            return jsonify({"error": "Restricted Username"}), 409
        password = payload.get("password") or ""
        if not email or not login or not password:
            return jsonify({"error": "email, login, and password are required"}), 400

        hpw = generate_password_hash(password)

        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
        except IntegrityError:
            return jsonify({"error": "email or login already exists"}), 409
        except Exception as e:
            return jsonify({"error": "Failed to process DB request"}), 503

        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {login, password}
    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400

        # refuse early if this source has been guessing passwords
        keys = _login_keys(email)
        wait = _login_locked_for(keys)
        if wait:
            _json_log(app.logger, logging.WARNING, "login_throttled",
                      ts=int(time.time()), ip=_client_ip(), email=email, retry_after=wait)
            resp = jsonify({"error": "too many failed login attempts, try again later"})
            resp.headers["Retry-After"] = str(wait)
            return resp, 429

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                    {"email": email},
                ).first()
        except Exception as e:
            return jsonify({"error": "Failed to process DB request"}), 503

        if not row or not check_password_hash(row.hpassword, password):
            _login_note_fail(keys)
            _json_log(app.logger, logging.WARNING, "login_fail",
                        ts=int(time.time()), ip=request.remote_addr, email=email)
            return jsonify({"error": "invalid credentials"}), 401

        _login_note_success(keys)
        token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        _json_log(app.logger, logging.INFO, "login_ok",
                ts=int(time.time()), ip=request.remote_addr, user=int(row.id), login=row.login)
        return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200

    # POST /api/upload-document  (multipart/form-data)
    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        if "file" not in request.files:
            return jsonify({"error": "file is required (multipart/form-data)"}), 400
        file = request.files["file"]
        if not file or file.filename == "":
            return jsonify({"error": "empty filename"}), 400
        #Check clean filename
        clean_filename = secure_filename(file.filename)
        if not clean_filename:
            return jsonify({"error": "invalid filename"}), 400

        content_length = request.content_length
        if content_length is not None and content_length > app.config["MAX_CONTENT_LENGTH"]:
            _json_log(
                    app.logger,
                    logging.WARNING,
                    "upload_reject",
                    ts=int(time.time()),
                    ip=request.remote_addr,
                    reason="request too large",
                    size=content_length,
                    user=int(g.user["id"]),
            )
            return jsonify({"error": "file too large"}), 413
        fname = file.filename

        #user_dir = app.config["STORAGE_DIR"] / "files" / g.user["login"]
        #Sanitize user login directory to prevent path traversal
        safe_login = secure_filename(str(g.user["id"]))
        user_dir = app.config["STORAGE_DIR"] / "files" / safe_login
        user_dir.mkdir(parents=True, exist_ok=True)

        ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        #Secure filename provided by user from form
        user_provided_name = request.form.get("name")
        if user_provided_name:
            final_name = secure_filename(user_provided_name)
            if not final_name:
                final_name = clean_filename
        else:
            final_name = clean_filename
        stored_name = f"{ts}__{clean_filename}"
        #stored_path = user_dir / stored_name
        stored_path = (user_dir / stored_name).resolve()

         # Verify the path cannot escape storage directory
        try:
            stored_path.relative_to(app.config["STORAGE_DIR"].resolve())
        except ValueError:
            return jsonify({"error": "invalid storage path"}), 400
        # Validate PDF (verify it's actually a PDF)
        header = file.read(4)
        file.seek(0)
        if header != b"%PDF":
            _json_log(app.logger, logging.WARNING, "upload_reject",
                    ts=int(time.time()), ip=request.remote_addr,
                    reason="not a PDF", filename=fname, user=g.user["id"])
            return jsonify({"error": "uploaded file is not a valid PDF"}), 400

        file.save(stored_path)
        #Set restrictive file permissions
        stored_path.chmod(0o600)
        sha_hex = _sha256_file(stored_path)
        size = stored_path.stat().st_size
        MAX_PARSE_SIZE = 2 * 1024 * 1024
        if size > MAX_PARSE_SIZE:
            stored_path.unlink(missing_ok=True)
            _json_log(app.logger, logging.WARNING, "upload_reject",
                    ts=int(time.time()), ip=request.remote_addr,
                reason="file too large", size=size, user=g.user["id"])
            return jsonify({"error": "file too large"}), 413

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                    """),
                    {
                        "name": final_name,
                        "path": str(stored_path),
                        "ownerid": int(g.user["id"]),
                        "sha256hex": sha_hex,
                        "size": int(size),
                    },
                )
                did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                row = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": did},
                ).one()
        except Exception as e:
            #Logging
            app.logger.exception("Database error during document upload")
            #Clean uploaded file if DB execution failed
            stored_path.unlink(missing_ok=True)
            return jsonify({"error": "Failed to process DB request"}), 503

        _json_log(app.logger, logging.INFO, "upload_ok",
                ts=int(time.time()), ip=request.remote_addr, user=g.user["id"],
                filename=fname, size=size, sha256=row.sha256_hex)

        return jsonify({
            "id": int(row.id),
            "name": row.name,
            "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }), 201

    # GET /api/list-documents
    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                    """),
                    {"uid": int(g.user["id"])},
                ).all()
        except Exception as e:
            return jsonify({"error": "Failed to process DB request"}), 503

        docs = [{
            "id": int(r.id),
            "name": r.name,
            "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
            "sha256": r.sha256_hex,
            "size": int(r.size),
        } for r in rows]
        return jsonify({"documents": docs}), 200



    # GET /api/list-versions
    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.id = :uid AND d.id = :did
                    """),
                    {"uid": str(g.user["id"]), "did": document_id},
                ).all()
        except Exception as e:
            return jsonify({"error": "Failed to process DB request"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "secret": r.secret,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200


    # GET /api/list-all-versions
    @app.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.id = :uid
                    """),
                    {"uid": str(g.user["id"])},
                ).all()
        except Exception as e:
            return jsonify({"error": "Failed to process DB request"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200

    # GET /api/get-document or /api/get-document/<id>  → returns the PDF (inline)
    @app.get("/api/get-document")
    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int | None = None):

        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            return jsonify({"error": "Failed to process DB request"}), 503

        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            # Path looks suspicious or outside storage
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        last_mod = file_path.stat().st_mtime
        download_name = row.name if str(row.name).lower().endswith(".pdf") else f"{secure_filename(row.name)}.pdf"

        fobj = None
        tmp_to_unlink = None
        try:
            # Refuse to follow symlinks at open time
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(str(file_path), flags)
            fobj = os.fdopen(fd, "rb")

            resp = send_file(
                fobj,
                mimetype="application/pdf",
                as_attachment=False,
                download_name=download_name,
                conditional=True,
                max_age=0,
                last_modified=last_mod,
            )
        except Exception:
            # Fallback: safe copy in case O_NOFOLLOW is not supported
            try:
                tmpf = tempfile.NamedTemporaryFile(delete=False, dir=str(app.config["STORAGE_DIR"].resolve()))
                tmp_to_unlink = Path(tmpf.name)
                tmpf.close()
                shutil.copy2(file_path, tmp_to_unlink)
                fobj = tmp_to_unlink.open("rb")
                resp = send_file(
                    fobj,
                    mimetype="application/pdf",
                    as_attachment=False,
                    download_name=download_name,
                    conditional=True,
                    max_age=0,
                    last_modified=last_mod,
                )
            except Exception:
                app.logger.exception("Failed to open document id=%s", document_id)
                if fobj:
                    try: fobj.close()
                    except Exception: pass
                if tmp_to_unlink and tmp_to_unlink.exists():
                    try: tmp_to_unlink.unlink()
                    except Exception: pass
                return jsonify({"error": "file unavailable"}), 500

        # Ensure file descriptors and temp files are closed and cleaned up after response ends
        def _cleanup_doc():
            try:
                if fobj:
                    fobj.close()
            except Exception:
                pass
            if tmp_to_unlink and tmp_to_unlink.exists():
                try:
                    tmp_to_unlink.unlink(missing_ok=True)
                except Exception:
                    pass

        resp.call_on_close(_cleanup_doc)

        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())

        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp

    # GET /api/get-version/<link>  → returns the watermarked PDF (inline)
    @app.get("/api/get-version/<link>")
    def get_version(link: str):

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT *
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                    """),
                    {"link": link},
                ).first()
        except Exception as e:
            return jsonify({"error": "Failed to process DB request"}), 503

        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            # Path looks suspicious or outside storage
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        last_mod = file_path.stat().st_mtime

        fobj = None
        tmp_to_unlink = None
        try:
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(str(file_path), flags)
            fobj = os.fdopen(fd, "rb")
            resp = send_file(
                fobj,
                mimetype="application/pdf",
                as_attachment=False,
                download_name=row.link if str(row.link).lower().endswith(".pdf") else f"{secure_filename(row.link)}.pdf",
                conditional=True,
                max_age=0,
                last_modified=last_mod,
            )
        except Exception:
            try:
                tmpf = tempfile.NamedTemporaryFile(delete=False, dir=str(app.config["STORAGE_DIR"].resolve()))
                tmp_to_unlink = Path(tmpf.name)
                tmpf.close()
                shutil.copy2(file_path, tmp_to_unlink)
                fobj = tmp_to_unlink.open("rb")
                resp = send_file(
                    fobj,
                    mimetype="application/pdf",
                    as_attachment=False,
                    download_name=row.link if str(row.link).lower().endswith(".pdf") else f"{secure_filename(row.link)}.pdf",
                    conditional=True,
                    max_age=0,
                    last_modified=last_mod,
                )
            except Exception:
                if fobj:
                    try:
                        fobj.close()
                    except Exception:
                        pass
                if tmp_to_unlink and tmp_to_unlink.exists():
                    try:
                        tmp_to_unlink.unlink()
                    except Exception:
                        pass
                return jsonify({"error": "file unavailable"}), 500

        def _cleanup_ver():
            try:
                if fobj:
                    fobj.close()
            except Exception:
                pass
            if tmp_to_unlink:
                try:
                    tmp_to_unlink.unlink(missing_ok=True)
                except Exception:
                    pass
        resp.call_on_close(_cleanup_ver)

        resp.headers["Cache-Control"] = "private, max-age=0"
        return resp

    # Helper: resolve path safely under STORAGE_DIR (handles absolute/relative)
    def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        # Python 3.12 has is_relative_to on Path
        if hasattr(fp, "is_relative_to"):
            if not fp.is_relative_to(storage_root):
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        else:
            try:
                fp.relative_to(storage_root)
            except ValueError:
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

    # DELETE /api/delete-document  (and variants)
    @app.route("/api/delete-document", methods=["DELETE", "POST"])  # POST supported for convenience
    @app.route("/api/delete-document/<document_id>", methods=["DELETE"])
    @require_auth
    def delete_document(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or ((request.get_json(silent=True) or {}).get("id") if request.is_json else None)
            )
        try:
            doc_id = int(document_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        # Fetch the document (enforce ownership)
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                                text("SELECT id, path FROM Documents WHERE id = :id AND ownerid = :uid LIMIT 1"),
                                {"id": doc_id, "uid": int(g.user["id"])}
                ).first()
        except Exception as e:
            return jsonify({"error": "Failed to process DB request"}), 503

        if not row:
            # Don’t reveal others’ docs—just say not found
            return jsonify({"error": "document not found"}), 404

        # Resolve and delete file (best effort)
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_deleted = False
        file_missing = False
        delete_error = None
        try:
            fp = _safe_resolve_under_storage(row.path, storage_root)
            if fp.exists():
                try:
                    fp.unlink()
                    file_deleted = True
                except Exception as e:
                    delete_error = f"failed to delete file: {e}"
                    app.logger.warning("Failed to delete file %s for doc id=%s: %s", fp, row.id, e)
            else:
                file_missing = True
        except RuntimeError as e:
            # Path escapes storage root; refuse to touch the file
            delete_error = str(e)
            app.logger.error("Path safety check failed for doc id=%s: %s", row.id, e)

        # Delete DB row (will cascade to Version if FK has ON DELETE CASCADE)
        try:
            with get_engine().begin() as conn:
                # If your schema does NOT have ON DELETE CASCADE on Version.documentid,
                # uncomment the next line first:
                # conn.execute(text("DELETE FROM Version WHERE documentid = :id"), {"id": doc_id})
                conn.execute(
                               text("DELETE FROM Documents WHERE id = :id AND ownerid = :uid"),
                               {"id": doc_id, "uid": int(g.user["id"])}
                )
        except Exception as e:
            return jsonify({"error": "Failed to process DB request delete"}), 503

        _json_log(app.logger, logging.INFO, "doc_delete",
                ts=int(time.time()), user=int(g.user["id"]), doc_id=doc_id,
                file_deleted=file_deleted)
        return jsonify({
            "deleted": True,
            "id": doc_id,
            "file_deleted": file_deleted,
            "file_missing": file_missing,
            "note": delete_error,   # null/omitted if everything was fine
        }), 200


    # POST /api/create-watermark or /api/create-watermark/<id>  → create watermarked pdf and returns metadata
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on GET
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or ((request.get_json(silent=True) or {}).get("id") if request.is_json else None)
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        payload = request.get_json(silent=True) or {}
        # allow a couple of aliases for convenience
        method = payload.get("method")
        intended_for = payload.get("intended_for")
        position = payload.get("position") or None
        secret = payload.get("secret")
        key = payload.get("key")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not intended_for or not isinstance(secret, str) or not isinstance(key, str):
            return jsonify({"error": "method, intended_for, secret, and key are required"}), 400

        # lookup the document; enforce ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": doc_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            return jsonify({"error": "Failed to process DB request"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # check watermark applicability
        try:
            applicable = WMUtils.is_watermarking_applicable(
                method=method,
                pdf=str(file_path),
                position=position
            )
            if applicable is False:
                _json_log(app.logger, logging.WARNING, "watermark_applicability_fail",
                    ts=int(time.time()), user=int(g.user["id"]), method=method,
                    reason="not applicable", doc_id=int(doc_id))
                return jsonify({"error": "watermarking method not applicable"}), 400
        except Exception as e:
            _json_log(app.logger, logging.WARNING, "watermark_applicability_fail",
                ts=int(time.time()), doc_id=int(doc_id), user=int(g.user["id"]), method=method,
                reason="check failed", error=str(e))
            return jsonify({"error": "watermark applicability check failed"}), 400

        # apply watermark → bytes
        try:
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=position
            )
            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                _json_log(app.logger, logging.WARNING, "watermark_applicability_fail",
                    ts=int(time.time()), doc_id=int(doc_id), user=int(g.user["id"]), method=method,
                    reason="no output bytes")
                return jsonify({"error": "watermarking produced no output"}), 500
        except Exception as e:
            _json_log(app.logger, logging.WARNING, "watermark_applicability_fail",
                ts=int(time.time()), doc_id=int(doc_id), user=int(g.user["id"]), method=method,
                reason="apply failed", error=str(e))
            return jsonify({"error": f"watermarking failed: {e}"}), 500

        # build destination file name: "<original_name>__<intended_to>.pdf"
        base_name = Path(row.name or file_path.name).stem
        intended_slug = secure_filename(intended_for)
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)

        #candidate = f"{base_name}__{intended_slug}.pdf"
        candidate = f"{base_name}__{intended_slug}__{uuid.uuid4().hex}.pdf"
        dest_path = dest_dir / candidate

        # write bytes
        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception as e:
            return jsonify({"error": "Failed to write watermarked file"}), 500

        # link token = sha1(watermarked_file_name)
        #link_token = hashlib.sha1(candidate.encode("utf-8")).hexdigest()
        #change it to random instead of sha1
        link_token = secrets.token_urlsafe(32)

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": doc_id,
                        "link": link_token,
                        "intended_for": intended_for,
                        "secret": secret,
                        "method": method,
                        "position": position or "",
                        "path": dest_path
                    },
                )
                vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
        except Exception as e:
            # best-effort cleanup if DB insert fails
            try:
                dest_path.unlink(missing_ok=True)
            except Exception:
                pass
            return jsonify({"error": "Failed to process DB insert request"}), 503


        _json_log(app.logger, logging.INFO, "wm_create",
            ts=int(time.time()), doc_id=int(doc_id), user=int(g.user["id"]), method=method,
            reason="success", intended_for=intended_for, size=len(wm_bytes))
        return jsonify({
            "id": vid,
            "documentid": doc_id,
            "link": link_token,
            "intended_for": intended_for,
            "method": method,
            "position": position,
            "filename": candidate,
            "size": len(wm_bytes),
        }), 201


    # @app.post("/api/load-plugin")
    # @require_auth
    # def load_plugin():
    #     """
    #     Load a serialized Python class implementing WatermarkingMethod from
    #     STORAGE_DIR/files/plugins/<filename>.{pkl|dill} and register it in wm_mod.METHODS.
    #     Body: { "filename": "MyMethod.pkl", "overwrite": false }
    #     """
    #     payload = request.get_json(silent=True) or {}
    #     filename = (payload.get("filename") or "").strip()
    #     overwrite = bool(payload.get("overwrite", False))

    #     if not filename:
    #         return jsonify({"error": "filename is required"}), 400

    #     # Check only trust plugin (whitelisting)
    #     ALLOWED_PLUGINS = {
    #         "eof_method": "add_after_eof.AddAfterEOF",
    #     }
    #     if filename not in ALLOWED_PLUGINS:
    #         return jsonify({"error": "unauthorized or disallowed plugin"}), 403

    #     # Locate the plugin in /storage/files/plugins (relative to STORAGE_DIR)
    #     storage_root = Path(app.config["STORAGE_DIR"])
    #     plugins_dir = storage_root / "files" / "plugins"
    #     try:
    #         plugins_dir.mkdir(parents=True, exist_ok=True)
    #         plugin_path = plugins_dir / filename
    #     except Exception as e:
    #         return jsonify({"error": f"plugin path error: {e}"}), 500

    #     #There's no 'safe' defined
    #     if not plugin_path.exists():
    #         return jsonify({"error": "plugin file not found"}), 404

    #     # Unpickle the object (dill if available; else std pickle)
    #     try:
    #         with plugin_path.open("rb") as f:
    #             obj = _pickle.load(f)
    #     except Exception as e:
    #         return jsonify({"error": f"failed to deserialize plugin: {e}"}), 400

    #     # Accept: class object, or instance (we'll promote instance to its class)
    #     if isinstance(obj, type):
    #         cls = obj
    #     else:
    #         cls = obj.__class__

    #     # Determine method name for registry
    #     method_name = getattr(cls, "name", getattr(cls, "__name__", None))
    #     if not method_name or not isinstance(method_name, str):
    #         return jsonify({"error": "plugin class must define a readable name (class.__name__ or .name)"}), 400

    #     # Validate interface: either subclass of WatermarkingMethod or duck-typing
    #     has_api = all(hasattr(cls, attr) for attr in ("add_watermark", "read_secret"))
    #     if WatermarkingMethod is not None:
    #         is_ok = issubclass(cls, WatermarkingMethod) and has_api
    #     else:
    #         is_ok = has_api
    #     if not is_ok:
    #         return jsonify({"error": "plugin does not implement WatermarkingMethod API (add_watermark/read_secret)"}), 400

    #     # Register the class (not an instance) so you can instantiate as needed later
    #     WMUtils.METHODS[method_name] = cls()

    #     return jsonify({
    #         "loaded": True,
    #         "filename": filename,
    #         "registered_as": method_name,
    #         "class_qualname": f"{getattr(cls, '__module__', '?')}.{getattr(cls, '__qualname__', cls.__name__)}",
    #         "methods_count": len(WMUtils.METHODS)
    #     }), 201



    # GET /api/get-watermarking-methods -> {"methods":[{"name":..., "description":...}, ...], "count":N}
    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        methods = []

        for m in WMUtils.METHODS:
            methods.append({"name": m, "description": WMUtils.get_method(m).get_usage()})

        return jsonify({"methods": methods, "count": len(methods)}), 200

    # POST /api/read-watermark
    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or ((request.get_json(silent=True) or {}).get("id") if request.is_json else None)
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        payload = request.get_json(silent=True) or {}
        # allow a couple of aliases for convenience
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not isinstance(key, str):
            return jsonify({"error": "method, and key are required"}), 400

        # lookup the document; FIXME enforce ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                    """),
                    {"id": doc_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            return jsonify({"error": "Failed to process DB request"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        secret = None
        try:
            secret = WMUtils.read_watermark(
                method=method,
                pdf=str(file_path),
                key=key
            )
        except Exception as e:
            _json_log(app.logger, logging.WARNING, "wm_read_fail",
                ts=int(time.time()), doc_id=int(doc_id), method=method,
                error=str(e), user=int(g.user["id"]))
            return jsonify({"error": "Error when attempting to read watermark"}), 400

        _json_log(app.logger, logging.INFO, "wm_read_ok",
            ts=int(time.time()), doc_id=int(doc_id), method=method,
            user=int(g.user["id"]))
        return jsonify({
            "documentid": doc_id,
            "secret": secret,
            "method": method,
            "position": position
        }), 201

    @app.errorhandler(413)
    def request_entity_too_large(_error):
        return jsonify({"error": "file too large"}), 413

    register_rmap(app)
    return app


# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
