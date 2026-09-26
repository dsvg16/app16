# RMAP endpoints (Phase I). Kept in its own module, separate from server.py.
# Uses the rmap library for the handshake, then watermarks + stores a version.
from __future__ import annotations

import hashlib
import os
import re
import secrets
import threading
from pathlib import Path

from flask import jsonify, request
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash

import watermarking_utils as WMUtils

try:
    from rmap import RMAPServer, RMAPError
    from rmap.crypto import load_key
    from rmap.exceptions import ProtocolStateException
    from rmap_paired_relay import (
        PairedRelay, InvalidRelayMessage, TargetError, paired_targets,
    )
    _RMAP_IMPORTED = True
except Exception:  # library not installed yet
    RMAPServer = None

    class RMAPError(Exception):
        pass

    class ProtocolStateException(RMAPError):
        pass

    class InvalidRelayMessage(Exception):
        pass

    class TargetError(Exception):
        pass

    _RMAP_IMPORTED = False


# RMAP hands out the teacher's PDF with our STRONGEST method (defence-in-depth:
# coordinate-LSB + tiled-visible + honey-microspacing + decoy), so a leaked copy
# is hardest to scrub before Phase II.
WM_METHOD = "Method 5"
SYSTEM_USER_LOGIN = "rmap-system"
SYSTEM_USER_EMAIL = "rmap-system@tatou.local"
# cap versions per identity so nobody can fill the disk
MAX_VERSIONS_PER_IDENTITY = 200
MAX_PENDING_HANDSHAKES = 5000


def _db_url() -> URL:
    # URL.create escapes the password, so @ / # ? in it don't break the url
    return URL.create(
        "mysql+pymysql",
        username=os.environ.get("DB_USER", "tatou"),
        password=os.environ.get("DB_PASSWORD", ""),
        host=os.environ.get("DB_HOST", "db"),
        port=int(os.environ.get("DB_PORT", "3306")),
        database=os.environ.get("DB_NAME", "tatou"),
        query={"charset": "utf8mb4"},
    )


def _safe_link(link: str) -> str:
    # safe filename from the link (link is 32 hex normally)
    if re.fullmatch(r"[0-9a-fA-F]{16,64}", link or ""):
        return link.lower()
    return hashlib.sha256((link or "").encode("utf-8")).hexdigest()


def register_rmap(app) -> None:
    # add the RMAP routes. if keys/library are missing the routes just return 503.
    storage_dir = Path(os.environ.get("STORAGE_DIR", "/app/storage")).resolve()
    source_pdf = Path(os.environ.get("RMAP_SOURCE_PDF", "/app/source/Group_16.pdf"))
    wm_key = os.environ.get("RMAP_WM_KEY", "")
    engine = create_engine(_db_url(), pool_pre_ping=True, future=True)
    handshake_lock = threading.Lock()
    version_lock = threading.Lock()

    def _source_ready() -> bool:
        # must be a real, watermarkable pdf. a 0-page pdf would pass a header
        # check but produce an unwatermarked copy, so check applicability.
        try:
            return bool(source_pdf.is_file()) and WMUtils.is_watermarking_applicable(
                method=WM_METHOD, pdf=str(source_pdf)
            )
        except Exception:
            return False

    rmap_server = None
    if _RMAP_IMPORTED:
        pub = os.environ.get("RMAP_SERVER_PUB", "")
        priv = os.environ.get("RMAP_SERVER_PRIV", "")
        clients = os.environ.get("RMAP_CLIENT_KEYS_DIR", "")
        if (pub and priv and clients and Path(pub).exists()
                and Path(priv).exists() and Path(clients).is_dir()):
            try:
                rmap_server = RMAPServer(
                    server_public_key_path=pub,
                    server_private_key_path=priv,
                    passphrase=os.environ.get("RMAP_KEY_PASSPHRASE") or None,
                    verbose=False,
                )
                rmap_server.loadIdentities(clients)
                app.logger.info("RMAP enabled")
            except Exception as e:  # bad key material shouldn't crash the app
                app.logger.warning("RMAP disabled: init failed: %s", e)
                rmap_server = None
        else:
            app.logger.warning("RMAP disabled: key material not configured")
    else:
        app.logger.warning("RMAP disabled: rmap library not installed")

    paired_relay = None
    if rmap_server is not None and os.environ.get("RMAP_PAIRED_RELAY") == "1":
        try:
            targets = paired_targets(
                include_group32=os.environ.get("RMAP_PAIR_30_32", "1") == "1"
            )
            target_keys = {}
            for group in sorted(set(targets.values())):
                key_path = Path(clients) / f"{group}.asc"
                if key_path.is_file():
                    target_keys[group] = load_key(key_path)
                else:
                    app.logger.warning("paired relay missing public key for %s", group)
            targets = {
                visitor: target for visitor, target in targets.items()
                if target in target_keys
            }
            if not targets:
                raise ValueError("no paired targets have public keys")
            paired_relay = PairedRelay(
                own_private_key=rmap_server.serverPrivateKey,
                passphrase=os.environ.get("RMAP_KEY_PASSPHRASE") or None,
                target_public_keys=target_keys,
                allowed_identities=rmap_server.identities,
                targets=targets,
            )
            app.logger.info("RMAP paired-group relay enabled")
        except (OSError, ValueError, RMAPError) as exc:
            app.logger.warning("RMAP paired-group relay disabled: %s", exc)

    def _store_paired_capture(target_group: str, link: str, data: bytes) -> None:
        if not re.fullmatch(r"Group_\d{2}", target_group):
            raise ValueError("invalid target group")
        capture_dir = storage_dir / "rmap_paired_captures" / target_group
        capture_dir.mkdir(parents=True, exist_ok=True)
        destination = capture_dir / f"{link}.pdf"
        temporary = capture_dir / f".{link}.{secrets.token_hex(6)}.tmp"
        try:
            temporary.write_bytes(data)
            temporary.chmod(0o600)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)

    # helpers
    def _ensure_source_document(conn) -> int:
        path_str = str(source_pdf)
        existing = conn.execute(
            text("SELECT id FROM Documents WHERE path = :p"), {"p": path_str}
        ).scalar()
        if existing:
            return int(existing)
        data = source_pdf.read_bytes()
        conn.execute(
            text("""INSERT INTO Users (email, hpassword, login)
                    VALUES (:email, :hp, :login)
                    ON DUPLICATE KEY UPDATE email = email"""),
            # random password, this user never logs in
            {"email": SYSTEM_USER_EMAIL, "login": SYSTEM_USER_LOGIN,
             "hp": generate_password_hash(secrets.token_urlsafe(32))},
        )
        owner = conn.execute(
            text("SELECT id FROM Users WHERE email = :e"), {"e": SYSTEM_USER_EMAIL}
        ).scalar()
        conn.execute(
            text("""INSERT INTO Documents (name, path, ownerid, sha256, size)
                    VALUES (:name, :path, :owner, :sha, :size)
                    ON DUPLICATE KEY UPDATE name = name"""),
            {"name": source_pdf.name, "path": path_str, "owner": owner,
             "sha": hashlib.sha256(data).digest(), "size": len(data)},
        )
        return int(conn.execute(
            text("SELECT id FROM Documents WHERE path = :p"), {"p": path_str}
        ).scalar())

    def _ensure_version(link: str, identity: str) -> bool:
        # make + store the watermarked pdf for this handshake.
        # returns False if the identity is over the quota.
        with engine.connect() as conn:
            if conn.execute(text("SELECT id FROM Versions WHERE link = :l"),
                            {"l": link}).first():
                return True  # same link already done (replay)
            issued = conn.execute(
                text("SELECT COUNT(*) FROM Versions WHERE intended_for = :i"),
                {"i": identity},
            ).scalar() or 0
        if issued >= MAX_VERSIONS_PER_IDENTITY:
            app.logger.warning("RMAP version quota exceeded for %s", identity)
            return False

        # mark carries the group name + the link
        wm_bytes = WMUtils.apply_watermark(
            pdf=str(source_pdf), secret=f"{identity}:{link}", key=wm_key,
            method=WM_METHOD, position=None,
        )
        out_dir = storage_dir / "rmap"
        out_dir.mkdir(parents=True, exist_ok=True)
        wm_file = out_dir / f"{_safe_link(link)}.pdf"
        tmp_file = out_dir / f".{_safe_link(link)}.{secrets.token_hex(6)}.tmp"
        tmp_file.write_bytes(wm_bytes)
        tmp_file.replace(wm_file)  # write to temp then rename

        try:
            with engine.begin() as conn:
                documentid = _ensure_source_document(conn)
                conn.execute(
                    text("""INSERT INTO Versions
                            (documentid, link, intended_for, secret, method, position, path)
                            VALUES (:documentid, :link, :intended_for, :secret,
                                    :method, :position, :path)"""),
                    {"documentid": documentid, "link": link, "intended_for": identity,
                     "secret": f"{identity}:{link}", "method": WM_METHOD,
                     "position": "", "path": str(wm_file)},
                )
        except IntegrityError:
            # a duplicate link means another request won the race, keep it
            with engine.connect() as conn:
                duplicate = conn.execute(
                    text("SELECT id FROM Versions WHERE link = :l"),
                    {"l": link},
                ).first()
            if duplicate:
                return True
            wm_file.unlink(missing_ok=True)
            raise
        except Exception:
            wm_file.unlink(missing_ok=True)  # don't leave the file if db fails
            raise
        return True

    # routes
    @app.post("/api/rmap-initiate")
    def rmap_initiate():
        if rmap_server is None:
            return jsonify({"error": "RMAP not configured"}), 503
        # bound the library's in-memory pending-nonce table against msg1 spam
        pending = getattr(rmap_server, "_nonce_server_index", None)
        if pending is not None and len(pending) >= MAX_PENDING_HANDSHAKES:
            return jsonify({"error": "too many pending handshakes"}), 429
        payload = request.get_json(force=True, silent=True) or {}
        if paired_relay is not None:
            try:
                relayed_response = paired_relay.initiate(payload)
                if relayed_response is not None:
                    return jsonify(relayed_response)
            except TargetError:
                app.logger.warning("paired initiate failed; using the local RMAP server")
            except (RMAPError, InvalidRelayMessage, KeyError, ValueError, TypeError):
                return jsonify({"error": "rmap protocol error"}), 400
        try:
            with handshake_lock:
                _identity, resp1 = rmap_server.receiveMsg1(payload)
        except (RMAPError, KeyError, ValueError, TypeError):
            # bad or wrong-shaped message -> same generic error
            return jsonify({"error": "rmap protocol error"}), 400
        return jsonify(resp1)

    @app.post("/api/rmap-get-link")
    def rmap_get_link():
        if rmap_server is None:
            return jsonify({"error": "RMAP not configured"}), 503
        if not wm_key:
            return jsonify({"error": "RMAP watermark key not configured"}), 503
        if not _source_ready():
            return jsonify({"error": "RMAP source document unavailable"}), 503
        payload = request.get_json(force=True, silent=True) or {}
        relay_result = None
        try:
            with handshake_lock:
                identity, link, resp2 = rmap_server.receiveMsg2(payload)
        except ProtocolStateException:
            if paired_relay is None:
                return jsonify({"error": "rmap protocol error"}), 400
            try:
                relay_result = paired_relay.finish(payload)
            except TargetError:
                app.logger.warning("paired target could not finish a relayed handshake")
                return jsonify({"error": "service unavailable"}), 503
            except (RMAPError, InvalidRelayMessage, KeyError, ValueError, TypeError):
                return jsonify({"error": "rmap protocol error"}), 400
            if relay_result is None:
                return jsonify({"error": "rmap protocol error"}), 400
            identity, link = relay_result.identity, relay_result.link
            resp2 = rmap_server.encrypt_for_identity({"result": link}, identity)
        except (RMAPError, KeyError, ValueError, TypeError):
            return jsonify({"error": "rmap protocol error"}), 400
        # make + save the version before returning the link (spec 5.5).
        # the lock keeps the quota count + insert atomic across threads.
        try:
            with version_lock:
                created = _ensure_version(link, identity)
        except Exception:
            app.logger.exception("rmap-get-link: could not create version")
            return jsonify({"error": "service unavailable"}), 503
        if not created:
            return jsonify({"error": "too many versions for this identity"}), 429
        if relay_result is not None:
            if relay_result.target_pdf is not None:
                try:
                    _store_paired_capture(
                        relay_result.target_group, link, relay_result.target_pdf
                    )
                    app.logger.info(
                        "paired PDF captured from %s for %s", relay_result.target_group,
                        identity,
                    )
                except OSError:
                    app.logger.exception("could not store paired PDF capture")
            else:
                app.logger.warning("paired target issued a link, but its PDF was unavailable")
        return jsonify(resp2)

    # get-version/<link> is served by server.py; don't register it twice here.

    if _RMAP_IMPORTED:
        @app.errorhandler(RMAPError)
        def _rmap_error(_e):  # same error for bad input or unknown group
            return jsonify({"error": "rmap protocol error"}), 400
