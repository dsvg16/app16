# RMAP endpoint tests using the real RMAPClient.
from __future__ import annotations

import os
from pathlib import Path

import pymupdf
import pytest

pytest.importorskip("rmap", reason="rmap library not installed")
from rmap import RMAPClient  # noqa: E402
from rmap.keygen import generate_keypair  # noqa: E402

import server as server_module  # noqa: E402

IDENTITY = "Group_TEST"
QUOTA_IDENTITY = "Group_QUOTA"
REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def keydir(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("rmapkeys")
    (d / "clients").mkdir()
    srv = generate_keypair("Tatou Server", "server@example.invalid")
    (d / "server_priv.asc").write_text(str(srv))
    (d / "server_pub.asc").write_text(str(srv.pubkey))
    cli = generate_keypair(IDENTITY, "client@example.invalid")
    (d / "client_priv.asc").write_text(str(cli))
    (d / "clients" / f"{IDENTITY}.asc").write_text(str(cli.pubkey))
    # second identity for the quota test (db is shared across the module)
    quota = generate_keypair(QUOTA_IDENTITY, "quota@example.invalid")
    (d / "quota_priv.asc").write_text(str(quota))
    (d / "clients" / f"{QUOTA_IDENTITY}.asc").write_text(str(quota.pubkey))
    return d


@pytest.fixture
def app(keydir, monkeypatch, tmp_path):
    monkeypatch.setenv("RMAP_SERVER_PUB", str(keydir / "server_pub.asc"))
    monkeypatch.setenv("RMAP_SERVER_PRIV", str(keydir / "server_priv.asc"))
    monkeypatch.setenv("RMAP_CLIENT_KEYS_DIR", str(keydir / "clients"))
    monkeypatch.setenv("RMAP_WM_KEY", "unit-test-wm-key")
    monkeypatch.setenv("STORAGE_DIR", str(tmp_path))
    source_pdf = REPO_ROOT / "Group_16.pdf"
    if not source_pdf.exists():
        source_pdf = tmp_path / "test-source.pdf"
        document = pymupdf.open()
        document.new_page()
        document.save(source_pdf)
        document.close()
    monkeypatch.setenv("RMAP_SOURCE_PDF", str(source_pdf))
    return server_module.create_app()


def _client(keydir: Path, identity: str = IDENTITY, priv: str = "client_priv.asc"):
    return RMAPClient(
        identity=identity,
        client_private_key_path=str(keydir / priv),
        server_public_key_path=str(keydir / "server_pub.asc"),
    )


def test_initiate_is_accepted_by_official_client(app, keydir):
    # the real client must be able to read our resp1
    c = _client(keydir)
    resp = app.test_client().post("/api/rmap-initiate", json=c.build_msg1())
    assert resp.status_code == 200, resp.get_data(as_text=True)
    c.process_resp1(resp.get_json())
    assert "payload" in c.build_msg2()


def test_malformed_payload_gives_generic_400(app):
    resp = app.test_client().post("/api/rmap-initiate", json={"payload": "not-pgp"})
    assert resp.status_code == 400
    assert resp.get_json() == {"error": "rmap protocol error"}


def test_unknown_identity_gives_same_generic_400(app, keydir, tmp_path):
    # unknown group should look the same as a bad message
    other = generate_keypair("Group_UNKNOWN", "x@example.invalid")
    priv = tmp_path / "unknown_priv.asc"
    priv.write_text(str(other))
    c = RMAPClient(
        identity="Group_UNKNOWN",
        client_private_key_path=str(priv),
        server_public_key_path=str(keydir / "server_pub.asc"),
    )
    resp = app.test_client().post("/api/rmap-initiate", json=c.build_msg1())
    assert resp.status_code == 400
    assert resp.get_json() == {"error": "rmap protocol error"}


def test_get_version_unknown_link_is_404_or_503(app):
    # 404 when the DB is reachable, 503 when it is not; never a 200/traceback.
    assert app.test_client().get("/api/get-version/" + "0" * 32).status_code in (404, 503)


@pytest.mark.skipif(
    not os.environ.get("TATOU_DB_TEST"),
    reason="needs a live MariaDB; covered by the docker compose deploy check",
)
def test_full_handshake_issues_a_working_link(app, keydir):
    from tiled_visible_watermark import TiledVisibleWatermark

    tc = app.test_client()
    c = _client(keydir)
    c.process_resp1(tc.post("/api/rmap-initiate", json=c.build_msg1()).get_json())
    r2 = tc.post("/api/rmap-get-link", json=c.build_msg2())
    assert r2.status_code == 200, r2.get_data(as_text=True)
    link = c.process_resp2(r2.get_json())

    dl = tc.get(f"/api/get-version/{link}")
    assert dl.status_code == 200
    assert dl.data.startswith(b"%PDF-")
    # the served copy must carry this identity + this handshake
    recovered = TiledVisibleWatermark().read_secret(dl.data, "unit-test-wm-key")
    assert recovered.startswith(f"{IDENTITY}:")


# error / security cases

def _make_app(keydir, monkeypatch, tmp_path, **overrides):
    env = {
        "RMAP_SERVER_PUB": str(keydir / "server_pub.asc"),
        "RMAP_SERVER_PRIV": str(keydir / "server_priv.asc"),
        "RMAP_CLIENT_KEYS_DIR": str(keydir / "clients"),
        "RMAP_WM_KEY": "unit-test-wm-key",
        "STORAGE_DIR": str(tmp_path),
        "RMAP_SOURCE_PDF": str(REPO_ROOT / "Group_16.pdf"),
    }
    env.update(overrides)
    for k, v in env.items():
        monkeypatch.setenv(k, str(v))
    return server_module.create_app()


def test_safe_link_rejects_non_hex_and_is_traversal_proof():
    from rmap_endpoints import _safe_link

    assert _safe_link("A" * 32) == "a" * 32          # hex passes through, lowered
    nasty = _safe_link("../../etc/passwd")            # non-hex is hashed away
    assert nasty.isalnum() and "/" not in nasty and ".." not in nasty


def test_get_link_503_when_source_pdf_missing(keydir, monkeypatch, tmp_path):
    # if the source pdf is missing we should say 503, not crash
    app = _make_app(keydir, monkeypatch, tmp_path,
                    RMAP_SOURCE_PDF=str(tmp_path / "nope.pdf"))
    r = app.test_client().post("/api/rmap-get-link", json={"payload": "x"})
    assert r.status_code == 503
    assert "source" in r.get_json()["error"].lower()


def test_get_link_503_when_source_is_not_a_pdf(keydir, monkeypatch, tmp_path):
    bogus = tmp_path / "not.pdf"
    bogus.write_bytes(b"I am not a PDF")
    app = _make_app(keydir, monkeypatch, tmp_path, RMAP_SOURCE_PDF=str(bogus))
    assert app.test_client().post("/api/rmap-get-link", json={"payload": "x"}).status_code == 503


def test_get_link_503_when_wm_key_not_configured(keydir, monkeypatch, tmp_path):
    app = _make_app(keydir, monkeypatch, tmp_path, RMAP_WM_KEY="")
    assert app.test_client().post("/api/rmap-get-link", json={"payload": "x"}).status_code == 503


def test_both_endpoints_503_when_keys_absent(keydir, monkeypatch, tmp_path):
    app = _make_app(keydir, monkeypatch, tmp_path,
                    RMAP_SERVER_PUB="", RMAP_SERVER_PRIV="", RMAP_CLIENT_KEYS_DIR="")
    tc = app.test_client()
    assert tc.post("/api/rmap-initiate", json={}).status_code == 503
    assert tc.post("/api/rmap-get-link", json={}).status_code == 503


def test_get_version_never_leaks_db_internals(keydir, monkeypatch, tmp_path):
    # a broken db must not print db details to the caller
    app = _make_app(keydir, monkeypatch, tmp_path, DB_HOST="127.0.0.1", DB_PORT="1")
    r = app.test_client().get("/api/get-version/" + "a" * 32)
    assert r.status_code == 503
    body = r.get_data(as_text=True).lower()
    for leak in ("traceback", "pymysql", "sqlalchemy", "mysql", "password", "select"):
        assert leak not in body, f"leaked {leak!r}: {body}"


@pytest.mark.skipif(not os.environ.get("TATOU_DB_TEST"), reason="needs a live MariaDB")
def test_quota_exceeded_returns_429(app, keydir, monkeypatch):
    import rmap_endpoints

    # set the quota directly instead of counting rows (db persists between runs)
    tc = app.test_client()

    def handshake() -> int:
        c = _client(keydir, identity=QUOTA_IDENTITY, priv="quota_priv.asc")
        c.process_resp1(tc.post("/api/rmap-initiate", json=c.build_msg1()).get_json())
        return tc.post("/api/rmap-get-link", json=c.build_msg2()).status_code

    monkeypatch.setattr(rmap_endpoints, "MAX_VERSIONS_PER_IDENTITY", 10**9)
    assert handshake() == 200, "a handshake under quota must succeed"
    monkeypatch.setattr(rmap_endpoints, "MAX_VERSIONS_PER_IDENTITY", 0)
    assert handshake() == 429, "a handshake over quota must be refused"


@pytest.mark.skipif(not os.environ.get("TATOU_DB_TEST"), reason="needs a live MariaDB")
def test_repeat_handshakes_give_distinct_links_and_replay_does_not(app, keydir):
    tc = app.test_client()
    links = []
    for _ in range(2):
        c = _client(keydir)
        c.process_resp1(tc.post("/api/rmap-initiate", json=c.build_msg1()).get_json())
        msg2 = c.build_msg2()
        links.append(c.process_resp2(tc.post("/api/rmap-get-link", json=msg2).get_json()))
        # replaying the *same* msg2 must resolve to the same link, not a new one
        assert c.process_resp2(tc.post("/api/rmap-get-link", json=msg2).get_json()) == links[-1]
    assert links[0] != links[1], "each handshake must get its own version"


@pytest.mark.skipif(not os.environ.get("TATOU_DB_TEST"), reason="needs a live MariaDB")
def test_get_version_410_when_file_deleted_from_disk(app, keydir, tmp_path):
    tc = app.test_client()
    c = _client(keydir)
    c.process_resp1(tc.post("/api/rmap-initiate", json=c.build_msg1()).get_json())
    link = c.process_resp2(tc.post("/api/rmap-get-link", json=c.build_msg2()).get_json())
    assert tc.get(f"/api/get-version/{link}").status_code == 200
    for p in (tmp_path / "rmap").glob("*.pdf"):
        p.unlink()
    assert tc.get(f"/api/get-version/{link}").status_code == 410
