"""Closed-loop protocol tests; no course server or network is contacted."""

from __future__ import annotations

import pymupdf
import pytest
from flask import Flask

pytest.importorskip("rmap")
from rmap import RMAPClient, RMAPServer
from rmap.crypto import load_key
from rmap.keygen import generate_keypair

import rmap_endpoints
from rmap_paired_relay import CourseGroupHTTP, PairedRelay, TargetError, paired_targets


def make_pdf(label):
    document = pymupdf.open()
    document.new_page().insert_text((72, 72), label)
    result = document.tobytes()
    document.close()
    return result


class LocalTarget:
    def __init__(self, server, label):
        self.server = server
        self.label = label
        self.versions = {}

    def post(self, endpoint, payload):
        if endpoint == "/api/rmap-initiate":
            return self.server.receiveMsg1(payload)[1]
        if endpoint == "/api/rmap-get-link":
            identity, link, response = self.server.receiveMsg2(payload)
            self.versions[link] = make_pdf(f"{self.label} copy for {identity}")
            return response
        raise AssertionError(endpoint)

    def get_version(self, link):
        return self.versions[link]


@pytest.fixture
def protocol(tmp_path):
    keys = {
        "ours": generate_keypair("Group_16", "ours@example.invalid"),
        "Group_02": generate_keypair("Group_02", "two@example.invalid"),
        "Group_04": generate_keypair("Group_04", "four@example.invalid"),
        "Group_14": generate_keypair("Group_14", "fourteen@example.invalid"),
    }
    for stem, key in keys.items():
        (tmp_path / f"{stem}_priv.asc").write_text(str(key))
        (tmp_path / f"{stem}_pub.asc").write_text(str(key.pubkey))

    our_server = RMAPServer(tmp_path / "ours_pub.asc", tmp_path / "ours_priv.asc")
    targets = {}
    clients = {}
    for group in ("Group_02", "Group_04", "Group_14"):
        our_server.loadIdentity(group, tmp_path / f"{group}_pub.asc")
        client = RMAPClient(
            group, tmp_path / f"{group}_priv.asc", tmp_path / "ours_pub.asc"
        )
        clients[group] = client
    for group in ("Group_02", "Group_04"):
        target = RMAPServer(
            tmp_path / f"{group}_pub.asc", tmp_path / f"{group}_priv.asc"
        )
        visitors = ("Group_04", "Group_14") if group == "Group_02" else ("Group_02",)
        for visitor in visitors:
            target.loadIdentity(visitor, tmp_path / f"{visitor}_pub.asc")
        targets[group] = LocalTarget(target, group)

    relay = PairedRelay(
        load_key(tmp_path / "ours_priv.asc"), None,
        {group: load_key(tmp_path / f"{group}_pub.asc") for group in targets},
        our_server.identities, paired_targets(),
        transport_factory=lambda group: targets[group],
    )
    return clients, our_server, relay, targets, tmp_path


@pytest.mark.parametrize(
    "visitor,target", [
        ("Group_02", "Group_04"),
        ("Group_04", "Group_02"),
        ("Group_14", "Group_02"),
    ]
)
def test_paired_capture_and_visitor_pickup(protocol, visitor, target):
    clients, our_server, relay, _targets, _keydir = protocol
    client = clients[visitor]
    client.process_resp1(relay.initiate(client.build_msg1()))
    result = relay.finish(client.build_msg2())
    assert result.identity == visitor
    assert result.target_group == target
    assert result.link == client.expected_link
    with pymupdf.open(stream=result.target_pdf, filetype="pdf") as captured:
        assert f"{target} copy for {visitor}" in captured[0].get_text()

    our_versions = {result.link: make_pdf(f"Group_16 copy for {visitor}")}
    response2 = our_server.encrypt_for_identity({"result": result.link}, visitor)
    visitor_link = client.process_resp2(response2)
    with pymupdf.open(stream=our_versions[visitor_link], filetype="pdf") as pickup:
        assert f"Group_16 copy for {visitor}" in pickup[0].get_text()


def test_busy_relay_uses_local_fallback(protocol):
    clients, _our_server, relay, _targets, _keydir = protocol
    first = clients["Group_02"]
    second = clients["Group_04"]
    assert relay.initiate(first.build_msg1()) is not None
    assert relay.initiate(second.build_msg1()) is None


def test_rejected_final_keeps_pending_session(protocol):
    clients, _our_server, relay, targets, _keydir = protocol
    client = clients["Group_02"]
    client.process_resp1(relay.initiate(client.build_msg1()))
    target = targets["Group_04"]
    real_post = target.post

    def reject_final(endpoint, payload):
        if endpoint == "/api/rmap-get-link":
            raise TargetError("rejected")
        return real_post(endpoint, payload)

    target.post = reject_final
    msg2 = client.build_msg2()
    with pytest.raises(TargetError):
        relay.finish(msg2)
    target.post = real_post
    assert relay.finish(msg2).link == client.expected_link


@pytest.mark.parametrize(
    "visitor,target", [("Group_02", "Group_04"), ("Group_14", "Group_02")]
)
def test_flask_initiate_route_selects_the_pair(
    protocol, monkeypatch, visitor, target
):
    clients, _our_server, relay, targets, keydir = protocol
    client_keys = keydir / "clients"
    client_keys.mkdir()
    for group in ("Group_02", "Group_04", "Group_14"):
        (client_keys / f"{group}.asc").write_text(
            (keydir / f"{group}_pub.asc").read_text()
        )
    monkeypatch.setenv("RMAP_SERVER_PUB", str(keydir / "ours_pub.asc"))
    monkeypatch.setenv("RMAP_SERVER_PRIV", str(keydir / "ours_priv.asc"))
    monkeypatch.setenv("RMAP_CLIENT_KEYS_DIR", str(client_keys))
    monkeypatch.setenv("RMAP_PAIRED_RELAY", "1")
    monkeypatch.setenv("STORAGE_DIR", str(keydir / "storage"))
    monkeypatch.setattr(
        rmap_endpoints, "paired_targets", lambda include_group32: {
            "Group_02": "Group_04", "Group_04": "Group_02",
            "Group_14": "Group_02",
            "Group_06": "Group_08", "Group_08": "Group_06",
        }
    )
    monkeypatch.setattr(rmap_endpoints, "PairedRelay", lambda **_kwargs: relay)
    app = Flask(__name__)
    rmap_endpoints.register_rmap(app)

    client = clients[visitor]
    response = app.test_client().post("/api/rmap-initiate", json=client.build_msg1())
    assert response.status_code == 200
    client.process_resp1(response.get_json())
    assert targets[target].server.identities[visitor].nonceClient == client.nonceClient


def test_pair_mapping_and_host_boundary():
    mapping = paired_targets()
    assert len(mapping) == 15
    assert all(mapping[mapping[visitor]] == visitor
               for visitor in mapping if visitor != "Group_14")
    assert mapping["Group_02"] == "Group_04"
    assert mapping["Group_04"] == "Group_02"
    assert mapping["Group_14"] == "Group_02"
    assert "Group_16" not in mapping
    assert mapping["Group_26"] == "Group_28"
    assert mapping["Group_28"] == "Group_26"
    assert mapping["Group_30"] == "Group_32"
    assert mapping["Group_32"] == "Group_30"
    assert "Group_30" not in paired_targets(include_group32=False)
    assert CourseGroupHTTP("Group_04").host == "softsec-group-04.dsv.local.su.se"
    with pytest.raises(ValueError):
        CourseGroupHTTP("Group_05")
