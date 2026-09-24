"""Opt-in RMAP relay that pairs neighboring even-numbered course groups."""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass
from urllib.request import HTTPRedirectHandler, Request, build_opener

from rmap.crypto import decrypt_json, encrypt_json


class TargetError(Exception):
    """A paired course server did not complete the protocol step."""


class InvalidRelayMessage(Exception):
    """The incoming message is not a valid RMAP relay message."""


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def paired_targets(include_group32: bool = True) -> dict[str, str]:
    """Pair every external even group, with 14↔34 in place of our Group 16."""
    pairs = [(number, number + 2) for number in range(2, 30, 4)
             if number != 14]
    if include_group32:
        pairs.append((30, 32))
    mapping = {}
    for first, second in pairs:
        a, b = f"Group_{first:02d}", f"Group_{second:02d}"
        mapping[a] = b
        mapping[b] = a
    mapping["Group_14"] = "Group_34"
    mapping["Group_34"] = "Group_14"
    return mapping


@dataclass(frozen=True)
class RelayResult:
    identity: str
    target_group: str
    link: str
    target_pdf: bytes | None


@dataclass(frozen=True)
class PendingRelay:
    identity: str
    target_group: str
    nonce_client: int
    transport: object
    started: float


class CourseGroupHTTP:
    """HTTP transport confined to one paired course host on port 5000 or 8000."""

    def __init__(self, target_group: str, timeout: float = 5.0):
        if not re.fullmatch(r"Group_\d{2}", target_group):
            raise ValueError("invalid course group")
        number = int(target_group.split("_")[1])
        if not 2 <= number <= 34 or number % 2:
            raise ValueError("target group must be an even course group from 02 to 34")
        self.host = f"softsec-group-{number:02d}.dsv.local.su.se"
        self.timeout = timeout
        self.port: int | None = None
        self.opener = build_opener(NoRedirects)

    def _post_to_port(self, port: int, endpoint: str, payload: dict) -> dict:
        request = Request(
            f"http://{self.host}:{port}{endpoint}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read(1_000_001)
            if len(body) > 1_000_000:
                raise TargetError("RMAP response is too large")
            message = json.loads(body)
            if not isinstance(message, dict) or not isinstance(message.get("payload"), str):
                raise TargetError("invalid RMAP response")
            return message
        except (OSError, ValueError) as exc:
            raise TargetError("paired RMAP endpoint unavailable") from exc

    def post(self, endpoint: str, payload: dict) -> dict:
        if self.port is not None:
            return self._post_to_port(self.port, endpoint, payload)
        last_error = None
        for port in (5000, 8000):
            try:
                response = self._post_to_port(port, endpoint, payload)
                self.port = port
                return response
            except TargetError as exc:
                last_error = exc
        raise TargetError("paired RMAP endpoint unavailable on ports 5000 and 8000") from last_error

    def get_version(self, link: str) -> bytes:
        if self.port is None or not re.fullmatch(r"[0-9a-f]{32}", link):
            raise ValueError("invalid RMAP link or missing target port")
        request = Request(
            f"http://{self.host}:{self.port}/api/get-version/{link}", method="GET"
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                data = response.read(20_000_001)
            if len(data) > 20_000_000 or not data.startswith(b"%PDF-"):
                raise TargetError("paired server returned no valid PDF")
            return data
        except OSError as exc:
            raise TargetError("paired server PDF unavailable") from exc


class PairedRelay:
    def __init__(self, own_private_key, passphrase, target_public_keys,
                 allowed_identities, targets, transport_factory=CourseGroupHTTP,
                 pending_seconds: float = 300):
        self.own_private_key = own_private_key
        self.passphrase = passphrase
        self.target_public_keys = target_public_keys
        self.allowed_identities = allowed_identities
        self.targets = targets
        self.transport_factory = transport_factory
        self.pending_seconds = pending_seconds
        self.lock = threading.Lock()
        self.pending: PendingRelay | None = None

    def _expire(self) -> None:
        if self.pending and time.monotonic() - self.pending.started > self.pending_seconds:
            self.pending = None

    def initiate(self, msg1: dict) -> dict | None:
        """Return the selected target's sealed response, or None for local handling."""
        with self.lock:
            self._expire()
            if self.pending is not None:
                return None
            data = decrypt_json(msg1, self.own_private_key, self.passphrase)
            identity, nonce_client = data.get("identity"), data.get("nonceClient")
            if (not isinstance(identity, str) or identity not in self.allowed_identities
                    or type(nonce_client) is not int or not 0 <= nonce_client < 2**64):
                raise InvalidRelayMessage("invalid identity or client nonce")
            target_group = self.targets.get(identity)
            if target_group is None:
                return None
            target_key = self.target_public_keys[target_group]
            transport = self.transport_factory(target_group)
            relayed = encrypt_json(
                {"identity": identity, "nonceClient": nonce_client}, target_key
            )
            response = transport.post("/api/rmap-initiate", relayed)
            self.pending = PendingRelay(
                identity, target_group, nonce_client, transport, time.monotonic()
            )
            return response

    def finish(self, msg2: dict) -> RelayResult | None:
        """Complete the paired handshake and fetch its document."""
        with self.lock:
            self._expire()
            if self.pending is None:
                return None
            data = decrypt_json(msg2, self.own_private_key, self.passphrase)
            nonce_server = data.get("nonceServer")
            if type(nonce_server) is not int or not 0 <= nonce_server < 2**64:
                raise InvalidRelayMessage("invalid server nonce")
            pending = self.pending
            target_key = self.target_public_keys[pending.target_group]
            relayed = encrypt_json({"nonceServer": nonce_server}, target_key)
            pending.transport.post("/api/rmap-get-link", relayed)
            link = f"{pending.nonce_client:016x}{nonce_server:016x}"
            try:
                target_pdf = pending.transport.get_version(link)
            except TargetError:
                target_pdf = None
            self.pending = None
            return RelayResult(pending.identity, pending.target_group, link, target_pdf)
