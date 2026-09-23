"""Authenticated encryption for watermark secrets.

A secret is sealed with AES-256-GCM under a key stretched from the caller's
key with scrypt, so the ciphertext reveals nothing without the key and any
tampering is detected. Output must be deterministic (base-class contract),
so the nonce is synthetic: HMAC(nonce_key, context || secret). A nonce can
only repeat when key, context and secret all repeat, which yields the same
ciphertext and leaks nothing beyond that equality.
"""

from __future__ import annotations

import hashlib
import hmac
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from watermarking_method import InvalidKeyError

NONCE_LEN = 12
TAG_LEN = 16
OVERHEAD = NONCE_LEN + TAG_LEN

_SALT = b"tatou-wm-crypto:v1"


@lru_cache(maxsize=32)
def _derive(key: str) -> tuple[bytes, bytes]:
    # scrypt makes offline brute force of weak keys expensive
    material = Scrypt(salt=_SALT, length=64, n=2**14, r=8, p=1).derive(key.encode("utf-8"))
    return material[:32], material[32:]


def seal(secret: str, key: str, context: bytes) -> bytes:
    """Return nonce || ciphertext || tag, bound to ``context``."""
    enc_key, nonce_key = _derive(key)
    plaintext = secret.encode("utf-8")
    nonce = hmac.new(nonce_key, context + b"\x00" + plaintext, hashlib.sha256).digest()[:NONCE_LEN]
    return nonce + AESGCM(enc_key).encrypt(nonce, plaintext, context)


def unseal(blob: bytes, key: str, context: bytes) -> str:
    """Inverse of :func:`seal`; raises InvalidKeyError on wrong key or tampering."""
    if len(blob) < OVERHEAD:
        raise InvalidKeyError("sealed payload too short")
    enc_key, _ = _derive(key)
    try:
        plaintext = AESGCM(enc_key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], context)
    except InvalidTag as exc:
        raise InvalidKeyError("key failed to authenticate the watermark (wrong key or tampered)") from exc
    return plaintext.decode("utf-8")
