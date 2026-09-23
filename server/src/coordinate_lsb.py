"""
coordinate_lsb.py
=================

A custom Tatou watermarking method: **Coordinate-LSB steganography**.

This method hides a secret string inside a PDF by making *tiny, invisible*
adjustments to where existing text is drawn on the page. The secret is
encrypted-and-authenticated with the caller's `key` (HMAC), so another group
cannot read it, forge it, or silently corrupt it without detection.

Registered in `watermarking_utils.METHODS` as "coordinate-lsb".

Interface implemented (matches Tatou's abstract base):
    - name                        -> str   (unique identifier of the method)
    - add_watermark(pdf, secret, key, position) -> bytes
    - read_secret(pdf, key)       -> str
    - is_watermark_applicable(pdf, position) -> bool
    - get_usage()                 -> str

Dependencies: pikepdf + Python stdlib.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import struct
from typing import Union

import pikepdf

# Tatou ships these in watermarking_method.py. Import them if present;
# fall back to local definitions so this file is also runnable standalone.
try:
    from watermarking_method import (
        WatermarkingMethod,
        WatermarkingError,
        SecretNotFoundError,
        load_pdf_bytes,
        PdfSource,
    )
except Exception:  # pragma: no cover - standalone fallback
    class WatermarkingError(Exception):
        ...

    class SecretNotFoundError(WatermarkingError):
        ...

    PdfSource = Union[str, bytes, io.BytesIO]

    class WatermarkingMethod:
        name: str = "base"

        def add_watermark(self, pdf, secret, key, position=None) -> bytes:
            raise NotImplementedError

        def read_secret(self, pdf, key) -> str:
            raise NotImplementedError

        def is_watermark_applicable(self, pdf, position=None) -> bool:
            return True

        def get_usage(self) -> str:
            return ""

    def load_pdf_bytes(pdf: PdfSource) -> bytes:
        if isinstance(pdf, bytes):
            return pdf
        if isinstance(pdf, io.BytesIO):
            return pdf.getvalue()
        with open(pdf, "rb") as fh:
            return fh.read()


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# A short signature so we can recognise our own watermark on read.
_MAGIC = b"TATOU-CLSB\x01"

# We hide payload bits in the low-order fraction of Tx/Ty text-position
# operands inside PDF content streams. STEP is the quantisation grid: text is
# nudged onto a grid of 1/GRID points, and the chosen grid cell's parity
# carries one bit. 0.01 pt is far below anything a human eye (or a printer)
# resolves, but survives being re-saved.
_GRID = 100          # 1/100 pt resolution
_HMAC_LEN = 16       # bytes of truncated HMAC-SHA256 appended for integrity


# --------------------------------------------------------------------------- #
# Helpers: turn a secret into an authenticated, self-describing bit-stream
# --------------------------------------------------------------------------- #

def _derive_key(key: str) -> bytes:
    """Stretch the user-supplied key into a 32-byte MAC key."""
    return hashlib.sha256(("tatou-clsb::" + key).encode("utf-8")).digest()


def _pack_payload(secret: str, key: str) -> bytes:
    """
    Build the byte blob we will embed:

        MAGIC | len(secret) as u32 | secret_bytes | HMAC(everything above)

    The HMAC is what makes this tamper-evident: change one byte of the
    watermark and the tag no longer matches, so read_secret refuses it
    instead of returning garbage.
    """
    body = _MAGIC + struct.pack(">I", len(secret.encode())) + secret.encode("utf-8")
    tag = hmac.new(_derive_key(key), body, hashlib.sha256).digest()[:_HMAC_LEN]
    return body + tag


def _unpack_payload(blob: bytes, key: str) -> str:
    """Reverse of _pack_payload, with full verification."""
    if len(blob) < len(_MAGIC) + 4 + _HMAC_LEN:
        raise SecretNotFoundError("payload too short")
    if not blob.startswith(_MAGIC):
        raise SecretNotFoundError("magic header not found")

    start = len(_MAGIC) + 4
    (slen,) = struct.unpack(">I", blob[len(_MAGIC):start])
    # blob continues past the payload with bits from untouched operands
    end = start + slen
    if len(blob) < end + _HMAC_LEN:
        raise SecretNotFoundError("payload truncated")

    body, tag = blob[:end], blob[end:end + _HMAC_LEN]
    expected = hmac.new(_derive_key(key), body, hashlib.sha256).digest()[:_HMAC_LEN]
    # constant-time compare so an attacker can't time their way to a forgery
    if not hmac.compare_digest(tag, expected):
        raise SecretNotFoundError("integrity check failed (wrong key or tampered)")

    return body[start:].decode("utf-8")


def _bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def _bits_to_bytes(bits) -> bytes:
    out = bytearray()
    acc = 0
    n = 0
    for b in bits:
        acc = (acc << 1) | b
        n += 1
        if n == 8:
            out.append(acc)
            acc = 0
            n = 0
    return bytes(out)


# --------------------------------------------------------------------------- #
# The watermarking method
# --------------------------------------------------------------------------- #

class CoordinateLSB(WatermarkingMethod):
    """Hide bits in the low-order digits of text-drawing coordinates."""

    name = "coordinate-lsb"

    # ---- required interface -------------------------------------------- #

    @staticmethod
    def get_usage() -> str:
        return (
            "Embeds an HMAC-authenticated secret in the sub-point fractional "
            "part of text positioning operators (Td/TD/Tm) across the PDF's "
            "content streams. Invisible to readers, robust to re-saving, and "
            "tamper-evident: reading requires the same key used to embed."
        )

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        """We need enough text-positioning operators to store the payload."""
        try:
            capacity_bits = self._count_capacity(load_pdf_bytes(pdf))
        except Exception:
            return False
        # A tiny secret still needs MAGIC(11) + len(4) + hmac(16) = 31 bytes.
        return capacity_bits >= (31 * 8)

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        raw = load_pdf_bytes(pdf)
        payload = _pack_payload(secret, key)
        bits = list(_bytes_to_bits(payload))

        with pikepdf.open(io.BytesIO(raw)) as doc:
            written = self._embed_bits(doc, bits)
            if written < len(bits):
                raise WatermarkingError(
                    f"not enough capacity: needed {len(bits)} bits, "
                    f"only {written} available"
                )
            buf = io.BytesIO()
            doc.save(buf)
            return buf.getvalue()

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        raw = load_pdf_bytes(pdf)
        with pikepdf.open(io.BytesIO(raw)) as doc:
            bits = self._extract_bits(doc)

        data = _bits_to_bytes(bits)
        # Search for our MAGIC and try to unpack from there. We embed
        # sequentially from the first operator, so offset 0 is the fast path.
        idx = data.find(_MAGIC)
        if idx == -1:
            raise SecretNotFoundError("no coordinate-LSB watermark present")
        return _unpack_payload(data[idx:], key)

    # ---- internals ----------------------------------------------------- #

    def _count_capacity(self, raw: bytes) -> int:
        with pikepdf.open(io.BytesIO(raw)) as doc:
            return self._embed_bits(doc, bits=None, dry_run=True)

    def _target_operators(self):
        # Operators whose numeric operands we are allowed to nudge.
        return {b"Td", b"TD", b"Tm"}

    def _embed_bits(self, doc, bits, dry_run: bool = False) -> int:
        """
        Walk every content stream, find text-positioning operators, and encode
        one bit into the fractional part of each numeric operand by forcing the
        (value * GRID) integer to have the desired parity.

        Returns the number of bits written (or, in dry_run, the capacity).
        """
        targets = self._target_operators()
        written = 0
        total_bits = None if dry_run else len(bits)

        for page in doc.pages:
            for _name, stream in self._content_streams(page):
                try:
                    tokens = list(pikepdf.parse_content_stream(stream))
                except Exception:
                    continue

                changed = False
                # Rebuild instructions as plain lists: pikepdf may hand back
                # operand copies, so in-place edits would not be serialized.
                rebuilt = []
                for operands, operator in tokens:
                    operands = list(operands)
                    if bytes(operator) in targets:
                        for idx, op in enumerate(operands):
                            try:
                                value = float(op)
                            except Exception:
                                continue

                            if total_bits is not None and written >= total_bits:
                                break

                            if not dry_run:
                                operands[idx] = self._encode_bit(value, bits[written])
                                changed = True
                            written += 1
                    rebuilt.append((operands, operator))

                if changed:
                    self._write_stream(stream, rebuilt)

                if total_bits is not None and written >= total_bits:
                    return written

        return written

    def _extract_bits(self, doc):
        targets = self._target_operators()
        bits = []
        for page in doc.pages:
            for _name, stream in self._content_streams(page):
                try:
                    tokens = list(pikepdf.parse_content_stream(stream))
                except Exception:
                    continue
                for operands, operator in tokens:
                    if bytes(operator) not in targets:
                        continue
                    for op in operands:
                        try:
                            value = float(op)
                        except Exception:
                            continue
                        bits.append(self._decode_bit(value))
        return bits

    @staticmethod
    def _encode_bit(value: float, bit: int) -> float:
        """Snap value onto the 1/GRID grid, then set the cell's parity = bit."""
        cell = round(value * _GRID)
        if (cell & 1) != bit:
            cell += 1  # bump to the neighbouring cell to fix parity
        return cell / _GRID

    @staticmethod
    def _decode_bit(value: float) -> int:
        return round(value * _GRID) & 1

    # ---- pikepdf plumbing --------------------------------------------- #

    def _content_streams(self, page):
        """Yield (name, stream_object) for a page's content stream(s)."""
        contents = page.obj.get("/Contents")
        if contents is None:
            return
        if isinstance(contents, pikepdf.Array):
            for i, s in enumerate(contents):
                yield (f"contents[{i}]", s)
        else:
            yield ("contents", contents)

    def _write_stream(self, stream, tokens):
        data = pikepdf.unparse_content_stream(tokens)
        stream.write(data)
