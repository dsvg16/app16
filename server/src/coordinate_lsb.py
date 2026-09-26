"""
coordinate_lsb.py
=================

Coordinate-LSB steganography: the secret is hidden by nudging existing text
positions by at most 0.01 pt, far below anything visible or printable.

Each translation operand of a Td / TD / Tm operator is snapped to a 1/100 pt
grid and the parity of its grid cell carries one bit. Only translations are
touched (Tm's e/f, never its a-d scale/rotation/shear), so glyph shapes are
unchanged.

The embedded bit-stream is::

    MAGIC | u32 len(sealed) | sealed

where ``sealed`` is the AES-256-GCM encryption of the secret (see
``wm_crypto``): without the key the secret can be neither read nor forged.
"""

from __future__ import annotations

import io
import struct

import pikepdf

import wm_crypto
from watermarking_method import (
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)

_MAGIC = b"TATOU-CLSB\x02"
_CONTEXT = b"wm:coordinate-lsb:v2"
_GRID = 100  # 1/100 pt resolution
_HEADER_LEN = len(_MAGIC) + 4


def _pack_payload(secret: str, key: str) -> bytes:
    sealed = wm_crypto.seal(secret, key, _CONTEXT)
    return _MAGIC + struct.pack(">I", len(sealed)) + sealed


def _unpack_payload(blob: bytes, key: str) -> str:
    if len(blob) < _HEADER_LEN or not blob.startswith(_MAGIC):
        raise SecretNotFoundError("magic header not found")
    (slen,) = struct.unpack(">I", blob[len(_MAGIC):_HEADER_LEN])
    # blob continues past the payload with bits from untouched operands
    sealed = blob[_HEADER_LEN:_HEADER_LEN + slen]
    if slen < wm_crypto.OVERHEAD or len(sealed) < slen:
        raise SecretNotFoundError("coordinate-LSB payload truncated or corrupt")
    return wm_crypto.unseal(sealed, key, _CONTEXT)


def _bytes_to_bits(data: bytes) -> list[int]:
    return [(byte >> i) & 1 for byte in data for i in range(7, -1, -1)]


def _bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        acc = 0
        for b in bits[i:i + 8]:
            acc = (acc << 1) | b
        out.append(acc)
    return bytes(out)


def _slot_indices(operator: bytes, n_operands: int) -> range:
    """Operand indices that are pure translations and may carry a bit."""
    if operator in (b"Td", b"TD") and n_operands == 2:
        return range(0, 2)
    if operator == b"Tm" and n_operands == 6:
        return range(4, 6)
    return range(0)


def _encode_bit(value: float, bit: int) -> float:
    cell = round(value * _GRID)
    if (cell & 1) != bit:
        cell += 1
    return cell / _GRID


def _decode_bit(value: float) -> int:
    return round(value * _GRID) & 1


class CoordinateLSB(WatermarkingMethod):
    """Hide an encrypted secret in the low-order digits of text translations."""

    name = "Method 2"

    @staticmethod
    def get_usage() -> str:
        # return (
        #     "Hides an AES-GCM-encrypted secret in the 1/100 pt digits of text "
        #     "translation operands (Td/TD, Tm e/f). Invisible, survives re-saving, "
        #     "needs a text-heavy PDF. Position is ignored."
        # )
        return "Method no 2"

    @staticmethod
    def bits_needed(secret: str) -> int:
        return 8 * (_HEADER_LEN + wm_crypto.OVERHEAD + len(secret.encode("utf-8")))

    def capacity_bits(self, pdf: PdfSource) -> int:
        with self._open(load_pdf_bytes(pdf)) as doc:
            return self._walk(doc, bits=None)

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        try:
            return self.capacity_bits(pdf) >= self.bits_needed("x")
        except Exception:
            return False

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        if not isinstance(secret, str) or not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        bits = _bytes_to_bits(_pack_payload(secret, key))
        with self._open(load_pdf_bytes(pdf)) as doc:
            try:
                written = self._walk(doc, bits)
                if written < len(bits):
                    raise WatermarkingError(
                        f"not enough capacity: needed {len(bits)} bits, only {written} available"
                    )
                buf = io.BytesIO()
                doc.save(buf, deterministic_id=True)
            except WatermarkingError:
                raise
            except Exception as exc:
                raise WatermarkingError(f"could not embed coordinate-LSB watermark: {exc}") from exc
        return buf.getvalue()

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        with self._open(load_pdf_bytes(pdf)) as doc:
            try:
                bits = self._extract_bits(doc)
            except Exception as exc:
                raise WatermarkingError(f"could not read content streams: {exc}") from exc

        data = _bits_to_bytes(bits)
        idx = data.find(_MAGIC)
        if idx == -1:
            raise SecretNotFoundError("no coordinate-LSB watermark present")
        return _unpack_payload(data[idx:], key)

    # ---- internals ----------------------------------------------------- #

    @staticmethod
    def _open(raw: bytes) -> pikepdf.Pdf:
        try:
            return pikepdf.open(io.BytesIO(raw))
        except Exception as exc:
            raise WatermarkingError(f"could not open PDF: {exc}") from exc

    def _walk(self, doc: pikepdf.Pdf, bits: list[int] | None) -> int:
        """Embed ``bits`` in order; with ``bits=None`` just count capacity."""
        total = None if bits is None else len(bits)
        written = 0
        for page in doc.pages:
            for stream in self._content_streams(page):
                try:
                    instructions = pikepdf.parse_content_stream(stream)
                except Exception:
                    continue

                changed = False
                # Rebuild instructions as plain lists: pikepdf may hand back
                # operand copies, so in-place edits would not be serialized.
                rebuilt = []
                for operands, operator in instructions:
                    operands = list(operands)
                    for idx in _slot_indices(bytes(operator), len(operands)):
                        if total is not None and written >= total:
                            break
                        try:
                            value = float(operands[idx])
                        except Exception:
                            continue
                        if bits is not None:
                            operands[idx] = _encode_bit(value, bits[written])
                            changed = True
                        written += 1
                    rebuilt.append((operands, operator))

                if changed:
                    stream.write(pikepdf.unparse_content_stream(rebuilt))
                if total is not None and written >= total:
                    return written
        return written

    def _extract_bits(self, doc: pikepdf.Pdf) -> list[int]:
        bits = []
        for page in doc.pages:
            for stream in self._content_streams(page):
                try:
                    instructions = pikepdf.parse_content_stream(stream)
                except Exception:
                    continue
                for operands, operator in instructions:
                    for idx in _slot_indices(bytes(operator), len(operands)):
                        try:
                            bits.append(_decode_bit(float(operands[idx])))
                        except Exception:
                            continue
        return bits

    @staticmethod
    def _content_streams(page):
        contents = page.obj.get("/Contents")
        if contents is None:
            return []
        if isinstance(contents, pikepdf.Array):
            return list(contents)
        return [contents]


__all__ = ["CoordinateLSB"]
