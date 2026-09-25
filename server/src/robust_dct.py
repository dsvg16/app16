"""robust_dct.py

Robust image watermark that survives re-compression and re-encoding.

Unlike the LSB schemes (``image-normalize``, ``coordinate-lsb``) whose bits
live in the least-significant part of a sample and are wiped by any lossy
step, this method embeds each payload bit **redundantly** across many
mid-frequency 8x8 DCT coefficients of the image's luminance channel using
quantization-index modulation (QIM / dither modulation).

Robustness comes from three things working together:

1. Mid-frequency coefficients survive JPEG quantization far better than the
   high-frequency detail an LSB touches.
2. Every payload bit is written into many blocks; the reader takes a
   majority vote, so a minority of corrupted blocks does not flip the bit.
3. The payload is framed ``MAGIC | nonce | len | AES-CTR(secret) | HMAC``.
   The HMAC (keyed) confirms a clean recovery and rejects a wrong key or a
   too-damaged image, and AES-CTR keeps the secret confidential while
   tolerating the occasional residual bit error the vote could not fix
   (CTR errors stay local instead of destroying the whole plaintext).

It is *not* magic: a blind watermark cannot survive an attack that
geometrically desynchronises the pixel grid (e.g. rasterising the whole
page to an image with new margins and a new resolution). It is built to
beat the cheap, common attacks - structural re-saves, "optimise my PDF"
JPEG recompression, and format conversion - that defeat a bare LSB.
"""
from __future__ import annotations

from typing import Final
import hashlib
import hmac
import io
import struct
import zlib

import numpy as np
import pikepdf
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)

_BLOCK: Final[int] = 8
# Mid-frequency coefficient that carries one QIM bit per block. Low enough to
# survive JPEG quantisation, high enough to stay perceptually quiet.
_COEF: Final[tuple[int, int]] = (3, 2)
# Quantisation step. Larger = more robust but more visible; tuned empirically.
_DELTA: Final[float] = 24.0
_MAGIC: Final[bytes] = b"RDCT"
_HMAC_LEN: Final[int] = 8
_NONCE_LEN: Final[int] = 8
# Fixed payload footprint so embed and read tile blocks with the same modulus
# (the reader cannot know the secret length in advance). Supports a secret of
# up to _FIXED_BYTES - (4+8+1+8) = 75 bytes; the rest is zero padding.
_FIXED_BYTES: Final[int] = 96
_HEAD: Final[int] = len(_MAGIC) + _NONCE_LEN + 1  # magic | nonce | len


def _dct_matrix() -> np.ndarray:
    # Orthonormal DCT-II: rows = frequency k, cols = spatial n.
    n = _BLOCK
    kf = np.arange(n)[:, None]   # frequency index (rows)
    xs = np.arange(n)[None, :]   # spatial index (cols)
    m = np.cos(np.pi * (2 * xs + 1) * kf / (2 * n))
    m *= np.sqrt(2.0 / n)
    m[0, :] *= 1 / np.sqrt(2)
    return m


_D = _dct_matrix()


class RobustDCT(WatermarkingMethod):
    """Redundant QIM watermark in mid-frequency image DCT coefficients."""

    name: Final[str] = "robust-dct"

    @staticmethod
    def get_usage() -> str:
        return (
            "Embeds the secret redundantly in mid-frequency 8x8 DCT coefficients "
            "of the largest image's luminance, using QIM + majority vote. Survives "
            "JPEG recompression and re-encoding. Position is ignored."
        )

    # -- key / payload -------------------------------------------------- #

    @staticmethod
    def _derive(key: str) -> bytes:
        return hashlib.sha256(b"robust-dct:v1:" + key.encode("utf-8")).digest()

    def _pack(self, secret: str, key: str) -> bytes:
        k = self._derive(key)
        sb = secret.encode("utf-8")
        max_secret = _FIXED_BYTES - _HEAD - _HMAC_LEN
        if len(sb) > max_secret:
            raise WatermarkingError(
                f"secret too long for robust-dct (max {max_secret} bytes)"
            )
        nonce = hmac.new(k, sb, hashlib.sha256).digest()[:_NONCE_LEN]
        ct = self._ctr(k, nonce, sb)
        body = _MAGIC + nonce + struct.pack(">B", len(ct)) + ct
        mac = hmac.new(k, body, hashlib.sha256).digest()[:_HMAC_LEN]
        frame = body + mac
        return frame + b"\x00" * (_FIXED_BYTES - len(frame))  # pad to fixed size

    def _unpack(self, blob: bytes, key: str) -> str:
        k = self._derive(key)
        if len(blob) < _FIXED_BYTES:
            raise SecretNotFoundError("recovered payload too short")
        if blob[:4] != _MAGIC:
            raise SecretNotFoundError("no robust-dct watermark present")
        nonce = blob[4:4 + _NONCE_LEN]
        (clen,) = struct.unpack(">B", blob[_HEAD - 1:_HEAD])
        if clen > _FIXED_BYTES - _HEAD - _HMAC_LEN:
            raise SecretNotFoundError("recovered length field is implausible")
        body = blob[:_HEAD + clen]
        mac = blob[_HEAD + clen:_HEAD + clen + _HMAC_LEN]
        expected = hmac.new(k, body, hashlib.sha256).digest()[:_HMAC_LEN]
        if not hmac.compare_digest(mac, expected):
            raise InvalidKeyError("wrong key or the watermark is too damaged to recover")
        ct = body[_HEAD:_HEAD + clen]
        return self._ctr(k, nonce, ct).decode("utf-8")

    @staticmethod
    def _ctr(k: bytes, nonce: bytes, data: bytes) -> bytes:
        # AES-CTR with a 128-bit block counter seeded from the 64-bit nonce.
        iv = nonce + b"\x00" * 8
        c = Cipher(algorithms.AES(k), modes.CTR(iv)).encryptor()
        return c.update(data) + c.finalize()

    @staticmethod
    def _bits(data: bytes) -> np.ndarray:
        return np.unpackbits(np.frombuffer(data, dtype=np.uint8))

    # -- image plumbing ------------------------------------------------- #

    @staticmethod
    def _largest(doc: pikepdf.Pdf):
        best = None
        for page in doc.pages:
            for obj in page.images.values():
                px = int(obj.Width) * int(obj.Height)
                if best is None or px > best[0]:
                    best = (px, obj)
        return best[1] if best else None

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        try:
            with pikepdf.open(io.BytesIO(load_pdf_bytes(pdf))) as doc:
                obj = self._largest(doc)
                if obj is None:
                    return False
                blocks = (int(obj.Width) // _BLOCK) * (int(obj.Height) // _BLOCK)
                return blocks >= 8 * (len(_MAGIC) + _NONCE_LEN + 1 + _HMAC_LEN + 4)
        except Exception:
            return False

    def add_watermark(self, pdf: PdfSource, secret: str, key: str,
                      position: str | None = None) -> bytes:
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not key:
            raise ValueError("Key must be a non-empty string")

        data = load_pdf_bytes(pdf)
        bits = self._bits(self._pack(secret, key))

        with pikepdf.open(io.BytesIO(data)) as doc:
            obj = self._largest(doc)
            if obj is None:
                raise WatermarkingError("No embedded image to watermark")
            rgb = pikepdf.PdfImage(obj).as_pil_image().convert("RGB")
            ycc = np.asarray(rgb.convert("YCbCr"), dtype=np.float64)
            y = ycc[:, :, 0]

            self._embed(y, bits)

            ycc[:, :, 0] = np.clip(y, 0, 255)
            out_img = Image.fromarray(ycc.astype(np.uint8), "YCbCr").convert("RGB")

            # Re-store as raw lossless RGB so the coefficients we set persist.
            samples = np.asarray(out_img, dtype=np.uint8).tobytes()
            obj.write(zlib.compress(samples), filter=pikepdf.Name.FlateDecode)
            obj.Width, obj.Height = out_img.width, out_img.height
            obj.ColorSpace = pikepdf.Name.DeviceRGB
            obj.BitsPerComponent = 8
            for extra in (pikepdf.Name.DecodeParms, pikepdf.Name.Decode, pikepdf.Name.SMask):
                if extra in obj:
                    del obj[extra]
            res = io.BytesIO()
            doc.save(res)
            return res.getvalue()

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        if not key:
            raise ValueError("Key must be a non-empty string")
        data = load_pdf_bytes(pdf)
        with pikepdf.open(io.BytesIO(data)) as doc:
            obj = self._largest(doc)
            if obj is None:
                raise SecretNotFoundError("No embedded image found")
            rgb = pikepdf.PdfImage(obj).as_pil_image().convert("RGB")
        y = np.asarray(rgb.convert("YCbCr"), dtype=np.float64)[:, :, 0]

        votes = self._extract(y, 8 * _FIXED_BYTES)
        recovered = np.packbits((votes > 0).astype(np.uint8)).tobytes()
        return self._unpack(recovered, key)

    # -- core DCT-QIM --------------------------------------------------- #

    def _embed(self, y: np.ndarray, bits: np.ndarray) -> None:
        h, w = y.shape
        by, bx = h // _BLOCK, w // _BLOCK
        u, v = _COEF
        idx = 0
        n = len(bits)
        for r in range(by):
            for c in range(bx):
                bit = int(bits[idx % n])
                idx += 1
                sl = (slice(r * _BLOCK, r * _BLOCK + _BLOCK),
                      slice(c * _BLOCK, c * _BLOCK + _BLOCK))
                block = y[sl]
                coef = _D @ block @ _D.T
                q = np.round(coef[u, v] / _DELTA)
                if (int(q) & 1) != bit:
                    q += 1
                coef[u, v] = q * _DELTA
                y[sl] = _D.T @ coef @ _D

    def _extract(self, y: np.ndarray, nbits: int) -> np.ndarray:
        h, w = y.shape
        by, bx = h // _BLOCK, w // _BLOCK
        u, v = _COEF
        # signed vote accumulator per payload-bit position
        votes = np.zeros(nbits, dtype=np.int64)
        idx = 0
        for r in range(by):
            for c in range(bx):
                sl = (slice(r * _BLOCK, r * _BLOCK + _BLOCK),
                      slice(c * _BLOCK, c * _BLOCK + _BLOCK))
                coef = _D @ y[sl] @ _D.T
                bit = int(np.round(coef[u, v] / _DELTA)) & 1
                votes[idx % nbits] += 1 if bit else -1
                idx += 1
        return votes


__all__ = ["RobustDCT"]
