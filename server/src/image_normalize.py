"""image_normalize.py

Normalizes embedded raster images so they render consistently across PDF
viewers: the largest image on the page is decoded, converted to 8-bit
DeviceRGB, and re-stored with a lossless filter. During that pass a short,
encrypted tag is carried in the least-significant bits of the colour samples.

The tag is encrypted and authenticated with AES-GCM using a key derived from
the caller's key, so it can neither be read nor forged without that key.
"""
from __future__ import annotations

from typing import Final
import hashlib
import hmac
import io
import struct
import zlib

import pikepdf
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class ImageNormalize(WatermarkingMethod):
    """Carry an encrypted tag in the low bit of an image's colour samples."""

    name: Final[str] = "image-normalize"

    # Marks the start of our payload so we can tell "no tag" from "wrong key".
    _MAGIC: Final[bytes] = b"IMG1"

    @staticmethod
    def get_usage() -> str:
        return (
            "Normalizes the largest embedded image to 8-bit DeviceRGB for "
            "consistent rendering. Position is ignored."
        )

    # ------------------------------------------------------------------ #
    # Interface
    # ------------------------------------------------------------------ #

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        try:
            with pikepdf.open(io.BytesIO(load_pdf_bytes(pdf))) as doc:
                return self._largest_image(doc) is not None
        except Exception:
            return False

    def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not key:
            raise ValueError("Key must be a non-empty string")

        data = load_pdf_bytes(pdf)
        payload = self._pack(secret, key)
        bits = self._to_bits(payload)

        with pikepdf.open(io.BytesIO(data)) as doc:
            obj = self._largest_image(doc)
            if obj is None:
                raise WatermarkingError("No embedded image to watermark")

            image = pikepdf.PdfImage(obj).as_pil_image().convert("RGB")
            samples = bytearray(image.tobytes())
            if len(bits) > len(samples):
                raise WatermarkingError("Image is too small for this secret")

            for i, bit in enumerate(bits):
                samples[i] = (samples[i] & 0xFE) | bit

            # Re-store the image as raw, lossless RGB so the low bits survive.
            obj.write(zlib.compress(bytes(samples)), filter=pikepdf.Name.FlateDecode)
            obj.Width, obj.Height = image.width, image.height
            obj.ColorSpace = pikepdf.Name.DeviceRGB
            obj.BitsPerComponent = 8
            for extra in (pikepdf.Name.DecodeParms, pikepdf.Name.Decode, pikepdf.Name.SMask):
                if extra in obj:
                    del obj[extra]

            out = io.BytesIO()
            doc.save(out)
            return out.getvalue()

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        if not key:
            raise ValueError("Key must be a non-empty string")

        data = load_pdf_bytes(pdf)
        with pikepdf.open(io.BytesIO(data)) as doc:
            obj = self._largest_image(doc)
            if obj is None:
                raise SecretNotFoundError("No embedded image found")
            image = pikepdf.PdfImage(obj).as_pil_image().convert("RGB")

        samples = image.tobytes()

        # Header is MAGIC (4 bytes) + nonce (12) + ciphertext length (4) = 20 bytes.
        header = self._from_bits(samples, 0, 20)
        if header[:4] != self._MAGIC:
            raise SecretNotFoundError("No image-normalize tag present")

        nonce = header[4:16]
        (clen,) = struct.unpack(">I", header[16:20])
        if clen <= 0 or (20 + clen) * 8 > len(samples):
            raise SecretNotFoundError("Tag header is invalid")

        ciphertext = self._from_bits(samples, 20, clen)
        try:
            plaintext = AESGCM(self._derive_key(key)).decrypt(nonce, ciphertext, None)
        except InvalidTag:
            raise InvalidKeyError("Wrong key or the tag was tampered with")
        return plaintext.decode("utf-8")

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _derive_key(key: str) -> bytes:
        """A 256-bit AES key from the caller's passphrase."""
        return hashlib.sha256(key.encode("utf-8")).digest()

    def _pack(self, secret: str, key: str) -> bytes:
        """MAGIC | nonce | len(ciphertext) | ciphertext, all authenticated."""
        aes_key = self._derive_key(key)
        # Synthetic nonce: derived from key + secret so identical inputs give
        # identical output (the interface requires determinism), while
        # different secrets get different nonces.
        nonce = hmac.new(aes_key, secret.encode("utf-8"), hashlib.sha256).digest()[:12]
        ciphertext = AESGCM(aes_key).encrypt(nonce, secret.encode("utf-8"), None)
        return self._MAGIC + nonce + struct.pack(">I", len(ciphertext)) + ciphertext

    @staticmethod
    def _to_bits(data: bytes) -> list[int]:
        bits: list[int] = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    @staticmethod
    def _from_bits(samples: bytes, start_byte: int, n_bytes: int) -> bytes:
        """Rebuild n_bytes from the low bit of samples, starting at byte start_byte."""
        out = bytearray()
        pos = start_byte * 8
        for _ in range(n_bytes):
            byte = 0
            for _ in range(8):
                byte = (byte << 1) | (samples[pos] & 1)
                pos += 1
            out.append(byte)
        return bytes(out)

    @staticmethod
    def _largest_image(doc: pikepdf.Pdf):
        """Return the image XObject with the most pixels, or None."""
        best = None
        for page in doc.pages:
            for obj in page.images.values():
                pixels = int(obj.Width) * int(obj.Height)
                if best is None or pixels > best[0]:
                    best = (pixels, obj)
        return best[1] if best else None


__all__ = ["ImageNormalize"]
