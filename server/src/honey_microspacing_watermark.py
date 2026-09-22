# Advanced dual-layer watermarking method combining:
# 1. Micro-spacing / Invisible content-stream steganography (Stealth Layer) ->
#   invisible text mode using PDF Text Rendering Mode 3 (Neither fill nor stroke)
#       at microscopic scale (0.01 pt)
# 2. A deceptive post-EOF trailer honey-token (Decoy Layer)

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Final

try:
    import pymupdf
except ImportError:
    import fitz as pymupdf

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class HoneyMicrospacingWatermark(WatermarkingMethod):
    name: Final[str] = "honey-microspacing"

    # Context for HMAC key derivation
    _CONTEXT: Final[bytes] = b"wm:honey-micro:v1:"
    _DECOY_CONTEXT: Final[bytes] = b"wm:add-after-eof:v1:"

    # Stealth token framing markers
    _PREFIX: Final[str] = "WM-STEALTH-v1:"
    _SUFFIX: Final[str] = ":1v-HTLAETS-MW"

    # Decoy EOF trailer marker (mimics AddAfterEOF)
    _DECOY_MAGIC: Final[bytes] = b"\n%%WM-ADD-AFTER-EOF:v1\n"


    @staticmethod
    def get_usage() -> str:
        return (
            "Dual-layer deceptive watermarking"
        )

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        # Check if PDF has at least one page to embed stealth micro-spacing
        try:
            data = load_pdf_bytes(pdf)
            doc = pymupdf.open(stream=data, filetype="pdf")
            try:
                return doc.page_count >= 1
            finally:
                doc.close()
        except Exception:
            return False

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        data = load_pdf_bytes(pdf)
        try:
            doc = pymupdf.open(stream=data, filetype="pdf")
        except Exception as exc:
            raise WatermarkingError(f"Could not open PDF: {exc}") from exc

        try:
            if doc.page_count < 1:
                raise WatermarkingError("PDF contains no pages to watermark")

            # 1. Build authentic stealth payload token
            stealth_token = self._build_stealth_token(secret, key)

            # 2. Inject invisible micro-spacing text on all pages (render_mode=3: invisible, 0.01 pt)
            for page in doc:
                page.insert_text(
                    pymupdf.Point(1, 1),
                    stealth_token,
                    fontsize=0.01,
                    render_mode=3,  # Neither fill nor stroke (should be invisible in renderers)
                    fontname="helv",
                )

            # Normalize metadata for deterministic reproducible output
            doc.set_metadata({})
            doc.del_xml_metadata()
            out = doc.tobytes(deflate=True, garbage=4, no_new_id=True)
        finally:
            doc.close()

        # 3. Append honey-token decoy trailer (appears as an ordinary AddAfterEOF watermark)
        decoy_trailer = self._build_decoy_trailer(secret, key)
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._DECOY_MAGIC + decoy_trailer + b"\n"

        return out

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        # Extract and authenticate the stealth secret; rejects decoy-only stripped files

        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        data = load_pdf_bytes(pdf)

        # 1. Inspect stealth content stream layer
        try:
            doc = pymupdf.open(stream=data, filetype="pdf")
        except Exception as exc:
            raise WatermarkingError(f"Could not open PDF: {exc}") from exc

        raw_text = ""
        try:
            raw_text = "".join(page.get_text() for page in doc)
        finally:
            doc.close()

        # Strip spaces introduced by PDF text extraction
        text = "".join(raw_text.split())

        # Search for candidate stealth tokens
        saw_valid_payload_shape = False
        pos = 0
        while True:
            start_idx = text.find(self._PREFIX, pos)
            if start_idx == -1:
                break
            end_idx = text.find(self._SUFFIX, start_idx + len(self._PREFIX))
            if end_idx == -1:
                break

            b64_payload = text[start_idx + len(self._PREFIX):end_idx]
            pos = end_idx + len(self._SUFFIX)

            try:
                raw_json = base64.urlsafe_b64decode(b64_payload.encode("ascii"))
                payload = json.loads(raw_json)
                if isinstance(payload, dict) and payload.get("v") == 1:
                    secret_bytes = base64.b64decode(payload["secret"].encode("ascii"))
                    mac_hex = str(payload["mac"])
                    saw_valid_payload_shape = True

                    expected_mac = self._mac_hex(secret_bytes, key)
                    if hmac.compare_digest(mac_hex, expected_mac):
                        return secret_bytes.decode("utf-8")
            except Exception:
                continue

        if saw_valid_payload_shape:
            raise InvalidKeyError("Provided key failed to authenticate stealth watermark")

        # 2. If stealth watermark was not found, check if a decoy exists (evidence of tampering/stripping)
        if self._DECOY_MAGIC in data:
            raise SecretNotFoundError(
                "Decoy watermark detected, but authentic stealth micro-spacing watermark is missing"
            )

        raise SecretNotFoundError("No honey-microspacing watermark found in PDF")

    # Helpers
    def _mac_hex(self, secret_bytes: bytes, key: str) -> str:
        #   Compute HMAC-SHA256 over contextualized secret
        hm = hmac.new(key.encode("utf-8"), self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()

    def _build_stealth_token(self, secret: str, key: str) -> str:
        # Serialize payload to JSON and convert to compact base64 token
        secret_bytes = secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        payload = {
            "v": 1,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
            "mac": mac_hex,
        }
        raw_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        b64_str = base64.urlsafe_b64encode(raw_json).decode("ascii")
        return f"{self._PREFIX}{b64_str}{self._SUFFIX}"

    def _build_decoy_trailer(self, secret: str, key: str) -> bytes:
        # Create a decoy AddAfterEOF-compatible payload containing a honey-token hash
        decoy_secret = f"decoy_track_{hashlib.sha256((secret + key).encode('utf-8')).hexdigest()[:16]}"
        decoy_bytes = decoy_secret.encode("utf-8")
        decoy_mac = hmac.new(key.encode("utf-8"), self._DECOY_CONTEXT + decoy_bytes, hashlib.sha256).hexdigest()

        decoy_obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": decoy_mac,
            "secret": base64.b64encode(decoy_bytes).decode("ascii"),
        }
        decoy_json = json.dumps(decoy_obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(decoy_json)


__all__ = ["HoneyMicrospacingWatermark"]
