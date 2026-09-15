# Visible watermark: tiles a faint token over every page.
# token looks like  WMK1:<secret>|<hmac>:1KMW
# the hmac (with the key) proves the mark is real. the secret is NOT hidden,
# it is meant to be visible so a leaked copy shows who leaked it.
from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Final

import pymupdf

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class TiledVisibleWatermark(WatermarkingMethod):

    name: Final[str] = "tiled-visible"

    _PREFIX: Final[str] = "WMK1:"
    _SUFFIX: Final[str] = ":1KMW"
    _CONTEXT: Final[bytes] = b"wm:tiled-visible:v1:"
    _DEFAULT_OPACITY: Final[float] = 0.10
    # smallest font we use. also limits the secret to about 150 chars
    _MIN_FONTSIZE: Final[float] = 3.0

    @staticmethod
    def get_usage() -> str:
        return (
            "Tiles a faint copy of the secret across every page. "
            "position (optional): integer opacity percent 1-100 (default 10)."
        )

    # helpers
    def _mac(self, secret: str, key: str) -> str:
        # 32 hex chars is enough and keeps the token short
        return hmac.new(
            key.encode("utf-8"),
            self._CONTEXT + secret.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:32]

    def _token(self, secret: str, key: str) -> str:
        # base64 the secret so it has no spaces (the pdf text layer adds spaces,
        # and we strip them on read). the mac is over the real secret.
        enc = base64.urlsafe_b64encode(secret.encode("utf-8")).decode("ascii")
        return f"{self._PREFIX}{enc}|{self._mac(secret, key)}{self._SUFFIX}"

    def _opacity(self, position: str | None) -> float:
        if not position:
            return self._DEFAULT_OPACITY
        try:
            pct = int(str(position).strip())
        except ValueError:
            raise ValueError("position must be an integer opacity percent (1-100)")
        if not 1 <= pct <= 100:
            raise ValueError("position opacity must be between 1 and 100")
        return pct / 100.0

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
        opacity = self._opacity(position)
        data = load_pdf_bytes(pdf)
        token = self._token(secret, key)

        try:
            doc = pymupdf.open(stream=data, filetype="pdf")
        except Exception as e:  # bad/corrupt pdf
            raise WatermarkingError(f"could not open pdf: {e}") from e
        try:
            for page in doc:
                self._stamp_page(page, token, opacity)
            # clear metadata and keep the source id so output is the same each time
            doc.set_metadata({})
            doc.del_xml_metadata()
            out = doc.tobytes(deflate=True, garbage=4, no_new_id=True)
        finally:
            doc.close()
        return out

    def _stamp_page(self, page, token: str, opacity: float) -> None:
        rect = page.rect
        margin = 20.0
        usable = max(rect.width - 2 * margin, 1.0)
        # shrink the font so the whole token fits on one line
        fontsize = 11.0
        width = pymupdf.get_text_length(token, fontname="helv", fontsize=fontsize)
        if width > usable:
            # 0.98 to stay a bit off the edge
            fontsize = max(self._MIN_FONTSIZE, fontsize * usable / width * 0.98)
            width = pymupdf.get_text_length(token, fontname="helv", fontsize=fontsize)
        if width > usable:
            # too long to fit, stop instead of writing a broken mark
            raise WatermarkingError(
                f"secret too long to watermark this page: needs {width:.0f}pt at "
                f"the {self._MIN_FONTSIZE:.0f}pt floor, only {usable:.0f}pt available"
            )
        writer = pymupdf.TextWriter(rect, color=(0.5, 0.5, 0.5))
        step_x = width + 30.0
        step_y = max(fontsize * 6.0, 40.0)
        y = margin + fontsize
        while y < rect.height:
            x = margin
            placed = False
            # at least one token per row
            while not placed or x + width <= rect.width - margin:
                writer.append((x, y), token, fontsize=fontsize)
                placed = True
                x += step_x
            y += step_y
        writer.write_text(page, opacity=opacity)

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        try:
            data = load_pdf_bytes(pdf)
            doc = pymupdf.open(stream=data, filetype="pdf")
            try:
                return doc.page_count >= 1
            finally:
                doc.close()
        except Exception:
            return False

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        try:
            doc = pymupdf.open(stream=data, filetype="pdf")
        except Exception as e:  # bad/corrupt pdf
            raise WatermarkingError(f"could not open pdf: {e}") from e
        try:
            raw = "".join(page.get_text() for page in doc)
        finally:
            doc.close()
        # remove spaces the pdf text may add between letters (token has none)
        text = "".join(raw.split())
        start = text.find(self._PREFIX)
        if start == -1:
            raise SecretNotFoundError("no tiled-visible watermark found")
        end = text.find(self._SUFFIX, start)
        if end == -1:
            raise SecretNotFoundError("watermark token truncated")
        body = text[start + len(self._PREFIX):end]
        if "|" not in body:
            raise SecretNotFoundError("watermark token malformed")
        enc, mac = body.rsplit("|", 1)
        try:
            secret = base64.urlsafe_b64decode(enc.encode("ascii")).decode("utf-8")
        except Exception:
            raise SecretNotFoundError("watermark token malformed")
        if not hmac.compare_digest(mac, self._mac(secret, key)):
            raise InvalidKeyError("watermark does not validate for key")
        return secret
