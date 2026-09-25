"""layered_watermark.py

Defence-in-depth watermark stacking three independent layers, each carrying
its own AES-GCM-sealed copy of the secret (see ``wm_crypto``):

1. coordinate-LSB: bits hidden in the 1/100 pt digits of the original text
   positions. Invisible and absent from text extraction. Skipped when the
   PDF has too little text to hold the payload.
2. tiled-visible: a faint sealed token tiled over every page. Deters leaking
   and is hard to scrub without visibly damaging the page.
3. honey-microspacing: the sealed token as invisible 0.01 pt text, plus a
   decoy post-EOF trailer that looks like a toy-eof watermark but carries
   only a honey-token.

Order matters: coordinate-LSB rewrites the original content streams via
pikepdf, PyMuPDF then only appends new streams (leaving those digits
intact), and the decoy trailer goes last because re-saving would drop it.

read_secret accepts the first layer that authenticates, so the secret
survives as long as any one layer does.
"""

from __future__ import annotations

import base64
import binascii
from typing import Final

try:
    import pymupdf
except ImportError:
    import fitz as pymupdf

import wm_crypto
from coordinate_lsb import CoordinateLSB
from honey_microspacing_watermark import HoneyMicrospacingWatermark
from robust_dct import RobustDCT
from tiled_visible_watermark import TiledVisibleWatermark
from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class LayeredWatermark(WatermarkingMethod):
    name: Final[str] = "layered"

    # (prefix, suffix, AEAD context) for each text layer
    _VISIBLE: Final = ("WMK2:", ":2KMW", b"wm:layered:visible:v1")
    _STEALTH: Final = ("WM-STEALTH-v2:", ":2v-HTLAETS-MW", b"wm:layered:stealth:v1")

    def __init__(self) -> None:
        self._coord = CoordinateLSB()
        self._tiled = TiledVisibleWatermark()
        self._honey = HoneyMicrospacingWatermark()
        self._robust = RobustDCT()

    @staticmethod
    def get_usage() -> str:
        return (
            "Three layers, each with an AES-GCM-encrypted secret: coordinate-LSB "
            "(invisible, when the PDF has enough text), a faint tiled visible token, "
            "and invisible micro-text plus a decoy trailer. Reading succeeds if any "
            "layer survives. position (optional): visible-layer opacity percent 1-100 "
            "(default 10)."
        )

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        return self._tiled.is_watermark_applicable(pdf, position)

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
        opacity = self._tiled._opacity(position)
        data = load_pdf_bytes(pdf)

        if self._coord.capacity_bits(data) >= self._coord.bits_needed(secret):
            data = self._coord.add_watermark(data, secret, key)

        visible = self._token(self._VISIBLE, secret, key)
        stealth = self._token(self._STEALTH, secret, key)
        try:
            doc = pymupdf.open(stream=data, filetype="pdf")
        except Exception as exc:
            raise WatermarkingError(f"could not open PDF: {exc}") from exc
        try:
            if doc.page_count < 1:
                raise WatermarkingError("PDF contains no pages to watermark")
            for page in doc:
                self._tiled._stamp_page(page, visible, opacity)
                page.insert_text(
                    pymupdf.Point(1, 1), stealth, fontsize=0.01, render_mode=3, fontname="helv"
                )
            doc.set_metadata({})
            doc.del_xml_metadata()
            out = doc.tobytes(deflate=True, garbage=4, no_new_id=True)
        finally:
            doc.close()

        # Robust image layer: survives JPEG recompression / re-encoding that
        # wipes the text-plane layers. Runs last (its pikepdf save would drop a
        # post-EOF trailer, so it must precede the decoy append) and is
        # best-effort: a PDF with no usable image simply keeps the other layers.
        try:
            if self._robust.is_watermark_applicable(out):
                out = self._robust.add_watermark(out, secret, key)
        except (WatermarkingError, ValueError):
            pass

        if not out.endswith(b"\n"):
            out += b"\n"
        return out + self._honey._DECOY_MAGIC + self._honey._build_decoy_trailer(secret, key) + b"\n"

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        data = load_pdf_bytes(pdf)
        wrong_key = False

        # Try the robust image layer first: it is the one most likely to have
        # survived a lossy attack that stripped the text-plane layers.
        try:
            return self._robust.read_secret(data, key)
        except InvalidKeyError:
            wrong_key = True
        except (SecretNotFoundError, WatermarkingError):
            pass

        try:
            return self._coord.read_secret(data, key)
        except InvalidKeyError:
            wrong_key = True
        except WatermarkingError:
            pass

        try:
            doc = pymupdf.open(stream=data, filetype="pdf")
        except Exception as exc:
            raise WatermarkingError(f"could not open PDF: {exc}") from exc
        try:
            text = "".join("".join(page.get_text() for page in doc).split())
        finally:
            doc.close()

        for prefix, suffix, context in (self._STEALTH, self._VISIBLE):
            for blob in self._candidates(text, prefix, suffix):
                try:
                    return wm_crypto.unseal(blob, key, context)
                except InvalidKeyError:
                    wrong_key = True

        if wrong_key:
            raise InvalidKeyError("key failed to authenticate any watermark layer")
        if self._honey._DECOY_MAGIC in data:
            raise SecretNotFoundError("only the decoy trailer is present; real layers were stripped")
        raise SecretNotFoundError("no layered watermark found")

    @staticmethod
    def _token(layer, secret: str, key: str) -> str:
        prefix, suffix, context = layer
        sealed = wm_crypto.seal(secret, key, context)
        return prefix + base64.urlsafe_b64encode(sealed).decode("ascii") + suffix

    @staticmethod
    def _candidates(text: str, prefix: str, suffix: str):
        pos = 0
        while (start := text.find(prefix, pos)) != -1:
            end = text.find(suffix, start + len(prefix))
            if end == -1:
                return
            pos = end + len(suffix)
            try:
                yield base64.urlsafe_b64decode(text[start + len(prefix):end].encode("ascii"))
            except (binascii.Error, ValueError):
                continue


__all__ = ["LayeredWatermark"]
