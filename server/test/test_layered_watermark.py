# tests/test_layered_watermark.py
from __future__ import annotations

import io

import pikepdf
import pymupdf
import pytest

from coordinate_lsb import CoordinateLSB
from layered_watermark import LayeredWatermark
from test_coordinate_lsb import make_text_pdf
from watermarking_method import InvalidKeyError, SecretNotFoundError

SECRET = "group16::alice"
KEY = "unit-test-key"
DECOY_MAGIC = b"\n%%WM-ADD-AFTER-EOF:v1\n"


@pytest.fixture(scope="module")
def text_pdf() -> bytes:
    return make_text_pdf()


@pytest.fixture(scope="module")
def blank_pdf() -> bytes:
    doc = pymupdf.open()
    doc.new_page()
    out = doc.tobytes()
    doc.close()
    return out


@pytest.fixture(scope="module")
def wm_text(text_pdf: bytes) -> bytes:
    return LayeredWatermark().add_watermark(text_pdf, SECRET, KEY)


@pytest.fixture(scope="module")
def wm_blank(blank_pdf: bytes) -> bytes:
    return LayeredWatermark().add_watermark(blank_pdf, SECRET, KEY)


def keep_streams(pdf_bytes: bytes, predicate) -> bytes:
    """Drop page content streams failing `predicate`, preserving any post-EOF trailer."""
    trailer_at = pdf_bytes.rfind(DECOY_MAGIC)
    with pikepdf.open(io.BytesIO(pdf_bytes)) as doc:
        for page in doc.pages:
            contents = page.obj.Contents
            streams = list(contents) if isinstance(contents, pikepdf.Array) else [contents]
            page.obj.Contents = pikepdf.Array([s for s in streams if predicate(s.read_bytes())])
        buf = io.BytesIO()
        doc.save(buf)
    out = buf.getvalue()
    return out + pdf_bytes[trailer_at:] if trailer_at != -1 else out


def page_text(pdf_bytes: bytes) -> str:
    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    try:
        return "".join(p.get_text() for p in doc)
    finally:
        doc.close()


def test_all_layers_present(wm_text: bytes):
    text = page_text(wm_text)
    assert "WMK2:" in text
    assert "WM-STEALTH-v2:" in text
    assert DECOY_MAGIC in wm_text
    assert CoordinateLSB().read_secret(wm_text, KEY) == SECRET


def test_roundtrip_with_and_without_coordinate_layer(wm_text: bytes, wm_blank: bytes):
    wm = LayeredWatermark()
    assert wm.read_secret(wm_text, KEY) == SECRET
    assert wm.read_secret(wm_blank, KEY) == SECRET


def test_no_layer_exposes_plaintext(wm_text: bytes):
    assert SECRET not in "".join(page_text(wm_text).split())
    assert SECRET.encode() not in wm_text
    doc = pymupdf.open(stream=wm_text, filetype="pdf")
    try:
        streams = b"".join(doc.xref_stream(x) or b"" for x in range(1, doc.xref_length()) if doc.xref_is_stream(x))
    finally:
        doc.close()
    assert SECRET.encode() not in streams


def test_survives_text_layers_stripped(wm_text: bytes):
    # keep only the original text stream: tiled + stealth layers are gone
    stripped = keep_streams(wm_text, lambda data: b"(Line" in data)
    assert "WMK2:" not in page_text(stripped)
    assert LayeredWatermark().read_secret(stripped, KEY) == SECRET


def test_survives_coordinate_layer_destroyed(wm_text: bytes):
    # drop the original text (and with it the coordinate bits); text layers remain
    stripped = keep_streams(wm_text, lambda data: b"(Line" not in data)
    with pytest.raises(SecretNotFoundError):
        CoordinateLSB().read_secret(stripped, KEY)
    assert LayeredWatermark().read_secret(stripped, KEY) == SECRET


def test_decoy_only_is_reported(wm_blank: bytes):
    stripped = keep_streams(wm_blank, lambda data: False)
    with pytest.raises(SecretNotFoundError, match="decoy"):
        LayeredWatermark().read_secret(stripped, KEY)


def test_wrong_key(wm_text: bytes, wm_blank: bytes):
    for pdf in (wm_text, wm_blank):
        with pytest.raises(InvalidKeyError):
            LayeredWatermark().read_secret(pdf, "wrong-key")


def test_unwatermarked(text_pdf: bytes):
    with pytest.raises(SecretNotFoundError):
        LayeredWatermark().read_secret(text_pdf, KEY)


def test_deterministic(text_pdf: bytes):
    wm = LayeredWatermark()
    assert wm.add_watermark(text_pdf, SECRET, KEY) == wm.add_watermark(text_pdf, SECRET, KEY)


def test_position_is_opacity(blank_pdf: bytes):
    wm = LayeredWatermark()
    assert wm.is_watermark_applicable(blank_pdf, "25") is True
    assert wm.is_watermark_applicable(blank_pdf, "nope") is False
    with pytest.raises(ValueError):
        wm.add_watermark(blank_pdf, SECRET, KEY, position="500")


@pytest.mark.parametrize("secret,key", [("", KEY), (SECRET, "")])
def test_input_validation(blank_pdf: bytes, secret, key):
    with pytest.raises(ValueError):
        LayeredWatermark().add_watermark(blank_pdf, secret, key)
