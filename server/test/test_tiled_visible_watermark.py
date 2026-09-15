from __future__ import annotations

from pathlib import Path

import pymupdf
import pytest

import watermarking_utils as WM
from tiled_visible_watermark import TiledVisibleWatermark
from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
)

SECRET = "Group_03"
KEY = "unit-test-wm-key"

REPO_ROOT = Path(__file__).resolve().parents[2]
GROUP_PDF = REPO_ROOT / "Group_16.pdf"


@pytest.fixture
def pdf_bytes() -> bytes:
    # use the real Group_16.pdf if it is here, else make a small pdf so CI works
    if GROUP_PDF.exists():
        return GROUP_PDF.read_bytes()
    doc = pymupdf.open()
    doc.new_page()
    try:
        return doc.tobytes()
    finally:
        doc.close()


@pytest.fixture
def method() -> TiledVisibleWatermark:
    return TiledVisibleWatermark()


def test_registered():
    assert WM.METHODS.get("tiled-visible").__class__ is TiledVisibleWatermark


def test_applicable(method, pdf_bytes):
    assert method.is_watermark_applicable(pdf_bytes) is True


def test_roundtrip(method, pdf_bytes):
    wm = method.add_watermark(pdf_bytes, SECRET, KEY)
    assert wm.startswith(b"%PDF-")
    assert method.read_secret(wm, KEY) == SECRET


def test_wrong_key_rejected(method, pdf_bytes):
    wm = method.add_watermark(pdf_bytes, SECRET, KEY)
    with pytest.raises(InvalidKeyError):
        method.read_secret(wm, "not-the-key")


def test_unwatermarked_raises(method, pdf_bytes):
    with pytest.raises(SecretNotFoundError):
        method.read_secret(pdf_bytes, KEY)


def test_deterministic(method, pdf_bytes):
    assert method.add_watermark(pdf_bytes, SECRET, KEY) == method.add_watermark(
        pdf_bytes, SECRET, KEY
    )


def test_rmap_shaped_secret_roundtrips(method, pdf_bytes):
    # a long RMAP-style secret (group name + link)
    secret = "Group_16:" + "a1b2c3d4" * 4
    assert method.read_secret(method.add_watermark(pdf_bytes, secret, KEY), KEY) == secret


def test_long_secret_within_capacity_roundtrips(method, pdf_bytes):
    secret = "X" * 120
    assert method.read_secret(method.add_watermark(pdf_bytes, secret, KEY), KEY) == secret


def test_oversized_secret_fails_loudly(method, pdf_bytes):
    # too long to fit should raise, not write a broken mark
    with pytest.raises(WatermarkingError):
        method.add_watermark(pdf_bytes, "X" * 400, KEY)


def test_secret_with_spaces_roundtrips(method, pdf_bytes):
    # secret with spaces/newline must survive (base64 handles it)
    secret = "Group 03 leaked\tthis"
    assert method.read_secret(method.add_watermark(pdf_bytes, secret, KEY), KEY) == secret


def test_corrupt_pdf_raises_watermarking_error(method):
    # starts with %PDF- but is broken -> clean error, not a raw pymupdf traceback
    bad = b"%PDF-1.4 broken junk not really a pdf"
    with pytest.raises(WatermarkingError):
        method.add_watermark(bad, SECRET, KEY)
    with pytest.raises(WatermarkingError):
        method.read_secret(bad, KEY)


def test_empty_secret_rejected(method, pdf_bytes):
    with pytest.raises(ValueError):
        method.add_watermark(pdf_bytes, "", KEY)


@pytest.mark.skipif(not GROUP_PDF.exists(), reason="Group_16.pdf not present")
def test_reportlab_source_roundtrip(method):
    wm = method.add_watermark(GROUP_PDF.read_bytes(), SECRET, KEY)
    assert method.read_secret(wm, KEY) == SECRET
