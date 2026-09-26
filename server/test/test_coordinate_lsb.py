# tests/test_coordinate_lsb.py
from __future__ import annotations

import io

import pikepdf
import pytest

from coordinate_lsb import CoordinateLSB, _MAGIC, _bits_to_bytes
from watermarking_method import InvalidKeyError, SecretNotFoundError, WatermarkingError

SECRET = "group16::alice"
KEY = "unit-test-key"


def make_text_pdf(lines: int = 150) -> bytes:
    """One page with `lines` text objects, each using Tm and Td (4 carrier bits per line)."""
    pdf = pikepdf.new()
    pdf.add_blank_page()
    font = pdf.make_indirect(pikepdf.Dictionary(
        Type=pikepdf.Name.Font, Subtype=pikepdf.Name.Type1, BaseFont=pikepdf.Name.Helvetica,
    ))
    page = pdf.pages[0]
    page.Resources = pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=font))
    body = b"".join(
        b"BT /F1 4 Tf 1 0 0 1 20 %d Tm 0 0 Td (Line %d) Tj ET\n" % (780 - i * 5, i)
        for i in range(lines)
    )
    page.Contents = pdf.make_stream(body)
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


@pytest.fixture(scope="module")
def text_pdf() -> bytes:
    return make_text_pdf()


@pytest.fixture(scope="module")
def blank_pdf() -> bytes:
    pdf = pikepdf.new()
    pdf.add_blank_page()
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


@pytest.fixture(scope="module")
def watermarked(text_pdf: bytes) -> bytes:
    return CoordinateLSB().add_watermark(text_pdf, SECRET, KEY)


def tm_operands(pdf_bytes: bytes) -> list[list[float]]:
    with pikepdf.open(io.BytesIO(pdf_bytes)) as doc:
        return [
            [float(x) for x in operands]
            for operands, op in pikepdf.parse_content_stream(doc.pages[0])
            if bytes(op) == b"Tm"
        ]


# def test_usage_is_static():
#     assert "AES-GCM" in CoordinateLSB.get_usage()


def test_applicability(text_pdf: bytes, blank_pdf: bytes):
    wm = CoordinateLSB()
    assert wm.is_watermark_applicable(text_pdf) is True
    assert wm.is_watermark_applicable(blank_pdf) is False
    assert wm.is_watermark_applicable(b"not-a-pdf") is False


def test_roundtrip(watermarked: bytes):
    assert CoordinateLSB().read_secret(watermarked, KEY) == SECRET


def test_unicode_roundtrip(text_pdf: bytes):
    wm = CoordinateLSB()
    assert wm.read_secret(wm.add_watermark(text_pdf, "üñï©ødé", KEY), KEY) == "üñï©ødé"


def test_secret_is_encrypted(watermarked: bytes):
    with pikepdf.open(io.BytesIO(watermarked)) as doc:
        data = _bits_to_bytes(CoordinateLSB()._extract_bits(doc))
    assert data.startswith(_MAGIC)
    assert SECRET.encode() not in data


def test_wrong_key_raises_invalid_key(watermarked: bytes):
    with pytest.raises(InvalidKeyError):
        CoordinateLSB().read_secret(watermarked, "wrong-key")


def test_tampered_payload_rejected(watermarked: bytes):
    # 6 instructions per line (BT Tf Tm Td Tj ET); line 60's Tm carries bits 240-241,
    # which fall inside the ciphertext rather than the plaintext header
    target = 6 * 60 + 2
    with pikepdf.open(io.BytesIO(watermarked)) as doc:
        rebuilt = []
        for i, (operands, op) in enumerate(pikepdf.parse_content_stream(doc.pages[0])):
            operands = list(operands)
            if i == target:
                assert bytes(op) == b"Tm"
                operands[5] = float(operands[5]) + 0.01
            rebuilt.append((operands, op))
        doc.pages[0].Contents = doc.make_stream(pikepdf.unparse_content_stream(rebuilt))
        buf = io.BytesIO()
        doc.save(buf)
    with pytest.raises(InvalidKeyError):
        CoordinateLSB().read_secret(buf.getvalue(), KEY)


def test_only_translations_are_modified(text_pdf: bytes, watermarked: bytes):
    before, after = tm_operands(text_pdf), tm_operands(watermarked)
    assert [m[:4] for m in before] == [m[:4] for m in after]
    assert any(b[4:] != a[4:] for b, a in zip(before, after))
    assert all(abs(x - y) <= 0.0100001 for b, a in zip(before, after) for x, y in zip(b, a))


def test_deterministic(text_pdf: bytes):
    wm = CoordinateLSB()
    assert wm.add_watermark(text_pdf, SECRET, KEY) == wm.add_watermark(text_pdf, SECRET, KEY)


def test_survives_resave(watermarked: bytes):
    with pikepdf.open(io.BytesIO(watermarked)) as doc:
        buf = io.BytesIO()
        doc.save(buf, compress_streams=True, object_stream_mode=pikepdf.ObjectStreamMode.generate)
    assert CoordinateLSB().read_secret(buf.getvalue(), KEY) == SECRET


def test_unwatermarked_pdf(text_pdf: bytes):
    with pytest.raises(SecretNotFoundError):
        CoordinateLSB().read_secret(text_pdf, KEY)


@pytest.mark.parametrize("secret,key", [("", KEY), (SECRET, ""), (None, KEY), (SECRET, None)])
def test_input_validation(text_pdf: bytes, secret, key):
    with pytest.raises(ValueError):
        CoordinateLSB().add_watermark(text_pdf, secret, key)


def test_read_requires_key(watermarked: bytes):
    with pytest.raises(ValueError):
        CoordinateLSB().read_secret(watermarked, "")


def test_capacity_exceeded(text_pdf: bytes):
    with pytest.raises(WatermarkingError, match="capacity"):
        CoordinateLSB().add_watermark(text_pdf, "x" * 500, KEY)


def test_corrupt_pdf_errors_are_wrapped():
    corrupt = b"%PDF-1.7\nthis is not a real pdf body"
    with pytest.raises(WatermarkingError):
        CoordinateLSB().add_watermark(corrupt, SECRET, KEY)
    with pytest.raises(WatermarkingError):
        CoordinateLSB().read_secret(corrupt, KEY)
