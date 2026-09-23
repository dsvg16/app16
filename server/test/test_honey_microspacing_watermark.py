# tests/test_honey_microspacing_watermark.py
from __future__ import annotations

from pathlib import Path
import pymupdf
import pytest

from honey_microspacing_watermark import HoneyMicrospacingWatermark
from watermarking_method import InvalidKeyError, SecretNotFoundError, WatermarkingError


@pytest.fixture
def sample_pdf(tmp_path: Path) -> Path:
    pdf_path = tmp_path / "sample.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((100, 100), "Confidential Internal Report", fontsize=12)
    doc.save(pdf_path)
    doc.close()
    return pdf_path


@pytest.fixture
def empty_page_pdf(tmp_path: Path) -> Path:
    pdf_path = tmp_path / "empty_page.pdf"
    doc = pymupdf.open()
    doc.new_page()
    doc.save(pdf_path)
    doc.close()
    return pdf_path


def test_usage_description():
    usage = HoneyMicrospacingWatermark.get_usage()
    assert isinstance(usage, str)
    assert len(usage) > 10


def test_applicability(sample_pdf: Path):
    wm = HoneyMicrospacingWatermark()
    assert wm.is_watermark_applicable(sample_pdf) is True
    assert wm.is_watermark_applicable(b"not-a-pdf") is False


def test_roundtrip_extraction(sample_pdf: Path):
    wm = HoneyMicrospacingWatermark()
    secret = "employee_id:98765-audit-trace"
    key = "super-secret-hmac-key"

    watermarked_bytes = wm.add_watermark(sample_pdf, secret=secret, key=key)
    assert watermarked_bytes.startswith(b"%PDF-")
    assert b"%%WM-ADD-AFTER-EOF:v1" in watermarked_bytes

    recovered = wm.read_secret(watermarked_bytes, key=key)
    assert recovered == secret


def test_resilience_to_decoy_stripping(sample_pdf: Path):
    """Adversary strips bytes after %%EOF; stealth watermark inside PDF must still verify."""
    wm = HoneyMicrospacingWatermark()
    secret = "covert_identifier_alpha_1"
    key = "analyst-key"

    watermarked_bytes = wm.add_watermark(sample_pdf, secret=secret, key=key)

    # Adversary finds %%EOF and strips trailing decoy trailer
    eof_idx = watermarked_bytes.rfind(b"%%EOF")
    assert eof_idx != -1
    stripped_bytes = watermarked_bytes[:eof_idx + 5] + b"\n"

    assert b"%%WM-ADD-AFTER-EOF:v1" not in stripped_bytes

    # The stealth watermark inside the content stream should still be recoverable!
    recovered = wm.read_secret(stripped_bytes, key=key)
    assert recovered == secret


def test_invalid_key_raises_error(sample_pdf: Path):
    wm = HoneyMicrospacingWatermark()
    secret = "classified-data"
    key = "correct-key"
    wrong_key = "attacker-guessing-key"

    watermarked_bytes = wm.add_watermark(sample_pdf, secret=secret, key=key)

    with pytest.raises(InvalidKeyError):
        wm.read_secret(watermarked_bytes, key=wrong_key)


def test_unwatermarked_pdf_raises_error(sample_pdf: Path):
    wm = HoneyMicrospacingWatermark()
    with pytest.raises(SecretNotFoundError):
        wm.read_secret(sample_pdf, key="some-key")


def test_decoy_only_raises_error(sample_pdf: Path):
    """If PDF contains only the decoy trailer but no stealth payload, it raises SecretNotFoundError."""
    wm = HoneyMicrospacingWatermark()
    # Create fake decoy-only PDF
    pdf_bytes = sample_pdf.read_bytes() + b"\n%%WM-ADD-AFTER-EOF:v1\neyJhbGciOiJITUFDLVNIQTI1NiJ9\n"

    with pytest.raises(SecretNotFoundError) as exc_info:
        wm.read_secret(pdf_bytes, key="some-key")
    assert "Decoy watermark detected" in str(exc_info.value)


def test_input_validation(sample_pdf: Path):
    wm = HoneyMicrospacingWatermark()
    with pytest.raises(ValueError):
        wm.add_watermark(sample_pdf, secret="", key="key")

    with pytest.raises(ValueError):
        wm.add_watermark(sample_pdf, secret="secret", key="")

    with pytest.raises(ValueError):
        wm.read_secret(sample_pdf, key="")
