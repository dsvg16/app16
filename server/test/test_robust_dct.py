"""Robustness + correctness tests for the transform-domain watermark.

These build their own synthetic image PDF (so they run without the
confidential Group_16.pdf) and re-apply the same lossy attacks used in the
manual robustness study: structural re-save, JPEG recompression, and an
image rescale round-trip. The point of robust-dct is exactly to survive the
lossy ones that defeat the LSB methods, so those are asserted here to catch
a future regression (e.g. a broken DCT matrix or a Delta that drifts too low).
"""
from __future__ import annotations

import io

import numpy as np
import pikepdf
import pytest
from PIL import Image

from robust_dct import RobustDCT
from watermarking_method import InvalidKeyError, SecretNotFoundError, WatermarkingError

SECRET = "Group_16:8d5fd801ac31681ca623572292cd226f"
KEY = "unit-test-wm-key"


def make_image_pdf(w: int = 512, h: int = 512) -> bytes:
    """A one-page PDF whose only content is a textured RGB image.

    Smooth gradients + mild noise give the mid-frequency DCT coefficients
    something to sit in, like a real photo (a flat colour would not).
    """
    rng = np.random.default_rng(0)
    yy, xx = np.mgrid[0:h, 0:w]
    r = (128 + 100 * np.sin(xx / 40.0)).astype(np.float64)
    g = (128 + 100 * np.cos(yy / 35.0)).astype(np.float64)
    b = ((xx + yy) / (w + h) * 255).astype(np.float64)
    arr = np.stack([r, g, b], axis=-1) + rng.normal(0, 6, (h, w, 3))
    img = Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8), "RGB")

    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(w, h))
    page = pdf.pages[0]
    raw = np.asarray(img, dtype=np.uint8).tobytes()
    stream = pikepdf.Stream(pdf, raw)
    stream.Type = pikepdf.Name.XObject
    stream.Subtype = pikepdf.Name.Image
    stream.Width, stream.Height = w, h
    stream.ColorSpace = pikepdf.Name.DeviceRGB
    stream.BitsPerComponent = 8
    page.Resources = pikepdf.Dictionary(XObject=pikepdf.Dictionary(Img0=stream))
    page.Contents = pdf.make_stream(b"q %d 0 0 %d 0 0 cm /Img0 Do Q" % (w, h))
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def _largest(doc: pikepdf.Pdf):
    best = None
    for page in doc.pages:
        for obj in page.images.values():
            px = int(obj.Width) * int(obj.Height)
            if best is None or px > best[0]:
                best = (px, obj)
    return best[1]


def attack_pikepdf_resave(data: bytes) -> bytes:
    with pikepdf.open(io.BytesIO(data)) as doc:
        buf = io.BytesIO()
        doc.save(buf, linearize=True)
        return buf.getvalue()


def attack_jpeg(data: bytes, quality: int) -> bytes:
    with pikepdf.open(io.BytesIO(data)) as doc:
        obj = _largest(doc)
        pil = pikepdf.PdfImage(obj).as_pil_image().convert("RGB")
        buf = io.BytesIO()
        pil.save(buf, format="JPEG", quality=quality)
        obj.write(buf.getvalue(), filter=pikepdf.Name.DCTDecode)
        obj.ColorSpace = pikepdf.Name.DeviceRGB
        obj.BitsPerComponent = 8
        for extra in (pikepdf.Name.DecodeParms, pikepdf.Name.Decode, pikepdf.Name.SMask):
            if extra in obj:
                del obj[extra]
        out = io.BytesIO()
        doc.save(out)
        return out.getvalue()


def attack_rescale(data: bytes, factor: float) -> bytes:
    import zlib
    with pikepdf.open(io.BytesIO(data)) as doc:
        obj = _largest(doc)
        pil = pikepdf.PdfImage(obj).as_pil_image().convert("RGB")
        w, h = pil.size
        small = pil.resize((max(8, int(w * factor)), max(8, int(h * factor))), Image.LANCZOS)
        back = small.resize((w, h), Image.LANCZOS)
        obj.write(zlib.compress(np.asarray(back, np.uint8).tobytes()),
                  filter=pikepdf.Name.FlateDecode)
        obj.Width, obj.Height = w, h
        obj.ColorSpace = pikepdf.Name.DeviceRGB
        obj.BitsPerComponent = 8
        for extra in (pikepdf.Name.DecodeParms, pikepdf.Name.Decode, pikepdf.Name.SMask):
            if extra in obj:
                del obj[extra]
        out = io.BytesIO()
        doc.save(out)
        return out.getvalue()


@pytest.fixture(scope="module")
def image_pdf() -> bytes:
    return make_image_pdf()


@pytest.fixture(scope="module")
def watermarked(image_pdf: bytes) -> bytes:
    return RobustDCT().add_watermark(image_pdf, SECRET, KEY)


def test_applicable_on_image_pdf(image_pdf):
    assert RobustDCT().is_watermark_applicable(image_pdf) is True


def test_not_applicable_without_image():
    pdf = pikepdf.new()
    pdf.add_blank_page()
    buf = io.BytesIO()
    pdf.save(buf)
    assert RobustDCT().is_watermark_applicable(buf.getvalue()) is False


def test_roundtrip_recovers_secret(watermarked):
    assert RobustDCT().read_secret(watermarked, KEY) == SECRET


def test_wrong_key_is_rejected(watermarked):
    with pytest.raises(InvalidKeyError):
        RobustDCT().read_secret(watermarked, "not-the-key")


def test_survives_structural_resave(watermarked):
    attacked = attack_pikepdf_resave(watermarked)
    assert RobustDCT().read_secret(attacked, KEY) == SECRET


@pytest.mark.parametrize("quality", [85, 60, 40])
def test_survives_jpeg_recompression(watermarked, quality):
    attacked = attack_jpeg(watermarked, quality)
    assert RobustDCT().read_secret(attacked, KEY) == SECRET


@pytest.mark.parametrize("factor", [0.9, 0.8, 0.7])
def test_survives_image_rescale(watermarked, factor):
    attacked = attack_rescale(watermarked, factor)
    assert RobustDCT().read_secret(attacked, KEY) == SECRET


def test_visually_quiet(image_pdf, watermarked):
    """The mark must be near-invisible (PSNR well above a visible-artifact floor)."""
    def largest_pixels(data):
        with pikepdf.open(io.BytesIO(data)) as doc:
            return np.asarray(
                pikepdf.PdfImage(_largest(doc)).as_pil_image().convert("RGB"),
                dtype=np.float64,
            )
    orig = largest_pixels(image_pdf)
    marked = largest_pixels(watermarked)
    mse = np.mean((orig - marked) ** 2)
    psnr = 99.0 if mse == 0 else 10 * np.log10(255 * 255 / mse)
    assert psnr > 32.0, f"watermark too visible: PSNR={psnr:.1f} dB"


def test_missing_watermark_is_reported(image_pdf):
    with pytest.raises((SecretNotFoundError, InvalidKeyError)):
        RobustDCT().read_secret(image_pdf, KEY)
