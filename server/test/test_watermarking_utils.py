# tests for the method registry / dispatch layer (used by the RMAP endpoints).
# an unknown method name must raise, not fail silently.
from __future__ import annotations

from pathlib import Path

import pymupdf
import pytest

import watermarking_utils as WM
from tiled_visible_watermark import TiledVisibleWatermark
from watermarking_method import WatermarkingMethod

KEY = "utils-test-key"
SECRET = "utils-test-secret"


@pytest.fixture(scope="module")
def pdf_path(tmp_path_factory) -> Path:
    p = tmp_path_factory.mktemp("utils") / "doc.pdf"
    doc = pymupdf.open()
    doc.new_page()
    doc.save(p)
    doc.close()
    return p


# registry

def test_registry_exposes_expected_methods():
    assert {"Method 1", "Method 2", "Method 3", "Method 4", "Method 5", "Method 6", "Method 7"} <= set(WM.METHODS)


def test_get_method_by_name_returns_instance():
    m = WM.get_method("Method 7")
    assert isinstance(m, TiledVisibleWatermark)


def test_get_method_passes_instances_through():
    inst = TiledVisibleWatermark()
    assert WM.get_method(inst) is inst


def test_get_method_unknown_name_raises_with_known_list():
    with pytest.raises(KeyError) as exc:
        WM.get_method("no-such-method")
    msg = str(exc.value)
    assert "no-such-method" in msg and "Method 7" in msg


def test_register_method_adds_and_replaces():
    class Dummy(WatermarkingMethod):
        name = "unit-dummy"

        @staticmethod
        def get_usage() -> str:
            return "dummy"

        def add_watermark(self, pdf, secret, key, position=None) -> bytes:
            return b"%PDF-dummy"

        def is_watermark_applicable(self, pdf, position=None) -> bool:
            return True

        def read_secret(self, pdf, key) -> str:
            return "dummy"

    try:
        WM.register_method(Dummy())
        assert isinstance(WM.get_method("unit-dummy"), Dummy)
        replacement = Dummy()
        WM.register_method(replacement)
        assert WM.get_method("unit-dummy") is replacement
    finally:
        WM.METHODS.pop("unit-dummy", None)


# dispatch wrappers

def test_apply_and_read_roundtrip_through_registry(pdf_path):
    out = WM.apply_watermark(method="Method 7", pdf=str(pdf_path),
                             secret=SECRET, key=KEY, position=None)
    assert out.startswith(b"%PDF-")
    assert WM.read_watermark(method="Method 7", pdf=out, key=KEY) == SECRET


def test_is_watermarking_applicable_dispatches(pdf_path):
    assert WM.is_watermarking_applicable(method="Method 7", pdf=str(pdf_path)) is True


def test_wrappers_reject_unknown_method(pdf_path):
    for call in (
        lambda: WM.apply_watermark(method="nope", pdf=str(pdf_path), secret=SECRET, key=KEY),
        lambda: WM.read_watermark(method="nope", pdf=str(pdf_path), key=KEY),
        lambda: WM.is_watermarking_applicable(method="nope", pdf=str(pdf_path)),
    ):
        with pytest.raises(KeyError):
            call()


# explore_pdf

def test_explore_pdf_reports_document_and_pages(pdf_path):
    tree = WM.explore_pdf(str(pdf_path))
    assert tree["type"] == "Document"
    assert tree["id"].startswith("pdf:")
    assert tree["size"] > 0
    # keep only page nodes that have a bbox
    pages = [c for c in tree["children"] if c["type"] == "Page" and "bbox" in c]
    assert len(pages) == 1
    assert len(pages[0]["bbox"]) == 4


def test_explore_pdf_is_deterministic_for_same_bytes(pdf_path):
    assert WM.explore_pdf(str(pdf_path))["id"] == WM.explore_pdf(pdf_path.read_bytes())["id"]


def test_explore_pdf_rejects_non_pdf():
    with pytest.raises(ValueError):
        WM.explore_pdf(b"definitely not a pdf")
