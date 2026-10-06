from __future__ import annotations

import pymupdf
import pytest

from tiled_visible_watermark import TiledVisibleWatermark

SECRET = "Group_09:leaked"
KEY = "unit-test-wm-key"


@pytest.fixture
def method():
    return TiledVisibleWatermark()


def _doc_with_texts(lines):
    # build a tiny pdf whose visible text is exactly `lines`, top to bottom
    doc = pymupdf.open()
    page = doc.new_page()
    y = 30.0
    for t in lines:
        page.insert_text((20, y), t)
        y += 30.0
    blob = doc.tobytes()
    doc.close()
    return blob


def test_skips_bad_base64_candidate_before_valid(method):
    # A malformed token (invalid base64) placed BEFORE a valid one must be
    # skipped (continue), not end the scan (break). Kills the base64 continue->break mutant.
    valid = method._token(SECRET, KEY)
    # "ABCDE" is 5 base64 chars -> decode raises (length can't be 1 mod 4),
    # so this exercises the except branch (which must continue, not break).
    bad = f"{method._PREFIX}ABCDE|deadbeef{method._SUFFIX}"
    blob = _doc_with_texts([bad, valid])
    assert method.read_secret(blob, KEY) == SECRET


def test_skips_candidate_without_pipe_before_valid(method):
    # A token with no '|' before a valid one must be skipped, not stop the scan.
    # Kills the '|' not in body continue->break mutant.
    valid = method._token(SECRET, KEY)
    nopipe = f"{method._PREFIX}nopipehere{method._SUFFIX}"
    blob = _doc_with_texts([nopipe, valid])
    assert method.read_secret(blob, KEY) == SECRET
