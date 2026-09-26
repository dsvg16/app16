# tests for the pdfwm command line tool.
# main() returns an exit code so we can call it directly.
# always pass --secret/--key, otherwise the cli asks on the terminal and blocks.
from __future__ import annotations

import json
from pathlib import Path

import pymupdf
import pytest

from watermarking_cli import build_parser, main

SECRET = "cli-test-secret"
KEY = "cli-test-key"
METHOD = "Method 7"


@pytest.fixture
def pdf(tmp_path) -> Path:
    p = tmp_path / "in.pdf"
    doc = pymupdf.open()
    doc.new_page()
    doc.save(p)
    doc.close()
    return p


def test_methods_lists_registered_methods(capsys):
    assert main(["methods"]) == 0
    out = capsys.readouterr().out
    assert METHOD in out


def test_explore_prints_json_tree(pdf, capsys):
    assert main(["explore", str(pdf)]) == 0
    tree = json.loads(capsys.readouterr().out)
    assert tree["type"] == "Document"


def test_explore_writes_json_file(pdf, tmp_path):
    out = tmp_path / "tree.json"
    assert main(["explore", str(pdf), "--out", str(out)]) == 0
    assert json.loads(out.read_text())["type"] == "Document"


def test_embed_then_extract_roundtrip(pdf, tmp_path, capsys):
    wm = tmp_path / "out.pdf"
    assert main(["embed", str(pdf), str(wm), "--method", METHOD,
                 "--secret", SECRET, "--key", KEY]) == 0
    assert wm.read_bytes().startswith(b"%PDF-")
    capsys.readouterr()  # drop the "Wrote watermarked PDF" line

    assert main(["extract", str(wm), "--method", METHOD, "--key", KEY]) == 0
    assert capsys.readouterr().out.strip() == SECRET


def test_extract_can_write_secret_to_file(pdf, tmp_path):
    wm = tmp_path / "out.pdf"
    main(["embed", str(pdf), str(wm), "--method", METHOD,
          "--secret", SECRET, "--key", KEY])
    dest = tmp_path / "secret.txt"
    assert main(["extract", str(wm), "--method", METHOD,
                 "--key", KEY, "--out", str(dest)]) == 0
    assert dest.read_text().strip() == SECRET


def test_secret_and_key_can_come_from_files(pdf, tmp_path, capsys):
    sfile, kfile = tmp_path / "s.txt", tmp_path / "k.txt"
    sfile.write_text(SECRET)
    kfile.write_text(KEY + "\n")  # trailing newline must be stripped from keys
    wm = tmp_path / "out.pdf"
    assert main(["embed", str(pdf), str(wm), "--method", METHOD,
                 "--secret-file", str(sfile), "--key-file", str(kfile)]) == 0
    capsys.readouterr()
    assert main(["extract", str(wm), "--method", METHOD, "--key", KEY]) == 0
    assert capsys.readouterr().out.strip() == SECRET


def test_missing_input_file_is_reported_not_raised(tmp_path, capsys):
    # a missing input file should fail with a message, not a crash
    rc = main(["embed", str(tmp_path / "nope.pdf"), str(tmp_path / "o.pdf"),
               "--method", METHOD, "--secret", SECRET, "--key", KEY])
    captured = capsys.readouterr()
    assert rc != 0
    assert (captured.out + captured.err).strip(), "failure must say something"
    assert not (tmp_path / "o.pdf").exists(), "must not write an output file"


def test_extract_from_unwatermarked_pdf_fails_cleanly(pdf, capsys):
    rc = main(["extract", str(pdf), "--method", METHOD, "--key", KEY])
    assert rc != 0
    assert capsys.readouterr().err  # says why, on stderr


def test_wrong_key_fails_cleanly(pdf, tmp_path, capsys):
    wm = tmp_path / "out.pdf"
    main(["embed", str(pdf), str(wm), "--method", METHOD,
          "--secret", SECRET, "--key", KEY])
    capsys.readouterr()
    assert main(["extract", str(wm), "--method", METHOD, "--key", "wrong"]) != 0


def test_parser_requires_a_subcommand():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])
