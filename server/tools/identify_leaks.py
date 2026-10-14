#!/usr/bin/env python3
"""Work out which group a leaked copy of our RMAP PDF was issued to.

RMAP hands every group the source PDF watermarked with "Method 5"
(layered_watermark.py) and the secret "<group identity>:<rmap link>".
This tool cross-checks suspect PDFs in up to four ways:

  1. inspect   (no key)  which watermark layers survived, and whether two
                         files carry the same token (= same recipient)
  2. storage   (no key)  sha256 match against the copies the server saved
                         in STORAGE_DIR/rmap/<link>.pdf  -> link
  3. versions  (no key)  map a link to its group using a CSV export of
                         the Versions table (intended_for,link)
  4. decode    (key)     decrypt the hidden secret with RMAP_WM_KEY
                         -> "<group>:<link>"

Usage:
  python identify_leaks.py leak1.pdf leak2.pdf ...
      [--key KEY | env RMAP_WM_KEY] [--try-keys wordlist.txt]
      [--storage /app/storage/rmap] [--versions versions.csv]
      [--src /app/src]
      [--pdf-dir DIR --csv in.csv --csv-out out.csv]   fill Intended_for in a CSV
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_SRC = next(
    (p for p in (Path("/app/src"), HERE.parent / "src") if (p / "layered_watermark.py").exists()),
    HERE.parent / "src",
)

VISIBLE = re.compile(r"WMK2:([A-Za-z0-9_\-=]+):2KMW")
STEALTH = re.compile(r"WM-STEALTH-v2:([A-Za-z0-9_\-=]+):2v-HTLAETS-MW")
DECOY = b"\n%%WM-ADD-AFTER-EOF:v1\n"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect(path: Path) -> dict:
    import pymupdf

    data = path.read_bytes()
    doc = pymupdf.open(stream=data, filetype="pdf")
    try:
        text = "".join("".join(p.get_text() for p in doc).split())
        producer = doc.metadata.get("producer") or ""
        pages = doc.page_count
    finally:
        doc.close()
    vis = set(VISIBLE.findall(text))
    stl = set(STEALTH.findall(text))
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "pages": pages,
        "producer": producer,
        "visible": vis,
        "stealth": stl,
        "decoy": DECOY in data,
        "has_text": bool(text),
    }


def load_versions(csv_path: Path) -> dict[str, str]:
    with csv_path.open(newline="") as f:
        sample = f.read(2048)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;")
        rows = csv.DictReader(f, dialect=dialect)
        return {r["link"].strip(): r["intended_for"].strip() for r in rows if r.get("link")}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pdfs", nargs="*", type=Path)
    ap.add_argument("--pdf-dir", type=Path, help="also check every *.pdf in this directory")
    ap.add_argument("--csv", type=Path, help="CSV with FileName,Intended_for columns to fill in")
    ap.add_argument("--csv-out", type=Path, help="where to write the filled CSV (default: <csv>.filled.csv)")
    ap.add_argument("--key", default=os.environ.get("RMAP_WM_KEY"))
    ap.add_argument("--try-keys", type=Path, help="file with one candidate key per line")
    ap.add_argument("--storage", type=Path, help="directory of server-issued copies (STORAGE_DIR/rmap)")
    ap.add_argument("--versions", type=Path, help="CSV export of Versions with intended_for,link columns")
    ap.add_argument("--src", type=Path, default=DEFAULT_SRC, help="Tatou server/src directory")
    args = ap.parse_args()

    sys.path.insert(0, str(args.src))

    pdfs = list(args.pdfs)
    if args.pdf_dir:
        pdfs += sorted(args.pdf_dir.glob("*.pdf"))
    if args.csv:
        with args.csv.open(newline="", encoding="utf-8-sig") as f:
            wanted = [r["FileName"].strip() for r in csv.DictReader(f)]
        have = {p.name for p in pdfs}
        pdfs += [args.csv.parent / n for n in wanted
                 if n not in have and (args.csv.parent / n).is_file()]
    if not pdfs:
        ap.error("no PDFs given (list them, or use --pdf-dir / --csv)")

    keys: list[str] = [args.key] if args.key else []
    if args.try_keys:
        keys += [k.strip() for k in args.try_keys.read_text().splitlines() if k.strip()]

    stored: dict[str, str] = {}
    if args.storage:
        for p in args.storage.glob("*.pdf"):
            stored[sha256(p)] = p.stem  # file name is the link
    versions = load_versions(args.versions) if args.versions else {}

    wm = None
    if keys:
        from layered_watermark import LayeredWatermark
        wm = LayeredWatermark()

    seen_tokens: dict[str, list[str]] = {}
    identity: dict[str, str] = {}  # file name -> recovered group
    for path in pdfs:
        try:
            info = inspect(path)
        except Exception as e:  # corrupt / not a PDF
            print(f"\n=== {path.name}\n  unreadable ({type(e).__name__}: {e})")
            continue
        print(f"\n=== {path.name}")
        print(f"  sha256       {info['sha256']}")
        print(f"  producer     {info['producer'] or '-'}   pages {info['pages']}")
        print(f"  visible WMK2 {'yes' if info['visible'] else 'NO'}   "
              f"stealth {'yes' if info['stealth'] else 'NO'}   decoy {'yes' if info['decoy'] else 'NO'}")
        if not (info["visible"] or info["stealth"] or info["decoy"]):
            note = "rasterised (no text layer)" if not info["has_text"] else "text present but no tokens"
            print(f"  -> text layers stripped: {note}; only the robust image layer could survive")
        for tok in info["visible"] | info["stealth"]:
            seen_tokens.setdefault(tok, []).append(path.name)

        link = group = None
        if info["sha256"] in stored:
            link = stored[info["sha256"]]
            print(f"  storage      exact match -> link {link}  (file was not modified)")
        elif stored:
            print("  storage      no exact match (file modified after download)")

        if wm:
            for k in keys:
                try:
                    secret = wm.read_secret(str(path), k)
                except Exception as e:  # wrong key, stripped, or unreadable
                    last = f"{type(e).__name__}: {e}"
                    continue
                group, _, link = secret.partition(":")
                print(f"  decoded      group {group}   link {link}")
                break
            else:
                print(f"  decoded      failed ({last})")

        if link and not group and versions:
            group = versions.get(link)
        if group:
            identity[path.name] = group
            print(f"  >>> ISSUED TO: {group}")
        elif link and versions:
            print("  >>> link not found in versions CSV")

    shared = {tuple(f) for f in seen_tokens.values() if len(f) > 1}
    print("\n=== cross-check")
    if shared:
        for files in sorted(shared):
            print(f"  same recipient: {', '.join(files)}")
    else:
        marked = {f for files in seen_tokens.values() for f in files}
        print(f"  {len(marked)} watermarked file(s), all with different tokens "
              "-> each went to a different group")

    if args.csv:
        out = args.csv_out or args.csv.with_suffix(".filled.csv")
        with args.csv.open(newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            fields = reader.fieldnames or ["FileName", "Intended_for"]
            rows = list(reader)
        for r in rows:
            name = r["FileName"].strip()
            r["Intended_for"] = identity.get(name) or identity.get(name + ".pdf") or "Unknown"
        with out.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
        known = sum(r["Intended_for"] != "Unknown" for r in rows)
        print(f"\n=== wrote {out}: {known} identified, {len(rows) - known} Unknown, {len(rows)} rows")
    return 0


if __name__ == "__main__":
    sys.exit(main())
