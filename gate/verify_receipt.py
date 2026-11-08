"""Check a shared demo run offline.

    python -m gate.verify_receipt run.json                      # the signature matches the key inside the record
    python -m gate.verify_receipt run.json --url https://<site> # ...and that key is the one the site publishes

Download run.json from https://<site>/api/proof/<token> (the "Share this result" link's data). Change any byte of it
and this says INVALID.
"""
from __future__ import annotations

import argparse
import json
import sys

from gate.receipt_sign import verify


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--url", help="the demo site; its /api/receipt-key is fetched and must match")
    ap.add_argument("--key", help="a public key (base64) you already trust, instead of --url")
    a = ap.parse_args(argv)
    with open(a.file, encoding="utf-8-sig") as f:      # a file saved on Windows may start with a BOM
        rec = json.load(f)
    trusted = a.key
    if a.url:
        import httpx
        trusted = httpx.get(a.url.rstrip("/") + "/api/receipt-key", timeout=15).json()["public_key"]
    bad = 0
    for name, r in (("this run", rec), ("the paired column", rec.get("other"))):
        if not r:
            continue
        ok, why = verify(r, trusted)
        print(f"{'VALID  ' if ok else 'INVALID'} {name}: {why}")
        bad += not ok
    if not trusted:   # review 11-08 m9: without the site's key, anyone could re-sign an edited record with their own
        print("NOTE: the key was not checked against the site; use --url <site> (or --key) to check who signed it")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
