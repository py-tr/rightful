"""Keyless gate: the sandbox holds no credential; account changes need a receipt from the owner's approval."""
import json
import pathlib

from .gate import Decision, Gate
from .grammar import Operation, Reject, parse
from .ledger import Ledger, LedgerError, verify
from .receipts import ReceiptStore


def load_pack(name_or_path: str) -> dict:
    p = pathlib.Path(name_or_path)
    if not p.exists():
        p = pathlib.Path(__file__).resolve().parent.parent / "packs" / f"{name_or_path}.json"
    return json.loads(p.read_text(encoding="utf-8"))


__all__ = ["Decision", "Gate", "Operation", "Reject", "parse", "Ledger", "LedgerError", "verify", "ReceiptStore",
           "load_pack"]
