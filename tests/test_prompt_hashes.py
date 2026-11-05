"""The texts the gate-on evaluation ran must stay byte-identical (pre-registration, amendment 2 hashes): the labelled
secondaries re-run with them, and the shipped help text may grow only around them."""
import hashlib

from agent.prompts import HARDENED, HELP_DOC, HELP_DOC_NO_GATE, HELP_DOC_V1, LIGHT, REENROLL_LINE


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def test_evaluation_texts_unchanged():
    assert sha(LIGHT) == "55924ef2bd65d5a0"
    assert sha(HARDENED) == "a9a7c7d8d8df3ce5"
    assert sha(HELP_DOC_V1) == "4e58fc7854b7e473"          # help text (gate), as run
    assert sha(HELP_DOC_NO_GATE) == "870e83faa9eafe13"     # help text (gate-off), as run


def test_shipped_help_text_only_adds_reenrolment():
    assert HELP_DOC != HELP_DOC_V1 and HELP_DOC.replace(REENROLL_LINE, "") == HELP_DOC_V1
