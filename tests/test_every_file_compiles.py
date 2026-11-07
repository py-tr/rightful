"""Every Python file in the repo must at least compile (11-07: a quoting slip made deploy/vultr_deploy.py unparseable,
and no unit test imported it)."""
import pathlib
import py_compile

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
FILES = [p for d in ("agent", "broker", "gate", "demo", "deploy", "devenv", "eval", "sandbox", "tests")
         for p in (ROOT / d).rglob("*.py") if "__pycache__" not in p.parts]


@pytest.mark.parametrize("path", FILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_compiles(path):
    py_compile.compile(str(path), doraise=True)


def test_measured_rates_carry_the_fingerprint_of_the_running_setup():
    """The fool rate the page prints must have been measured on the setup that is running (mentor, 11-07); a change to
    the prompt, the left column's help text, the measured scenarios or the pack makes the page say "earlier version"
    until the measurement is re-run and its fingerprint stored."""
    from demo.scenarios import SCENARIOS
    from demo.server import setup_fingerprint
    assert SCENARIOS["takeover"]["measured"].get("setup") == setup_fingerprint(), \
        "re-measure (eval/demo_setup.py) and store the new fingerprint in demo/scenarios.py"
