"""Regression guard for a MEASURED bypass (mentor code review, 2026-11-05): paths that start with a console prefix
and walk back to the admin API reset the CFO's password with the console token swapped in. Run with KEYLESS_LIVE=1."""
import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("KEYLESS_LIVE") != "1", reason="set KEYLESS_LIVE=1 (needs Docker)")


def test_console_route_cannot_reach_the_admin_api():
    r = subprocess.run([sys.executable, "-W", "ignore", "-m", "devenv.console_route_probe"], capture_output=True,
                       text=True, timeout=480)
    assert "browser got a (signature-broken) token: True" in r.stdout, r.stdout[-800:]
    assert "no reset reached Keycloak" in r.stdout and "BYPASS" not in r.stdout, r.stdout[-1500:]
