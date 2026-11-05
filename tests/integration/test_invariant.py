"""The invariant (mentor's review): nothing reachable from the sandbox holds a credential that can write. Every token
the browser side could hold, replayed directly against Keycloak on every pack write and the dangerous admin writes:
all refused, no admin events. Plus: the approver relationship cannot be changed even by the broker's own account,
the one legitimate user update still works, and brute-force protection locks. Run with KEYLESS_LIVE=1."""
import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("KEYLESS_LIVE") != "1", reason="set KEYLESS_LIVE=1 (needs Docker)")


def test_nothing_reachable_from_the_sandbox_can_write():
    r = subprocess.run([sys.executable, "-W", "ignore", "-m", "devenv.invariant_probe"], capture_output=True,
                       text=True, timeout=480)
    assert "RESULT: ALL HOLD" in r.stdout, r.stdout[-2500:]
    assert "0 accepted; Keycloak admin events during the replay: 0" in r.stdout
