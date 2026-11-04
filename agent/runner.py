"""Runs the agent's scripts. InProcessRunner is for tests; SubprocessRunner is for local development; the gVisor
container runner (one container per task, no route except the edge proxy) is the deployment runner."""
from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import traceback

SDK_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sdk")


class InProcessRunner:
    """Executes code in a fresh namespace with the helpdesk SDK bound to an injected client. Tests only."""

    def __init__(self, client, ticket_text: str):
        sys.path.insert(0, SDK_DIR)
        import helpdesk  # noqa: E402
        self.helpdesk = helpdesk
        helpdesk.use_client(client)
        fd, self.ticket_file = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(ticket_text)
        os.environ["TICKET_FILE"] = self.ticket_file

    def run(self, code: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        rc = 0
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                exec(compile(code, "<agent-script>", "exec"), {"__name__": "__main__", "helpdesk": self.helpdesk})
            except SystemExit as e:
                rc = int(e.code or 0)
            except Exception:
                traceback.print_exc()
                rc = 1
        return rc, out.getvalue()[-4000:], err.getvalue()[-2000:]


class SubprocessRunner:
    """Local development: a separate Python process with only the SDK on its path and no credential in its env."""

    def __init__(self, gate_url: str, run_id: str, ticket_text: str, timeout_s: int = 30):
        self.dir = tempfile.mkdtemp(prefix="keyless-task-")
        self.ticket_file = os.path.join(self.dir, "ticket.txt")
        with open(self.ticket_file, "w", encoding="utf-8") as f:
            f.write(ticket_text)
        self.env = {"PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
                    "PYTHONPATH": SDK_DIR, "GATE_URL": gate_url, "GATE_DEV_RUN": run_id,
                    "TICKET_FILE": self.ticket_file}
        self.timeout = timeout_s

    def run(self, code: str) -> tuple[int, str, str]:
        path = os.path.join(self.dir, "script.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(code)
        try:
            p = subprocess.run([sys.executable, path], cwd=self.dir, env=self.env, capture_output=True, text=True,
                               timeout=self.timeout)
            return p.returncode, p.stdout[-4000:], p.stderr[-2000:]
        except subprocess.TimeoutExpired:
            return 124, "", f"timeout after {self.timeout} s"
