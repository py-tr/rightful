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


class DockerRunner:
    """The task sandbox. Per task: a private Docker network marked internal (no route anywhere) whose only other
    member is the edge proxy, which leads only to the broker and stamps the run id. Per script: a fresh container,
    no capabilities, read-only root, small /tmp, memory/CPU/pid caps, a time limit, destroyed afterwards.
    `runtime="runsc"` selects gVisor (Linux hosts; Docker Desktop on Windows has none, so the scorecard records which
    runtime was used)."""

    def __init__(self, run_id: str, ticket_text: str, upstream: str = "http://host.docker.internal:8090",
                 task_image: str = "keyless-task:dev", edge_image: str = "keyless-edge:dev", runtime: str | None = None,
                 timeout_s: int = 120, memory: str = "256m", probe_targets: dict | None = None):
        import re as _re
        self.run_id = run_id
        self.tag = _re.sub(r"[^a-z0-9-]", "-", run_id.lower())[:40]
        self.net, self.edge = f"kl-net-{self.tag}", f"kl-edge-{self.tag}"
        self.task_image, self.edge_image, self.runtime = task_image, edge_image, runtime
        self.timeout, self.memory, self.upstream = timeout_s, memory, upstream
        self.probe_targets = probe_targets or {"broker": ["host.docker.internal", 8090],
                                               "keycloak": ["host.docker.internal", 8089]}
        self.dir = tempfile.mkdtemp(prefix="keyless-task-")
        with open(os.path.join(self.dir, "ticket.txt"), "w", encoding="utf-8") as f:
            f.write(ticket_text)
        self.n = 0
        self.containers: list[str] = []

    # The sandbox's whole environment, nothing inherited from the image (e.g. the Python image's public GPG_KEY):
    CLEAN_ENV = ["env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp", "PYTHONPATH=/opt/sdk",
                 "PYTHONDONTWRITEBYTECODE=1", "GATE_URL=http://gate:8080", "TICKET_FILE=/w/ticket.txt"]

    def _docker(self, *args, input_text=None, timeout=60):
        return subprocess.run(["docker", *args], input=input_text, capture_output=True, text=True, timeout=timeout)

    def start(self) -> "DockerRunner":
        self.close()
        self._docker("network", "create", "--internal", self.net).check_returncode()
        self._docker("run", "-d", "--name", self.edge, "--read-only", "--cap-drop", "ALL",
                     "--security-opt", "no-new-privileges", "--memory", "64m", "-e", f"RUN_ID={self.run_id}",
                     "-e", f"UPSTREAM={self.upstream}", "--add-host", "host.docker.internal:host-gateway",
                     self.edge_image).check_returncode()
        self._docker("network", "connect", "--alias", "gate", self.net, self.edge).check_returncode()
        # The sandbox reaches the edge by a fixed hosts entry, not DNS: Docker's embedded DNS depends on iptables
        # rules inside the container's namespace that gVisor's network stack does not run (measured on the worker).
        ip = self._docker("inspect", "-f", "{{(index .NetworkSettings.Networks \"%s\").IPAddress}}" % self.net,
                          self.edge).stdout.strip()
        if not ip:
            raise RuntimeError("edge proxy has no address on the task network")
        self.edge_ip = ip
        return self

    TMPFS = "/tmp:rw,size=16m,noexec"
    PY = "python"
    PIDS = "64"
    CPUS = "0.5"
    EXTRA: list[str] = []

    def _sandbox_args(self, name: str) -> list[str]:
        args = ["run", "--rm", "-i", "--name", name, "--network", self.net, "--read-only",
                "--tmpfs", self.TMPFS, "--memory", self.memory, "--memory-swap", self.memory,
                "--cpus", self.CPUS, "--pids-limit", self.PIDS, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "-e", "TICKET_FILE=/w/ticket.txt", "-v", f"{self.dir}:/w:ro", *self.EXTRA]
        if getattr(self, "edge_ip", None):
            args += ["--add-host", f"gate:{self.edge_ip}"]
        if self.runtime:
            args += ["--runtime", self.runtime]
        return args

    def run(self, code: str) -> tuple[int, str, str]:
        self.n += 1
        name = f"kl-task-{self.tag}-{self.n}"
        self.containers.append(name)
        try:
            p = self._docker(*self._sandbox_args(name), self.task_image, *self.CLEAN_ENV, self.PY, "-",
                             input_text=code, timeout=self.timeout)
            return p.returncode, p.stdout[-4000:], p.stderr[-2000:]
        except subprocess.TimeoutExpired:
            self._docker("rm", "-f", name)
            return 124, "", f"timeout after {self.timeout} s: container destroyed"

    def probe(self) -> dict:
        import json as _json
        name = f"kl-probe-{self.tag}"
        args = self._sandbox_args(name)
        p = self._docker(*args, self.task_image, *self.CLEAN_ENV, f"PROBE_TARGETS={_json.dumps(self.probe_targets)}",
                         self.PY, "/opt/probe.py", timeout=60)
        try:
            out = _json.loads(p.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            out = {"error": (p.stdout + p.stderr)[-500:]}
        out["runtime"] = self.runtime or "runc (Docker default; gVisor is used on the Linux worker)"
        return out

    def close(self) -> None:
        for c in self.containers:
            self._docker("rm", "-f", c)
        self._docker("rm", "-f", self.edge)
        self._docker("network", "rm", self.net)


class BrowserRunner(DockerRunner):
    """Pattern B: headless Chromium in the task sandbox. Same internal network and edge proxy; bigger limits for the
    browser; a write-only /out for screenshots (the only thing that leaves, as image files). Chromium runs with
    --no-sandbox because its own sandbox needs privileges the container drops; the container (gVisor on the worker)
    is the sandbox."""
    TMPFS = "/tmp:rw,size=256m"
    PY = "python3"
    PIDS = "256"
    CPUS = "1.0"

    def __init__(self, run_id: str, ticket_text: str, out_dir: str, **kw):
        kw.setdefault("task_image", "keyless-browser:dev")
        kw.setdefault("memory", "1g")
        kw.setdefault("timeout_s", 180)
        super().__init__(run_id, ticket_text, **kw)
        os.makedirs(out_dir, exist_ok=True)
        self.out_dir = out_dir
        self.EXTRA = ["--shm-size", "256m", "-v", f"{out_dir}:/out:rw"]
        self.CLEAN_ENV = self.CLEAN_ENV[:2] + ["PATH=/usr/local/bin:/usr/bin:/bin",
                                               "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright"] + self.CLEAN_ENV[3:]


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
