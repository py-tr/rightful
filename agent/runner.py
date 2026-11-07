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
                 timeout_s: int = 120, memory: str = "256m", probe_targets: dict | None = None,
                 run_key: str | None = None, realm: str | None = None, docker_host: str | None = None,
                 track_lifecycle: bool = False):
        """run_key: this task's edge key, runkey.task_key(master, run_id), derived by the control plane. The edge signs
        every request with it; the broker refuses unsigned run ids when it has a master key (always, in deployment).
        realm: the realm the SDK addresses (default 'corp'; the evaluation uses a scratch realm 'eval-...').
        track_lifecycle (the public demo only; mentor 11-07, "make the containment bullets measured"): record each
        script's container id from Docker and check afterwards, on the Docker host, that the container no longer
        exists. Off for the evaluation, whose runner stays exactly as measured."""
        import re as _re
        self.run_id, self.run_key = run_id, run_key
        if realm:
            if not _re.fullmatch(r"[a-z0-9-]{1,40}", realm):
                raise ValueError("bad realm name")
            self.CLEAN_ENV = self.CLEAN_ENV + [f"GATE_REALM={realm}"]
        self.tag = _re.sub(r"[^a-z0-9-]", "-", run_id.lower())[:40]
        self.net, self.edge = f"kl-net-{self.tag}", f"kl-edge-{self.tag}"
        self.task_image, self.edge_image, self.runtime = task_image, edge_image, runtime
        self.timeout, self.memory, self.upstream = timeout_s, memory, upstream
        # What the scorecard checks is UNREACHABLE from the sandbox: by default, the real broker address (from the
        # upstream URL, so it is right on the Vultr worker too) and Keycloak on the same host.
        from urllib.parse import urlsplit as _us
        _up = _us(upstream)
        self.probe_targets = probe_targets or {"broker": [_up.hostname, _up.port or 80],
                                               "keycloak": [_up.hostname, 8089]}
        # Remote mode: DOCKER_HOST=ssh://root@<worker> means mounted paths live on the WORKER, so task files are
        # created there over the same SSH link (measured: a local temp path mounted remotely shows up empty).
        # docker_host: per instance (parallel evaluation threads drive different workers; DOCKER_HOST is process-wide)
        dh = docker_host if docker_host is not None else os.environ.get("DOCKER_HOST", "")
        self._env = {**os.environ, "DOCKER_HOST": dh} if dh else None
        self.remote = dh[len("ssh://"):] if dh.startswith("ssh://") else None
        if self.remote:
            self.dir = f"/var/lib/keyless/tasks/{self.tag}"
            self._remote(f"rm -rf {self.dir} && mkdir -p {self.dir} && cat > {self.dir}/ticket.txt", ticket_text)
        else:
            self.dir = tempfile.mkdtemp(prefix="keyless-task-")
            with open(os.path.join(self.dir, "ticket.txt"), "w", encoding="utf-8") as f:
                f.write(ticket_text)
        self.n = 0
        self.containers: list[str] = []
        self.track_lifecycle = track_lifecycle
        self.lifecycle: list[dict] = []                # per script: {"script", "id", "exit", "gone"} (measured)
        self._checks: list = []

    def _remote(self, cmd: str, input_text: str | None = None) -> subprocess.CompletedProcess:
        data = input_text.encode("utf-8") if input_text is not None else None
        p = subprocess.run(["ssh", "-o", "BatchMode=yes", self.remote, cmd], input=data, capture_output=True,
                           timeout=60)
        if p.returncode != 0:
            raise RuntimeError(f"worker command failed: {p.stderr.decode('utf-8', 'replace')[:200]}")
        return p

    # The sandbox's whole environment, nothing inherited from the image (e.g. the Python image's public GPG_KEY):
    CLEAN_ENV = ["env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp", "PYTHONPATH=/opt/sdk",
                 "PYTHONDONTWRITEBYTECODE=1", "GATE_URL=http://gate:8080", "TICKET_FILE=/w/ticket.txt"]

    def _docker(self, *args, input_text=None, timeout=60):
        return subprocess.run(["docker", *args], input=input_text, capture_output=True, text=True, timeout=timeout,
                              env=self._env)

    def _clear_docker(self) -> None:
        for c in self.containers:
            self._docker("rm", "-f", c)
        self._docker("rm", "-f", self.edge)
        self._docker("network", "rm", self.net)

    def start(self) -> "DockerRunner":
        self._clear_docker()                       # leftovers from a crashed run with the same id; keeps task files
        try:
            return self._start()
        except Exception:                          # a half-started run must not leave its network/edge behind: the
            try:                                   # caller never gets a runner to close (Fable review 11-07: ~30
                self._clear_docker()               # orphaned networks would stop every new sandbox on the worker)
            except Exception:                      # noqa: BLE001
                pass
            raise

    def _start(self) -> "DockerRunner":
        self._docker("network", "create", "--internal", self.net).check_returncode()
        self._docker("run", "-d", "--name", self.edge, "--read-only", "--cap-drop", "ALL",
                     "--security-opt", "no-new-privileges", "--memory", "64m", "-e", f"RUN_ID={self.run_id}",
                     *(["-e", f"RUN_KEY={self.run_key}"] if self.run_key else []),
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
        cidfile = None
        extra: list[str] = []
        if self.track_lifecycle:                       # the Docker CLI writes the new container's id here (client side)
            cidfile = os.path.join(tempfile.gettempdir(), f"kl-cid-{self.tag}-{self.n}-{os.getpid()}")
            with contextlib.suppress(OSError):
                os.remove(cidfile)                     # --cidfile refuses an existing file
            extra = ["--cidfile", cidfile]
        try:
            p = self._docker(*self._sandbox_args(name), *extra, self.task_image, *self.CLEAN_ENV, self.PY, "-",
                             input_text=code, timeout=self.timeout)
            rc, out, err = p.returncode, p.stdout[-4000:], p.stderr[-2000:]
        except subprocess.TimeoutExpired:
            self._docker("rm", "-f", name)
            rc, out, err = 124, "", f"timeout after {self.timeout} s: container destroyed"
        if cidfile:
            self._track(cidfile, rc)
        return rc, out, err

    def _track(self, cidfile: str, rc: int) -> None:
        cid = ""
        with contextlib.suppress(OSError):
            with open(cidfile, encoding="utf-8") as f:
                cid = f.read().strip()
            os.remove(cidfile)
        entry = {"script": self.n, "id": cid[:12], "exit": rc, "gone": None}
        self.lifecycle.append(entry)
        if not cid:
            return
        import threading

        def check():                                   # measured on the Docker host, never assumed from --rm
            import time as _t
            for attempt in range(3):                   # --rm removal can trail the CLI's return by a moment
                try:
                    q = self._docker("inspect", "--format", "{{.Id}}", cid, timeout=30)
                except Exception:                      # noqa: BLE001  unknown stays unknown, never "gone"
                    entry["gone"] = None
                    return
                if q.returncode == 0:
                    entry["gone"] = False              # Docker still lists it
                elif "no such" in (q.stderr or "").lower():
                    entry["gone"] = True               # Docker on the host: no such container
                    return
                else:
                    entry["gone"] = None               # the check itself failed: unknown, not "gone"
                    return
                _t.sleep(1.0)
        t = threading.Thread(target=check, daemon=True)
        t.start()
        self._checks.append(t)

    def lifecycle_report(self, wait_s: float = 20.0) -> list[dict]:
        """Each script's container id and whether Docker on the host says it no longer exists (True), still exists
        (False) or could not be checked (None)."""
        import time as _t
        end = _t.time() + wait_s
        for t in self._checks:
            t.join(timeout=max(0.0, end - _t.time()))
        return [dict(e) for e in self.lifecycle]

    def probe(self) -> dict:
        import json as _json
        name = f"kl-probe-{self.tag}"
        args = self._sandbox_args(name)
        try:
            p = self._docker(*args, self.task_image, *self.CLEAN_ENV, f"PROBE_TARGETS={_json.dumps(self.probe_targets)}",
                             self.PY, "/opt/probe.py", timeout=60)
        finally:
            self._docker("rm", "-f", name)            # also after a timeout (Fable review 11-07)
        try:
            out = _json.loads(p.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            out = {"error": (p.stdout + p.stderr)[-500:]}
        out["runtime_configured"] = self.runtime or "runc (Docker default; gVisor is used on the Linux worker)"
        m = out.get("measured") or {}                  # what the sandbox itself saw, never the configuration (11-06)
        out["runtime"] = (f"gVisor (measured inside the sandbox: kernel {m.get('kernel_release')})" if m.get("gvisor")
                          else f"not gVisor (measured kernel {m.get('kernel_release') or 'unknown'})")
        return out

    def close(self) -> None:
        self._clear_docker()
        if getattr(self, "remote", None) and getattr(self, "dir", "").startswith("/var/lib/keyless/tasks/"):
            try:
                self._remote(f"rm -rf {self.dir}")
            except Exception:
                pass


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
        self.out_dir = out_dir                      # where screenshots end up on the control plane / workstation
        mount = out_dir
        if self.remote:                             # write on the worker, fetch afterwards
            mount = f"{self.dir}/out"
            self._remote(f"mkdir -p {mount} && chmod 777 {mount}")
        self.mount_out = mount
        self.EXTRA = ["--shm-size", "256m", "-v", f"{mount}:/out:rw"]
        self.CLEAN_ENV = self.CLEAN_ENV[:2] + ["PATH=/usr/local/bin:/usr/bin:/bin",
                                               "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright"] + self.CLEAN_ENV[3:]

    def fetch_out(self) -> list[str]:
        """Bring the screenshots home (remote mode); returns the local file names."""
        if self.remote:
            p = self._remote(f"tar -C {self.mount_out} -cf - .")
            import io as _io
            import tarfile as _tar
            with _tar.open(fileobj=_io.BytesIO(p.stdout)) as t:
                t.extractall(self.out_dir, filter="data")
        return sorted(os.listdir(self.out_dir))


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
