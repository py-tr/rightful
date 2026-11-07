"""The demo's per-script lifecycle (mentor 11-07: "make the containment bullets measured"): the container id comes from
Docker, and "gone" is only reported when Docker on the host says there is no such container; a failed check stays
unknown, never "gone"."""
import subprocess
import types

from agent.runner import DockerRunner


def _runner(inspect_results):
    r = DockerRunner.__new__(DockerRunner)               # no Docker needed: only the bookkeeping is under test
    r.tag, r.n, r.lifecycle, r._checks, r.track_lifecycle = "t", 0, [], [], True
    calls = iter(inspect_results)

    def fake_docker(*args, input_text=None, timeout=60):
        res = next(calls)
        if isinstance(res, Exception):
            raise res
        rc, err = res
        return types.SimpleNamespace(returncode=rc, stdout="", stderr=err)
    r._docker = fake_docker
    return r


def _track(r, cid="0123456789abcdef0123"):
    import os
    import tempfile
    r.n += 1
    p = os.path.join(tempfile.gettempdir(), f"kl-test-cid-{os.getpid()}-{r.n}")
    with open(p, "w", encoding="utf-8") as f:
        f.write(cid)
    r._track(p, 0)
    assert not os.path.exists(p)                         # the cidfile is cleaned up
    return r.lifecycle_report(wait_s=10)[-1]


def test_gone_only_when_docker_says_no_such_container():
    e = _track(_runner([(1, "Error: No such object: 0123")]))
    assert e == {"script": 1, "id": "0123456789ab", "exit": 0, "gone": True}


def test_still_listed_is_reported_as_not_gone():
    e = _track(_runner([(0, ""), (0, ""), (0, "")]))
    assert e["gone"] is False


def test_removal_that_trails_the_cli_is_seen_on_a_recheck():
    e = _track(_runner([(0, ""), (1, "Error: No such container: 0123")]))
    assert e["gone"] is True


def test_a_failed_check_is_unknown_not_gone():
    assert _track(_runner([(1, "error during connect: ssh: connection refused")]))["gone"] is None
    assert _track(_runner([subprocess.TimeoutExpired("docker", 30)]))["gone"] is None


def test_no_id_no_check():
    r = _runner([])
    e = _track(r, cid="")
    assert e["id"] == "" and e["gone"] is None and r._checks == []
