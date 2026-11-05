"""Static checks of the sandbox command lines (no Docker needed): the regressions we actually hit."""
from agent.runner import BrowserRunner, DockerRunner


def test_browser_runner_env_has_the_browser_path(tmp_path):
    r = BrowserRunner("t", "x", out_dir=str(tmp_path / "o"))
    assert "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright" in r.CLEAN_ENV       # lost once by a misplaced edit
    assert r.CLEAN_ENV[:2] == ["env", "-i"]
    assert not any(v.startswith(("GPG_KEY", "VULTR", "KEY")) for v in r.CLEAN_ENV)


def test_sandbox_args_are_locked_down(tmp_path):
    r = DockerRunner("t", "x")
    a = r._sandbox_args("c")
    for flag in ("--read-only", "--cap-drop", "--security-opt", "--pids-limit", "--memory", "--network"):
        assert flag in a
    assert a[a.index("--cap-drop") + 1] == "ALL" and a[a.index("--security-opt") + 1] == "no-new-privileges"
    r.edge_ip = "10.0.0.2"
    assert "gate:10.0.0.2" in r._sandbox_args("c")                         # a hosts entry, not DNS (gVisor)
