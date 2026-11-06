"""A finished conversation must drop its broker route (found 11-06: every conversation stayed registered in
BrokerDispatch for the process lifetime, keeping its whole SessionStack alive: a slow leak on the live demo)."""
from types import SimpleNamespace

import demo.server as ds
from demo.limits import Limits


class FakeState:
    def open_run(self, rid, mode):
        self.opened = rid


def demo_with_fakes(tmp_path):
    d = ds.Demo("http://kc", factory=None, limits=Limits(str(tmp_path / "budget.json")), hosts=[None],
                out_dir=str(tmp_path / "out"), edge_upstream="http://edge")
    d.company = lambda s: SimpleNamespace(app=SimpleNamespace(state=FakeState()), realm="demo-u000000000000")
    return d


def test_route_is_dropped_when_the_sandbox_fails_to_start(tmp_path, monkeypatch):
    d = demo_with_fakes(tmp_path)

    class Boom:
        def __init__(self, *a, **k):
            raise RuntimeError("sandbox could not start")
    monkeypatch.setattr(ds, "DockerRunner", Boom)
    s = ds.Session("v1", "1.2.3.4")
    d._converse(s, "hi", reserved=0.0)
    assert s.run_id and d.broker.apps == {}            # registered during the run, gone after it
    assert not s.busy
