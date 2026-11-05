"""Public-demo limits: atomic check-and-reserve, fail closed, persistent daily spend, kill switch."""
import threading

import pytest

from demo.limits import Limits, Refused


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


def make(tmp_path, **kw):
    return Limits(str(tmp_path / "limits.json"), clock=kw.pop("clock", Clock()), **kw)


def test_concurrent_reservations_never_overshoot_the_daily_cap(tmp_path):
    lim = make(tmp_path, daily_usd=1.0, per_ticket_usd=0.05, per_session_usd=100, tickets_per_session=1000,
               max_live_sessions=1000, sessions_per_ip_hour=1000)
    for i in range(50):
        lim.open_session(f"s{i}", f"10.0.0.{i}")
    ok = []

    def go(sid):
        for _ in range(20):
            try:
                ok.append(lim.reserve_ticket(sid))
            except Refused:
                pass
    ts = [threading.Thread(target=go, args=(f"s{i}",)) for i in range(50)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(ok) == 20                                         # exactly $1.00 / $0.05, never more


def test_settle_returns_the_unused_part_and_persists(tmp_path):
    clock = Clock()
    lim = make(tmp_path, daily_usd=0.10, per_ticket_usd=0.05, clock=clock)
    lim.open_session("s1", "1.1.1.1")
    r = lim.reserve_ticket("s1")
    lim.settle_ticket("s1", r, 0.01)
    again = Limits(str(tmp_path / "limits.json"), daily_usd=0.10, per_ticket_usd=0.05, clock=clock)   # a restart
    assert again.status()["spent_today"] == 0.01                 # spend survives the restart
    clock.t += 86400
    assert again.status()["spent_today"] == 0.0                  # and resets on a new UTC day


def test_per_session_and_per_ip_limits(tmp_path):
    lim = make(tmp_path, tickets_per_session=2, sessions_per_ip_hour=2)
    lim.open_session("a", "9.9.9.9")
    lim.reserve_ticket("a")
    lim.reserve_ticket("a")
    with pytest.raises(Refused, match="tickets"):
        lim.reserve_ticket("a")
    lim.open_session("b", "9.9.9.9")
    with pytest.raises(Refused, match="too many sessions"):
        lim.open_session("c", "9.9.9.9")


def test_kill_switch_stops_everything_new(tmp_path):
    lim = make(tmp_path)
    lim.open_session("a", "1.2.3.4")
    open(lim.kill_file, "w").close()
    with pytest.raises(Refused, match="paused"):
        lim.reserve_ticket("a")
    with pytest.raises(Refused, match="paused"):
        lim.open_session("b", "5.6.7.8")


def test_a_ticket_cannot_settle_more_than_it_reserved(tmp_path):
    lim = make(tmp_path, daily_usd=1.0, per_ticket_usd=0.05)
    lim.open_session("a", "1.2.3.4")
    r = lim.reserve_ticket("a")
    lim.settle_ticket("a", r, 99.0)
    assert lim.status()["spent_today"] == 0.05
