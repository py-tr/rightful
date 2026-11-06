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


def test_total_cap_holds_back_the_final_week_reserve(tmp_path):
    clock = Clock()
    lim = make(tmp_path, clock=clock, daily_usd=100, total_usd=0.20, final_week_reserve_usd=0.10,
               final_week_starts=clock.t + 7 * 86400, per_ticket_usd=0.05, per_session_usd=100,
               tickets_per_session=100, tickets_per_ip_day=100)
    lim.open_session("a", "1.1.1.1")
    for _ in range(2):
        lim.settle_ticket("a", lim.reserve_ticket("a"), 0.05)
    with pytest.raises(Refused, match="budget is used up"):        # $0.10 of $0.20 used: the rest waits
        lim.reserve_ticket("a")
    clock.t += 8 * 86400                                           # the final week: the reserve opens
    lim.open_session("b", "2.2.2.2")
    lim.settle_ticket("b", lim.reserve_ticket("b"), 0.05)
    assert lim.status()["spent_total"] == 0.15


def test_tickets_per_ip_per_day(tmp_path):
    lim = make(tmp_path, tickets_per_ip_day=3, tickets_per_session=100, sessions_per_ip_day=10, per_session_usd=100)
    lim.open_session("a", "7.7.7.7")
    lim.open_session("b", "7.7.7.7")
    lim.reserve_ticket("a"), lim.reserve_ticket("a"), lim.reserve_ticket("b")
    with pytest.raises(Refused, match="tickets from your address"):
        lim.reserve_ticket("b")                                     # a second session does not reset the IP's count


def test_a_ticket_cannot_settle_more_than_it_reserved(tmp_path):
    lim = make(tmp_path, daily_usd=1.0, per_ticket_usd=0.05)
    lim.open_session("a", "1.2.3.4")
    r = lim.reserve_ticket("a")
    lim.settle_ticket("a", r, 99.0)
    assert lim.status()["spent_today"] == 0.05


def test_per_ip_counts_survive_a_restart_and_never_store_the_address(tmp_path):
    clock = Clock()
    lim = make(tmp_path, clock=clock, sessions_per_ip_day=2, live_per_ip=5)
    lim.open_session("a", "203.0.113.7")
    lim.open_session("b", "203.0.113.7")
    assert "203.0.113.7" not in (tmp_path / "limits.json").read_text()      # a salted hash, not the address
    again = make(tmp_path, clock=clock, sessions_per_ip_day=2, live_per_ip=5)  # the service restarted
    with pytest.raises(Refused, match="too many sessions"):
        again.open_session("c", "203.0.113.7")
    clock.t += 86401                                                          # a rolling day later
    again.open_session("d", "203.0.113.7")


def test_at_most_two_live_sessions_per_address(tmp_path):
    lim = make(tmp_path, live_per_ip=2)
    lim.open_session("a", "198.51.100.1")
    lim.open_session("b", "198.51.100.1")
    with pytest.raises(Refused, match="already have 2 demo sessions open"):
        lim.open_session("c", "198.51.100.1")
    lim.open_session("x", "198.51.100.2")                                     # another address is unaffected
    lim.close_session("a")
    lim.open_session("c", "198.51.100.1")                                     # a closed one frees its place


def test_team_traffic_skips_the_per_ip_caps_but_not_the_spend_caps(tmp_path):
    lim = make(tmp_path, sessions_per_ip_day=1, live_per_ip=1, per_session_usd=0.05, per_ticket_usd=0.05)
    lim.open_session("v", "192.0.2.9")
    for i in range(3):
        lim.open_session(f"t{i}", "192.0.2.9", team=True)                   # same address, operator's smoke key
    lim.reserve_ticket("t0")
    with pytest.raises(Refused, match="model budget"):
        lim.reserve_ticket("t0")                                              # spend caps still apply
    with pytest.raises(Refused, match="too many sessions"):
        lim.open_session("v2", "192.0.2.9")                                   # team runs used none of the visitor's


def test_no_daily_session_cap_by_default_so_start_over_never_locks_a_judge_out(tmp_path):
    lim = make(tmp_path)                                    # production defaults for per-IP limits
    for i in range(40):                                     # 40 "start over"s from one venue address
        lim.open_session(f"s{i}", "203.0.113.50")
        lim.close_session(f"s{i}")


def test_per_ip_money_cap_is_the_abuse_limit(tmp_path):
    clock = Clock()
    lim = make(tmp_path, clock=clock, ip_usd_day=0.10, per_ticket_usd=0.05, per_session_usd=1.0,
               tickets_per_session=99, daily_usd=10.0)
    lim.open_session("a", "203.0.113.60")
    for _ in range(2):                                      # two tickets that really cost their full reservation
        r = lim.reserve_ticket("a")
        lim.settle_ticket("a", r, 0.05)
    with pytest.raises(Refused, match="share of today's demo budget"):
        lim.reserve_ticket("a")
    lim.open_session("b", "203.0.113.61")                   # another address still has its own share
    lim.reserve_ticket("b")
    again = make(tmp_path, clock=clock, ip_usd_day=0.10, per_ticket_usd=0.05, per_session_usd=1.0,
                 tickets_per_session=99, daily_usd=10.0)    # a restart is not a reset
    again.open_session("c", "203.0.113.60")
    with pytest.raises(Refused, match="share of today's demo budget"):
        again.reserve_ticket("c")
    clock.t += 86401
    again.reserve_ticket("c")                               # a rolling day later


def test_cheap_tickets_do_not_hit_the_money_cap(tmp_path):
    lim = make(tmp_path, ip_usd_day=0.75, per_ticket_usd=0.05, per_session_usd=5.0, tickets_per_session=200)
    lim.open_session("j", "203.0.113.70")
    for _ in range(60):                                     # a judge's realistic ticket costs about a cent
        r = lim.reserve_ticket("j")
        lim.settle_ticket("j", r, 0.01)
