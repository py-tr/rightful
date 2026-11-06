"""Abuse and spend limits for the public demo. All checks are check-and-reserve under ONE lock (no check-then-act race,
which is how naive counters overshoot), and they fail closed.

- Global daily model spend: a ticket reserves its per-ticket cap BEFORE any model call; the unused part is returned
  when it ends. Spend is persisted to disk per UTC day, so a restart cannot reset it.
- Per session: at most N tickets and $X.
- Per IP (11-06, mentor): the real abuse limit is MONEY: at most $X of model spend per address per rolling day (a judge
  spends cents; one abuser can take at most a share of the day). At most K sessions live at once per address (a venue
  network can put several judges behind one address; K < the global slots so one address cannot hold them all). A high
  ticket count per day is only a backstop. No daily SESSION cap: "start over" and a mis-tap must never lock a judge out.
  Per-IP counts are persisted, keyed by a salted hash of the address (never the address itself): a restart is not a reset.
- Team traffic (the smoke test, with the operator's key) skips the per-IP caps but not the spend caps.
- Concurrency: at most N live sessions.
- A kill switch file: if it exists, nothing new starts (an operator can stop the demo during judging in one command).
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time


class Refused(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class Limits:
    # Defaults = the mentor's table (judging window up to three weeks, GLM at under a cent a ticket):
    # total $25 with $7 held back for the final week, $3/day, per session $0.15 and 12 tickets, per IP per day 3 sessions
    # and 30 tickets, 6 concurrent sessions (a queue beyond), $0.05 and 8 steps per ticket.
    def __init__(self, state_path: str, daily_usd: float = 3.0, per_ticket_usd: float = 0.05,
                 per_session_usd: float = 0.15, tickets_per_session: int = 12, sessions_per_ip_day: int | None = None,
                 tickets_per_ip_day: int = 100, max_live_sessions: int = 6, total_usd: float = 25.0,
                 final_week_reserve_usd: float = 7.0, final_week_starts: float | None = None,
                 kill_file: str | None = None, clock=time.time, sessions_per_ip_hour: int | None = None,
                 live_per_ip: int = 6, ip_usd_day: float = 0.75):
        self.path, self.daily, self.per_ticket = state_path, daily_usd, per_ticket_usd
        self.per_session, self.tickets_per_session = per_session_usd, tickets_per_session
        self.per_ip_day = sessions_per_ip_hour if sessions_per_ip_hour is not None else sessions_per_ip_day
        self.tickets_per_ip_day, self.max_live, self.live_per_ip = tickets_per_ip_day, max_live_sessions, live_per_ip
        self.ip_usd_day = ip_usd_day
        self.total, self.reserve, self.final_week = total_usd, final_week_reserve_usd, final_week_starts
        self.kill_file = kill_file or (state_path + ".KILL")
        self._clock, self._lock = clock, threading.Lock()
        self._sessions: dict[str, dict] = {}
        self._state = self._load()
        self._ips: dict[str, list[float]] = self._state["ips"]            # hashed address -> session start times
        self._ip_tickets: dict[str, list[float]] = self._state["ip_tickets"]
        self._ip_spend: dict[str, list[list[float]]] = self._state["ip_spend"]   # hashed address -> [[t, usd], ...]

    # --- persistence ------------------------------------------------------------------------------------------
    def _day(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime(self._clock()))

    def _load(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as f:
                s = json.load(f)
        except (OSError, ValueError):
            s = {}
        total = s.get("total_spent", 0.0)
        keep = {"ip_salt": s.get("ip_salt") or secrets.token_hex(16), "ips": s.get("ips") or {},
                "ip_tickets": s.get("ip_tickets") or {}, "ip_spend": s.get("ip_spend") or {}}
        if s.get("day") == self._day():
            s.setdefault("total_spent", total)
            s.update(keep)
            s["reserved"] = 0.0                    # reservations die with the process that held them
            return s
        return {"day": self._day(), "spent": 0.0, "reserved": 0.0, "total_spent": total, **keep}

    def _save(self) -> None:
        now = self._clock()
        for m in (self._state["ips"], self._state["ip_tickets"]):     # keep only the rolling day
            for k in list(m):
                m[k] = [t for t in m[k] if now - t < 86400]
                if not m[k]:
                    del m[k]
        m = self._state["ip_spend"]
        for k in list(m):
            m[k] = [x for x in m[k] if now - x[0] < 86400]
            if not m[k]:
                del m[k]
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._state, f)
        os.replace(tmp, self.path)

    def _roll(self) -> None:
        if self._state.get("day") != self._day():
            self._state = {"day": self._day(), "spent": 0.0, "reserved": 0.0,
                           "total_spent": self._state.get("total_spent", 0.0),
                           "ip_salt": self._state["ip_salt"], "ips": self._ips, "ip_tickets": self._ip_tickets,
                           "ip_spend": self._ip_spend}

    def _total_allowed(self) -> float:
        """Before the final week, $7 of the total is held back so the last days of judging still have a live demo."""
        if self.final_week is not None and self._clock() < self.final_week:
            return self.total - self.reserve
        return self.total

    def _key(self, ip: str) -> str:
        return hashlib.sha256((self._state["ip_salt"] + ip).encode()).hexdigest()[:20]

    def _killed(self) -> bool:
        return os.path.exists(self.kill_file)

    # --- sessions ---------------------------------------------------------------------------------------------
    def open_session(self, sid: str, ip: str, team: bool = False) -> None:
        with self._lock:
            if self._killed():
                raise Refused("the demo is paused by the operator")
            now, key = self._clock(), self._key(ip)
            recent = [t for t in self._ips.get(key, []) if now - t < 86400]
            if not team:
                if self.per_ip_day is not None and len(recent) >= self.per_ip_day:
                    raise Refused("too many sessions from your address today; please try again tomorrow")
                if sum(1 for x in self._sessions.values() if x["ip"] == key) >= self.live_per_ip:
                    raise Refused(f"you already have {self.live_per_ip} demo sessions open; use one of them, or "
                                  "wait a few minutes for an idle one to close")
            if len(self._sessions) >= self.max_live:
                raise Refused("the demo is busy (all sessions in use); please try again in a few minutes")
            if not team:
                self._ips[key] = recent + [now]
            self._sessions[sid] = {"tickets": 0, "spent": 0.0, "reserved": 0.0, "ip": key, "team": team}
            self._save()

    def close_session(self, sid: str) -> None:
        with self._lock:
            self._sessions.pop(sid, None)

    def live_sessions(self) -> int:
        with self._lock:
            return len(self._sessions)

    # --- tickets: reserve before any model call, settle after ------------------------------------------------
    def reserve_ticket(self, sid: str) -> float:
        with self._lock:
            self._roll()
            if self._killed():
                raise Refused("the demo is paused by the operator")
            s = self._sessions.get(sid)
            if s is None:
                raise Refused("no such session")
            if s["tickets"] >= self.tickets_per_session:
                raise Refused(f"this session has used its {self.tickets_per_session} tickets; start a new session")
            eps = 1e-9                                  # float sums (19 x 0.05 > 0.95) must not cost a whole ticket
            if s["spent"] + s["reserved"] + self.per_ticket > self.per_session + eps:
                raise Refused("this session has used its model budget; start a new session")
            st = self._state
            if st["spent"] + st["reserved"] + self.per_ticket > self.daily + eps:
                raise Refused("today's model budget for the demo is used up; the recorded run is available instead")
            if st.get("total_spent", 0.0) + st["reserved"] + self.per_ticket > self._total_allowed() + eps:
                raise Refused("the demo's model budget is used up; the recorded run is available instead")
            now = self._clock()
            ipt = [t for t in self._ip_tickets.get(s["ip"], []) if now - t < 86400]
            if not s.get("team") and len(ipt) >= self.tickets_per_ip_day:
                raise Refused("too many tickets from your address today; please try again tomorrow")
            if not s.get("team"):
                ip_used = sum(x[1] for x in self._ip_spend.get(s["ip"], []) if now - x[0] < 86400)
                ip_held = sum(x["reserved"] for x in self._sessions.values() if x["ip"] == s["ip"])
                if ip_used + ip_held + self.per_ticket > self.ip_usd_day + eps:
                    raise Refused("your address has used its share of today's demo budget; please try again tomorrow")
            if not s.get("team"):
                self._ip_tickets[s["ip"]] = ipt + [now]
            s["tickets"] += 1
            s["reserved"] += self.per_ticket
            st["reserved"] += self.per_ticket
            self._save()
            return self.per_ticket

    def settle_ticket(self, sid: str, reserved: float, spent: float) -> None:
        spent = max(0.0, min(spent, reserved))         # a ticket can never spend more than it reserved (LLM cap)
        with self._lock:
            self._roll()
            st = self._state
            st["reserved"] = max(0.0, st["reserved"] - reserved)
            st["spent"] += spent
            st["total_spent"] = st.get("total_spent", 0.0) + spent
            s = self._sessions.get(sid)
            if s is not None:
                s["reserved"] = max(0.0, s["reserved"] - reserved)
                s["spent"] += spent
                if not s.get("team") and spent > 0:
                    self._ip_spend.setdefault(s["ip"], []).append([self._clock(), spent])
            self._save()

    def status(self) -> dict:
        with self._lock:
            self._roll()
            return {"day": self._state["day"], "spent_today": round(self._state["spent"], 4),
                    "spent_total": round(self._state.get("total_spent", 0.0), 4), "total_cap": self._total_allowed(),
                    "reserved_now": round(self._state["reserved"], 4), "daily_cap": self.daily,
                    "live_sessions": len(self._sessions), "max_sessions": self.max_live, "paused": self._killed()}
