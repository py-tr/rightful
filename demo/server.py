"""The public demo server. Two sides in one visitor session: the help-desk chat (the visitor is the caller, and with a
prepared scenario or the bounded ticket editor, the attacker) and the owner's phone (simulated, labelled as such).

Each visitor gets a fresh fake company from the realm factory, lazily, on the first ticket. Every ticket runs the real
system: the model, a sandbox on a worker through a signed edge, the gate, approvals, and Keycloak's own event log.
Limits are check-and-reserve and fail closed (demo/limits.py); a queue position is shown when the demo is full.

Security notes (mentor's review): this process never holds Keycloak's master admin (the factory does); a session is
an HttpOnly, Secure, SameSite=Strict cookie; every state change is a POST bound to that cookie; the phone of one
session is never reachable from another; everything model- or visitor-written is returned as data and rendered as
text by the page; the mailbox shows only that an email arrived, never its link; stack traces are never returned.
"""
from __future__ import annotations

import json
import os
import queue
import secrets
import threading
import time
from dataclasses import dataclass, field

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.testclient import TestClient

from agent.llm import LLM
from agent.loop import run_ticket
from agent.prompts import HARDENED, LIGHT
from agent.runner import DockerRunner
from broker import runkey
from demo.limits import Limits, Refused
from demo.scenarios import SCENARIOS
from demo.stack import SessionStack
from eval.dispatch import BrokerDispatch, PushDispatch, Timing

IDLE_S, MAX_S = 20 * 60, 60 * 60
MAX_CALLER_CHARS, MAX_TICKET_CHARS = 1200, 2500
MAX_TURNS, TICKET_WALL_S = 8, 180
WAIT_FOR_VISITOR_S = 90
HERE = os.path.dirname(os.path.abspath(__file__))


class FactoryClient:
    def __init__(self, base: str, token: str):
        self.http = httpx.Client(base_url=base, headers={"Authorization": f"Bearer {token}"}, timeout=60)

    def take(self) -> dict | None:
        r = self.http.post("/companies")
        return r.json() if r.status_code == 200 else None

    def give_back(self, realm: str) -> None:
        try:
            self.http.delete(f"/companies/{realm}")
        except httpx.HTTPError:
            pass


@dataclass
class Ticket:
    id: str
    scenario: str | None
    caller: str
    ticket_text: str
    prompt: str
    started: float = field(default_factory=time.time)
    status: str = "queued"                       # queued | running | waiting_for_you | done | refused | error
    messages: list[dict] = field(default_factory=list)      # what the visitor sees (role, text)
    inbox: "queue.Queue[str]" = field(default_factory=queue.Queue)
    cost: float = 0.0
    note: str = ""


@dataclass
class Session:
    id: str
    ip: str
    created: float = field(default_factory=time.time)
    seen: float = field(default_factory=time.time)
    stack: SessionStack | None = None
    tickets: list[Ticket] = field(default_factory=list)
    candidates: dict[str, list[str]] = field(default_factory=dict)      # push id -> the 3 numbers shown
    lock: threading.Lock = field(default_factory=threading.Lock)


class Demo:
    def __init__(self, kc_base: str, factory: FactoryClient, limits: Limits, hosts: list[str | None], out_dir: str,
                 edge_upstream: str, model: str = "glm-5.3-flash", max_in_flight: int = 4, mail_api: str | None = None,
                 counter_path: str | None = None, counter_since: str = "2026-11-08"):
        self.kc_base, self.factory, self.limits, self.hosts = kc_base, factory, limits, hosts
        self.out_dir, self.edge_upstream, self.model, self.mail_api = out_dir, edge_upstream, model, mail_api
        self.master = secrets.token_bytes(32)
        self.broker, self.push = BrokerDispatch(), PushDispatch()
        self.sessions: dict[str, Session] = {}
        self.cookies: dict[str, str] = {}                   # cookie value -> session id
        self.lock = threading.Lock()
        self.slots = threading.Semaphore(max_in_flight)
        self.waiting = 0
        self.counter_path = counter_path or os.path.join(out_dir, "counter.jsonl")
        self.counter_since = counter_since
        os.makedirs(out_dir, exist_ok=True)

    # --- sessions ------------------------------------------------------------------------------------------------
    def new_session(self, ip: str) -> tuple[Session, str]:
        sid = "v" + secrets.token_hex(8)
        self.limits.open_session(sid, ip)                   # raises Refused (per-IP, busy, paused)
        s = Session(sid, ip)
        cookie = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[sid] = s
            self.cookies[cookie] = sid
        return s, cookie

    def session_of(self, request: Request) -> Session | None:
        sid = self.cookies.get(request.cookies.get("ks", ""))
        s = self.sessions.get(sid or "")
        if s and time.time() - s.seen <= IDLE_S and time.time() - s.created <= MAX_S:
            s.seen = time.time()
            return s
        return None

    def company(self, s: Session) -> SessionStack:
        with s.lock:
            if s.stack is None:
                c = self.factory.take()
                if c is None:
                    raise Refused("the demo is busy (no company available); please try again in a minute")
                s.stack = SessionStack(self.kc_base, self.out_dir, self.master, c).create()
                self.push.register(s.stack.realm, s.stack.push)
            return s.stack

    def end_session(self, s: Session, why: str) -> None:
        with self.lock:
            self.sessions.pop(s.id, None)
            for k, v in list(self.cookies.items()):
                if v == s.id:
                    self.cookies.pop(k)
        self.limits.close_session(s.id)
        if s.stack is not None:
            self.archive(s, why)                            # BEFORE the realm is deleted: the counter never loses it
            self.push.unregister(s.stack.realm)
            self.factory.give_back(s.stack.realm)

    def sweep_once(self) -> None:
        now = time.time()
        for s in list(self.sessions.values()):
            if now - s.seen > IDLE_S or now - s.created > MAX_S:
                self.end_session(s, "idle" if now - s.seen > IDLE_S else "max lifetime")

    def run_background(self, every_s: float = 30.0) -> None:
        def loop():
            while True:
                try:
                    self.sweep_once()
                except Exception:                           # noqa: BLE001
                    pass
                time.sleep(every_s)
        threading.Thread(target=loop, daemon=True).start()

    # --- the counter: from the identity server's own log, across all companies ------------------------------
    def archive(self, s: Session, why: str) -> None:
        try:
            events = s.stack.events()
        except Exception as e:                              # noqa: BLE001  record that it could not be read
            events, why = [], f"{why}; events unreadable: {type(e).__name__}"
        rows = self.rows(s)
        n = self.counts(rows)
        rec = {"t": time.time(), "realm": s.stack.realm, "why": why, "events": len(events), **n,
               "orphans": max(0, len(events) - n["executed"])}
        with self.lock, open(self.counter_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")

    def counter(self) -> dict:
        tot = {"companies": 0, "attempted": 0, "executed": 0, "events": 0, "orphans": 0}
        if os.path.exists(self.counter_path):
            for line in open(self.counter_path, encoding="utf-8"):
                r = json.loads(line)
                tot["companies"] += 1
                for k in ("attempted", "executed", "events", "orphans"):
                    tot[k] += r.get(k, 0)
        return {"since": self.counter_since, "source": "the identity server's own admin log, across all companies",
                **tot}

    # --- tickets ---------------------------------------------------------------------------------------------
    def start_ticket(self, s: Session, scenario: str | None, caller: str, ticket_text: str, prompt: str) -> Ticket:
        if scenario:
            sc = SCENARIOS[scenario]
            caller, ticket_text, prompt = caller or sc["caller"], sc["ticket"], sc.get("prompt", prompt)
        caller, ticket_text = caller.strip()[:MAX_CALLER_CHARS], ticket_text.strip()[:MAX_TICKET_CHARS]
        if not caller:
            raise Refused("say something as the caller first")
        reserved = self.limits.reserve_ticket(s.id)         # BEFORE any model call; raises Refused
        t = Ticket("t" + secrets.token_hex(5), scenario, caller, ticket_text or
                   "INC-3101 | user: cfo | 'Account access request'\nNotes:\n- Caller requests account help.",
                   "hardened" if prompt == "hardened" else "light")
        t.messages.append({"role": "caller", "text": caller})
        with s.lock:
            s.tickets.append(t)
        threading.Thread(target=self._run, args=(s, t, reserved), daemon=True).start()
        return t

    def _run(self, s: Session, t: Ticket, reserved: float) -> None:
        spent = 0.0
        with self.lock:
            self.waiting += 1
        self.slots.acquire()
        with self.lock:
            self.waiting -= 1
        runner = None
        try:
            t.status = "running"
            stack = self.company(s)
            rid = runkey.new_run_id()
            t.run_id = rid
            stack.app.state.open_run(rid, "full")
            self.broker.register(rid, stack.app, Timing())
            host = self.hosts[hash(rid) % len(self.hosts)]
            runner = DockerRunner(rid, t.ticket_text, upstream=self.edge_upstream,
                                  run_key=runkey.task_key(self.master, rid), realm=stack.realm, docker_host=host,
                                  runtime="runsc" if (host or "").startswith("ssh://") else None,
                                  timeout_s=60).start()
            if os.environ.get("KEYLESS_DEMO_FAKE_LLM") == "1":     # local testing only; never a real visitor
                from eval.fake_llm import FakeLLM
                llm = FakeLLM(self.model)
            else:
                llm = LLM(models=[self.model], cap_usd=reserved)
            deadline = time.time() + TICKET_WALL_S
            led = stack.ledger.path

            def on_reply(delivered: str):
                t.messages.append({"role": "agent", "text": delivered})
                if time.time() > deadline:
                    return None
                t.status = "waiting_for_you"
                try:
                    nxt = t.inbox.get(timeout=min(WAIT_FOR_VISITOR_S, max(deadline - time.time(), 1)))
                except queue.Empty:
                    return None
                t.status = "running"
                return nxt[:MAX_CALLER_CHARS]
            prompt = HARDENED if t.prompt == "hardened" else LIGHT
            res = run_ticket(llm, runner, rid, t.caller, led, prompt=prompt, on_reply=on_reply, max_turns=MAX_TURNS)
            spent = llm.spent
            t.cost = round(spent, 5)
            t.status = "done"
            t.note = {"finished": "", "max_turns": "the ticket reached its step limit", "cap": "the ticket reached its "
                      "budget", "error": "the model service failed; nothing was changed by that"}.get(res.stop, "")
            stack.app.state.close_run(rid)
        except Refused as e:
            t.status, t.note = "refused", e.reason
        except Exception as e:                              # noqa: BLE001  never a stack trace to the visitor
            t.status, t.note = "error", f"something went wrong ({type(e).__name__}); nothing was changed by it"
        finally:
            if runner:
                try:
                    runner.close()
                except Exception:                           # noqa: BLE001
                    pass
            self.slots.release()
            self.limits.settle_ticket(s.id, reserved, spent)

    # --- what the page shows ---------------------------------------------------------------------------------
    def rows(self, s: Session) -> list[dict]:
        """One row per state-changing request: what the agent asked, what the gate said, the owner's device, and what
        the identity server recorded (the rightmost column, from Keycloak's own log)."""
        if s.stack is None:
            return []
        ents = s.stack.ledger.entries()
        try:
            events = s.stack.events()
        except Exception:                                   # noqa: BLE001
            events = []
        names = {v: k for k, v in s.stack.users().items()}
        # the owner's device per operation: the latest status of each challenge (send and poll entries share its id)
        op_of, last = {}, {}
        for e in ents:
            d = e["data"]
            if e["kind"] == "challenge" and d.get("challenge"):
                if d.get("op"):
                    op_of[d["challenge"]] = d["op"]
                last[d["challenge"]] = d.get("status")
        challenges = {}
        for cid, st in last.items():
            challenges.setdefault(op_of.get(cid, ""), []).append(
                {"sent": "push sent", "approved": "approved", "denied": "declined", "expired": "expired",
                 "rate_limited": "rate limited", "human_only": "human only"}.get(st, st))
        rows, used = [], set()
        for e in ents:
            d = e["data"]
            if e["kind"] not in ("decision", "forwarding") or d.get("method") not in ("PUT", "POST", "DELETE", None):
                continue
            if e["kind"] == "decision" and d.get("method") is None:
                continue
            op, user = d.get("op") or "?", d.get("user")
            ev = None
            if e["kind"] == "forwarding":
                for i, x in enumerate(events):
                    k = "change_email" if x["op"] == "user_update" else x["op"]
                    if i not in used and x["user"] == user and (k == op or op in ("mfa_recovery_lost_device",
                                                                                  "compromise_response")):
                        ev, _ = x, used.add(i)
                        break
            rows.append({"kind": "write", "asked": f"{op.replace('_', ' ')}, {names.get(user, user or '')}",
                         "gate": "allowed: approved by the owner's device" if e["kind"] == "forwarding" else
                                 {"denied_no_receipt": "refused: no approval from the owner",
                                  "denied_cooling_off": "approved; waiting out the cooling-off (cancel possible)",
                                  "quarantined": "refused and the run stopped"}.get(d.get("outcome"),
                                                                                   f"refused: {d.get('reason', '')}"),
                         "device": ", ".join(filter(None, challenges.get(op, []))) or "-",
                         "event": (f"{ev['type']} {ev['path'].split('/')[-1]}" if ev else None),
                         "hash": (d.get("request_hash") or "")[:8]})
        return rows

    @staticmethod
    def counts(rows: list[dict]) -> dict:
        """Distinct changes requested (by request hash: a refusal and its approved retry are ONE change) vs executed
        (an event in the identity server's log)."""
        return {"attempted": len({r["hash"] for r in rows if r["kind"] == "write"}),
                "executed": sum(1 for r in rows if r["event"])}

    def view(self, s: Session) -> dict:
        rows = self.rows(s)
        phone = {"label": "Simulated device. In production this is the owner's authenticator app.",
                 "pending": [], "notices": [], "mail": 0,
                 "note": "The only way a change happens is this device saying yes to this exact request. If you "
                         "approve it as the owner, you have performed the honest path, not a bypass."}
        if s.stack is not None:
            pc = TestClient(s.stack.push)
            for user in ("cfo", "ceo"):
                v = pc.get(f"/phone/{user}").json()
                for p in v["pending"]:
                    if p["id"] not in s.candidates:
                        decoys = set()
                        while len(decoys) < 2:
                            n = f"{secrets.randbelow(90) + 10}"
                            if n != p["number"]:
                                decoys.add(n)
                        nums = list(decoys) + [p["number"]]
                        secrets.SystemRandom().shuffle(nums)
                        s.candidates[p["id"]] = nums
                    phone["pending"].append({"id": p["id"], "device_of": user, "action": p["label"],
                                             "account": p["target"], "instruction": p["instruction"],
                                             "hash": p["binding"].rsplit("-", 1)[-1], "numbers": s.candidates[p["id"]]})
                phone["notices"] += [{"device_of": user, "text": n["value"], "cancel": bool(n.get("cancel_id")),
                                      "cancel_id": n.get("cancel_id")} for n in v["inbox"] if n["kind"] == "notice"]
                phone["notices"] += [{"device_of": user, "text": "A temporary password arrived on this device "
                                      "(shown only here, never to the agent).", "cancel": False}
                                     for n in v["inbox"] if n["kind"] == "temporary password"]
            if self.mail_api:
                from eval import oracle
                phone["mail"] = len(oracle.mails_for_realm(self.mail_api, s.stack.realm))
        return {"session": {"expires_in_s": int(min(IDLE_S - (time.time() - s.seen),
                                                    MAX_S - (time.time() - s.created)))},
                "tickets": [{"id": t.id, "scenario": t.scenario, "status": t.status, "note": t.note,
                             "messages": t.messages, "cost": t.cost} for t in s.tickets],
                "rows": rows, **self.counts(rows), "phone": phone,
                "queue": self.waiting, "limits": self.limits.status(), "counter": self.counter()}


def create_demo_app(demo: Demo) -> FastAPI:
    app = FastAPI(title="Keyless demo", docs_url=None, redoc_url=None, openapi_url=None)

    def err(msg: str, code: int = 400):
        return JSONResponse({"error": msg}, status_code=code)

    def need(request: Request):
        s = demo.session_of(request)
        if s is None:
            return None, err("no session (or it expired); start a new one", 401)
        if request.method == "POST" and request.headers.get("sec-fetch-site") not in (None, "same-origin"):
            return None, err("cross-site request refused", 403)
        return s, None

    @app.get("/")
    def page():
        return FileResponse(os.path.join(HERE, "static", "index.html"), headers={"Cache-Control": "no-store"})

    @app.get("/healthz")
    def health():
        return {"ok": True, **demo.limits.status()}

    @app.get("/api/scenarios")
    def scenarios():
        return [{"id": k, "title": v["title"], "side": v["side"], "expect": v["expect"], "caller": v["caller"],
                 "ticket": v["ticket"]} for k, v in SCENARIOS.items()]

    @app.post("/api/session")
    def session(request: Request):
        ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "?").split(",")[0]
        try:
            _, cookie = demo.new_session(ip.strip())
        except Refused as e:
            return err(e.reason, 429)
        r = JSONResponse({"ok": True})
        r.set_cookie("ks", cookie, httponly=True, secure=True, samesite="strict", max_age=MAX_S)
        return r

    @app.get("/api/state")
    def state(request: Request):
        s, e = need(request)
        return e or demo.view(s)

    @app.post("/api/tickets")
    async def tickets(request: Request):
        s, e = need(request)
        if e:
            return e
        try:
            j = await request.json()
            t = demo.start_ticket(s, j.get("scenario") if j.get("scenario") in SCENARIOS else None,
                                  str(j.get("caller", "")), str(j.get("ticket", "")), str(j.get("prompt", "light")))
        except Refused as x:
            return err(x.reason, 429)
        except (ValueError, KeyError):
            return err("bad request")
        return {"ticket": t.id}

    @app.post("/api/tickets/{tid}/say")
    async def say(tid: str, request: Request):
        s, e = need(request)
        if e:
            return e
        t = next((x for x in s.tickets if x.id == tid), None)
        if t is None or t.status != "waiting_for_you":
            return err("this ticket is not waiting for you")
        text = str((await request.json()).get("text", "")).strip()[:MAX_CALLER_CHARS]
        if not text:
            return err("empty message")
        t.messages.append({"role": "caller", "text": text})
        t.inbox.put(text)
        return {"ok": True}

    @app.post("/api/phone/{push_id}/{action}")
    async def phone(push_id: str, action: str, request: Request):
        s, e = need(request)
        if e:
            return e
        if s.stack is None or action not in ("approve", "deny"):
            return err("nothing to answer")
        pc = TestClient(s.stack.push)
        p = next((x for u in ("cfo", "ceo") for x in pc.get(f"/phone/{u}").json()["pending"] if x["id"] == push_id),
                 None)
        if p is None:
            return err("no such request on this phone", 404)
        if action == "deny":
            return {"ok": pc.post(f"/phone/{p['username']}/{push_id}/deny").status_code == 200}
        number = str((await request.json()).get("number", ""))
        if number not in s.candidates.get(push_id, []):
            return err("pick one of the numbers shown")
        r = pc.post(f"/phone/{p['username']}/{push_id}/approve", json={"number": number})   # the server compares
        return {"ok": r.status_code == 200, "matched": r.status_code == 200}

    @app.post("/api/phone/cancel/{cancel_id}")
    def cancel(cancel_id: str, request: Request):
        s, e = need(request)
        if e:
            return e
        if s.stack is None:
            return err("nothing to cancel")
        r = TestClient(s.stack.push).post(f"/phone/cfo/cancel/{cancel_id}")
        return {"ok": r.status_code == 200}

    @app.exception_handler(Exception)
    async def never_a_trace(request: Request, exc: Exception):
        return JSONResponse({"error": "something went wrong; nothing was changed by it"}, status_code=500)
    return app
