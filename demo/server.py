"""The public demo server, chat-first (mentor's UI review). One conversation per visitor, from the first message to
the end; the visitor can type at any time; everything that happens is appended to an event stream the page follows:
the visitor's words (at once), the agent's steps as quiet one-line statuses (scripts behind "view"), the gate's
refusal (the one loud line), the push with the number to choose ("Choose 79 on Jordan's phone": posted by the SYSTEM
when the push is sent, so the caller never has to wait for the model to say it), the agent's reply with any false
claim struck through, and a second voice, the identity system's log. A three-sentence summary ends each conversation.

Each visitor gets a fresh fictional company from the realm factory on the first message (a warm pool makes it
instant). Limits are check-and-reserve and fail closed (demo/limits.py). This process never holds Keycloak's master
admin; every state change is a POST bound to an HttpOnly, Secure, SameSite=Strict cookie; everything written by the
model or a visitor is data, rendered as text by the page; the mailbox shows only that an email arrived; no stack
traces ever reach the page.
"""
from __future__ import annotations

import json
import os
import queue
import re
import secrets
import threading
import time
from dataclasses import dataclass, field

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.testclient import TestClient

from agent import claims
from agent.llm import LLM
from agent.loop import run_ticket
from agent.prompts import HARDENED, LIGHT
from agent.runner import DockerRunner
from broker import runkey
from demo.limits import Limits, Refused
from demo.scenarios import DEFAULT_TICKET, SCENARIOS
from demo.stack import SessionStack
from eval.dispatch import BrokerDispatch, PushDispatch, Timing

IDLE_S, MAX_S = 20 * 60, 60 * 60
MAX_TEXT, MAX_TICKET = 1200, 2500
MAX_TURNS, CONVERSATION_WALL_S = 8, 240
WAIT_FOR_VISITOR_S = 20       # after the agent's reply: then the summary comes; a later message starts a new conversation
HERE = os.path.dirname(os.path.abspath(__file__))
PEOPLE = {"cfo": "Jordan Avery (CFO)", "ceo": "Sam Lee (CEO, Jordan's manager)",
          "jordan.avery.c": "Jordan Avery-Cole (contractor)"}
SHORT = {"cfo": "Jordan", "ceo": "Sam", "jordan.avery.c": "Jordan Avery-Cole"}
ACTIONS = {"reset_password": "reset the password", "send_actions_email": "send an account email",
           "remove_credential": "remove a sign-in credential", "logout_sessions": "sign out all sessions",
           "change_email": "change the email address", "mfa_recovery_lost_device": "recover a lost authenticator",
           "compromise_response": "run the compromise response", "identity_check": "verify the caller"}
STEP_WORDS = [("lost_device_recovery", "starting a lost-device recovery"), ("compromise_response", "starting a "
              "compromise response"), ("reset_password", "trying to reset the password"), ("change_email",
              "trying to change the email"), ("remove_credential", "trying to remove a credential"),
              ("send_actions_email", "trying to send an account email"), ("logout_sessions", "trying to sign out "
              "sessions"), ("wait_for_approval", "waiting for the phone"), ("send_challenge", "sending the request "
              "to the phone"), ("escalate", "escalating to a human"), ("get_ticket", "reading the ticket"),
              ("credentials", "checking the sign-in methods"), ("find_user", "looking up the account")]


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
class Session:
    id: str
    ip: str
    created: float = field(default_factory=time.time)
    seen: float = field(default_factory=time.time)
    stack: SessionStack | None = None
    events: list[dict] = field(default_factory=list)
    inbox: "queue.Queue[str]" = field(default_factory=queue.Queue)
    busy: bool = False                     # a conversation is running
    typing: bool = False                   # the model is thinking right now
    prompt: str = "light"
    candidates: dict[str, list[str]] = field(default_factory=dict)
    ledger_pos: int = 0
    run_id: str | None = None
    ticket: str = ""
    conversations: int = 0
    live: dict = field(default_factory=dict)      # this company's counts, recomputed from the identity server's log
    lock: threading.Lock = field(default_factory=threading.Lock)


class Demo:
    def __init__(self, kc_base: str, factory: FactoryClient, limits: Limits, hosts: list[str | None], out_dir: str,
                 edge_upstream: str, model: str = "glm-5.3-flash", max_in_flight: int = 4, mail_api: str | None = None,
                 counter_since: str = "2026-11-08"):
        self.kc_base, self.factory, self.limits, self.hosts = kc_base, factory, limits, hosts
        self.out_dir, self.edge_upstream, self.model, self.mail_api = out_dir, edge_upstream, model, mail_api
        self.master = secrets.token_bytes(32)
        self.broker, self.push = BrokerDispatch(), PushDispatch()
        self.sessions: dict[str, Session] = {}
        self.cookies: dict[str, str] = {}
        self.lock = threading.Lock()
        self.slots = threading.Semaphore(max_in_flight)
        self.waiting = 0
        self.counter_path = os.path.join(out_dir, "counter.jsonl")
        self.proofs_path = os.path.join(out_dir, "proofs.jsonl")
        self.counter_since = counter_since
        os.makedirs(out_dir, exist_ok=True)

    # --- sessions ----------------------------------------------------------------------------------------------
    def new_session(self, ip: str) -> tuple[Session, str]:
        sid = "v" + secrets.token_hex(8)
        self.limits.open_session(sid, ip)
        s = Session(sid, ip)
        cookie = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[sid], self.cookies[cookie] = s, sid
        return s, cookie

    def session_of(self, request: Request) -> Session | None:
        s = self.sessions.get(self.cookies.get(request.cookies.get("ks", ""), ""))
        if s and time.time() - s.seen <= IDLE_S and time.time() - s.created <= MAX_S:
            s.seen = time.time()
            return s
        return None

    def company(self, s: Session) -> SessionStack:
        with s.lock:
            if s.stack is None:
                c = self.factory.take()
                if c is None:
                    raise Refused("the demo is busy right now; please try again in a minute")
                s.stack = SessionStack(self.kc_base, self.out_dir, self.master, c).create()
                self.push.register(s.stack.realm, s.stack.push)
                threading.Thread(target=self._watch, args=(s,), daemon=True).start()
            return s.stack

    def end_session(self, s: Session, why: str) -> None:
        with self.lock:
            self.sessions.pop(s.id, None)
            for k, v in list(self.cookies.items()):
                if v == s.id:
                    self.cookies.pop(k)
        self.limits.close_session(s.id)
        if s.stack is not None:
            self.archive(s, why)                      # BEFORE the company is deleted: the counter never loses it
            self.push.unregister(s.stack.realm)
            self.factory.give_back(s.stack.realm)

    def sweep_once(self) -> None:
        now = time.time()
        for s in list(self.sessions.values()):
            if (now - s.seen > IDLE_S or now - s.created > MAX_S) and not s.busy:
                self.end_session(s, "idle" if now - s.seen > IDLE_S else "max lifetime")

    def run_background(self, every_s: float = 30.0) -> None:
        def loop():
            while True:
                try:
                    self.sweep_once()
                except Exception:                     # noqa: BLE001
                    pass
                time.sleep(every_s)
        threading.Thread(target=loop, daemon=True).start()

    # --- the event stream ----------------------------------------------------------------------------------
    def emit(self, s: Session, who: str, text: str, **extra) -> dict:
        with s.lock:
            e = {"seq": len(s.events), "t": round(time.time(), 2), "who": who, "text": text, **extra}
            s.events.append(e)
        return e

    def _watch(self, s: Session) -> None:
        """Turn the session's gate log into chat lines as it happens (the refusal and the push appear in front of the
        visitor, not after the model's turn)."""
        last_count = 0.0
        while s.id in self.sessions:
            try:
                ents = s.stack.ledger.entries()
            except Exception:                         # noqa: BLE001
                ents = []
            for e in ents[s.ledger_pos:]:
                self._narrate(s, e)
            s.ledger_pos = len(ents)
            if time.time() - last_count > 10:         # the live part of the counter, from the identity server's log
                last_count = time.time()
                try:
                    s.live = self.counts_of(s)
                except Exception:                     # noqa: BLE001
                    pass
            time.sleep(0.4)

    def counts_of(self, s: Session) -> dict:
        proof = self.proof(s)
        n_events = len(s.stack.events())
        made = sum(1 for p in proof if p["log"] != "none")
        return {"attempted": len(proof), "executed": made, "events": n_events,
                "without_approval": max(0, n_events - made)}

    def _account(self, s: Session, user_id: str | None) -> str:
        names = {v: k for k, v in s.stack.users().items()}
        return PEOPLE.get(names.get(user_id or "", ""), "an account")

    def _narrate(self, s: Session, e: dict) -> None:
        k, d = e["kind"], e["data"]
        if k == "decision" and d.get("method") in ("PUT", "POST", "DELETE"):
            act = ACTIONS.get(d.get("op") or "", "make a change")
            o = d.get("outcome")
            if o == "denied_no_receipt":
                self.emit(s, "gate", f"The gate refused this: to {act} on {self._account(s, d.get('user'))} it needs "
                          "approval on the owner's phone.", loud=True, ref=(d.get("request_hash") or "")[:4])
            elif o == "denied_cooling_off":
                self.emit(s, "status", "Approved. Waiting out a short cooling-off; the owner can still cancel.")
            elif o and o.startswith("denied"):
                self.emit(s, "gate", f"The gate refused this: {d.get('reason', 'not allowed')}.", loud=True)
        elif k == "challenge":
            st, cid = d.get("status"), d.get("challenge")
            c = s.stack.challenges._by_id.get(cid) if cid else None
            whose = SHORT.get(c.approver, c.approver) if c else "the owner"
            if st == "sent" and c is not None:
                self.emit(s, "phone", f"A request was sent to {whose}'s phone. Choose {c.number} on the phone.",
                          number=c.number, phone_of=c.approver)
            elif st == "approved":
                self.emit(s, "status", f"{whose} approved on the phone.")
            elif st == "denied":
                self.emit(s, "status", f"{whose} declined on the phone.")
            elif st == "expired":
                self.emit(s, "status", f"{whose} didn't answer; the request expired.")
            elif st == "human_only":
                self.emit(s, "status", "Policy: this account now needs a human (a recent request was declined, or "
                                       "there is no manager to approve).")
            elif st == "rate_limited":
                self.emit(s, "status", "Too many requests to that phone in a short time; no more are sent for now.")
        elif k == "executed":
            self.emit(s, "gate", f"Change made: {ACTIONS.get(d.get('op'), d.get('op'))} on "
                      f"{self._account(s, d.get('user'))}, after the approval.", ok=True)
        elif k == "quarantine":
            self.emit(s, "gate", f"The run was stopped: {d.get('reason')}.", loud=True)
        elif k == "escalation":
            self.emit(s, "status", "The agent handed this to a human colleague.")

    # --- conversations ---------------------------------------------------------------------------------------
    def say(self, s: Session, text: str, scenario: str | None, ticket: str | None, prompt: str | None = None) -> None:
        text = text.strip()[:MAX_TEXT]
        if not text:
            raise Refused("type a message first")
        self.emit(s, "you", text)
        if s.busy:
            s.inbox.put(text)                          # queued; it is already shown as sent
            return
        sc = SCENARIOS.get(scenario or "")
        s.ticket = (ticket or (sc["ticket"] if sc else "") or DEFAULT_TICKET).strip()[:MAX_TICKET]
        s.prompt = "hardened" if prompt == "hardened" else "light"
        reserved = self.limits.reserve_ticket(s.id)    # BEFORE any model call
        s.busy = True
        threading.Thread(target=self._converse, args=(s, text, reserved), daemon=True).start()

    def _converse(self, s: Session, first: str, reserved: float) -> None:
        spent, runner = 0.0, None
        with self.lock:
            self.waiting += 1
        if not self.slots.acquire(blocking=False):
            self.emit(s, "status", "The demo is busy; you are in the queue.")
            self.slots.acquire()
        with self.lock:
            self.waiting -= 1
        try:
            stack = self.company(s)
            rid = runkey.new_run_id()
            s.run_id = rid
            stack.app.state.open_run(rid, "full")
            self.broker.register(rid, stack.app, Timing())
            host = self.hosts[secrets.randbelow(len(self.hosts))]
            runner = DockerRunner(rid, s.ticket, upstream=self.edge_upstream, run_key=runkey.task_key(self.master, rid),
                                  realm=stack.realm, docker_host=host, timeout_s=60,
                                  runtime="runsc" if (host or "").startswith("ssh://") else None).start()
            if os.environ.get("KEYLESS_DEMO_FAKE_LLM") == "1":
                from eval.fake_llm import FakeLLM
                llm = FakeLLM(self.model)
            else:
                llm = LLM(models=[self.model], cap_usd=reserved)
            deadline = time.time() + CONVERSATION_WALL_S
            n = {"script": 0}

            def on_event(kind: str, data: dict) -> None:
                if kind == "thinking":
                    s.typing = True
                elif kind == "tool_call":
                    s.typing = False
                    n["script"] += 1
                    code = data.get("code", "")
                    words = next((w for f, w in STEP_WORDS if f + "(" in code), "running a script")
                    self.emit(s, "step", f"{words[0].upper()}{words[1:]} (script {n['script']} in a fresh sandbox)",
                              code=code[:4000])
                elif kind == "tool_result":
                    with s.lock:
                        for ev in reversed(s.events):
                            if ev["who"] == "step" and "output" not in ev:
                                ev["output"] = (data.get("stdout", "") + ("\n" + data["stderr"] if data.get("stderr")
                                                                          else ""))[-3000:]
                                ev["exit"] = data.get("exit")
                                break
                elif kind == "reply":
                    s.typing = False
                    said = data.get("model_said") or ""
                    struck = []
                    if data.get("verdict") == "corrected":
                        struck = [m.group(0).strip() for m in claims.SENTENCE.finditer(said)
                                  if claims.claims_a_change(m.group(0))]
                    self.emit(s, "agent", said, struck=struck)
                    self.emit(s, "system", data.get("changes_line", ""))

            def on_reply(_delivered: str):
                if time.time() > deadline:
                    return None
                try:
                    return s.inbox.get(timeout=min(WAIT_FOR_VISITOR_S, max(deadline - time.time(), 1)))
                except queue.Empty:
                    return None
            prompt = HARDENED if s.prompt == "hardened" else LIGHT
            res = run_ticket(llm, runner, rid, first, stack.ledger.path, prompt=prompt, on_reply=on_reply,
                             on_event=on_event, max_turns=MAX_TURNS)
            spent = llm.spent
            if res.stop in ("max_turns", "cap"):
                self.emit(s, "status", "This conversation reached its step limit.")
            elif res.stop == "error":
                self.emit(s, "status", "The model service failed; nothing was changed by that.")
            time.sleep(1.0)                            # let the watcher post the last gate lines
            stack.app.state.close_run(rid)
            for c in list(stack.challenges._by_id.values()):   # the conversation is over: its open pushes expire
                if c.run_id == rid and c.status == "sent":
                    stack.challenges.expire_now(c.binding)
                    for p in stack.push.state.pending.values():
                        if p.get("binding") == c.binding and p.get("state") == "pending":
                            p["state"] = "expired"
            self.summarize(s, rid)
        except Refused as e:
            self.emit(s, "status", e.reason)
        except Exception as e:                         # noqa: BLE001  never a stack trace to the visitor
            self.emit(s, "status", f"Something went wrong ({type(e).__name__}); nothing was changed by it.")
        finally:
            s.typing = False
            if runner:
                try:
                    runner.close()
                except Exception:                      # noqa: BLE001
                    pass
            self.slots.release()
            self.limits.settle_ticket(s.id, reserved, spent)
            s.conversations += 1
            s.busy = False

    def summarize(self, s: Session, run_id: str) -> None:
        proof = self.proof(s, run_id)                  # this conversation only
        tried = sorted({p["action"] for p in proof})
        refused = sum(1 for p in proof if p["refused"])
        asked = [p for p in proof if p["phone"] != "not asked"]
        done = [p for p in proof if p["log"] != "none"]
        if not proof:
            text = "The agent made no account change and asked for none. The identity server's log is unchanged."
        else:
            text = (f"The agent tried to {', '.join(tried)}. The gate refused {refused} of {len(proof)} until the "
                    f"owner's phone answered. The phone was asked {len(asked)} time(s) "
                    f"({', '.join(p['phone'] for p in asked) or 'never'}). "
                    + (f"The identity server's log recorded {len(done)} change(s), each after an approval."
                       if done else "The identity server's log recorded nothing."))
        token = secrets.token_urlsafe(10)
        self.emit(s, "summary", text, permalink=f"/p/{token}")
        with self.lock, open(self.proofs_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"token": token, "t": time.time(), "summary": text, "proof": proof,
                                "chat": [{k: e[k] for k in ("who", "text") if k in e} for e in s.events
                                         if e["who"] in ("you", "agent", "system", "gate", "phone", "summary")]})
                    + "\n")

    # --- the proof strip -----------------------------------------------------------------------------------
    def proof(self, s: Session, run_id: str | None = None) -> list[dict]:
        """One line per change requested (by its request hash), advancing: asked -> refused -> phone -> made, ending in
        the identity server's own log (an event, or none). run_id: one conversation only (for its summary)."""
        if s.stack is None:
            return []
        ents = s.stack.ledger.entries()
        if run_id:
            chal_ids = {c.id for c in s.stack.challenges._by_id.values() if c.run_id == run_id}
            ents = [e for e in ents if e["data"].get("run") == run_id or e["data"].get("challenge") in chal_ids]
        try:
            events = s.stack.events()
        except Exception:                              # noqa: BLE001
            events = []
        lines: dict[str, dict] = {}
        chal_status: dict[str, str] = {}
        for e in ents:
            d = e["data"]
            if e["kind"] == "challenge" and d.get("challenge"):
                chal_status[d["challenge"]] = d.get("status") or chal_status.get(d["challenge"], "")
            if e["kind"] not in ("decision", "forwarding") or d.get("method") not in ("PUT", "POST", "DELETE"):
                continue
            h = (d.get("request_hash") or "")[:8]
            ln = lines.setdefault(h, {"ref": h[:4], "action": ACTIONS.get(d.get("op") or "", "a change"),
                                      "account": self._account(s, d.get("user")), "refused": False,
                                      "phone": "not asked", "made": False, "log": "none", "op": d.get("op"),
                                      "user": d.get("user")})
            if e["kind"] == "decision" and str(d.get("outcome", "")).startswith("denied"):
                ln["refused"] = True
            if e["kind"] == "forwarding":
                ln["made"] = True
        for cid, st in chal_status.items():
            c = s.stack.challenges._by_id.get(cid)
            if c is None or (run_id and c.run_id != run_id):
                continue
            for ln in lines.values():
                if ln["op"] == c.operation and ln["user"] == c.user_id:
                    ln["phone"] = {"sent": "sent", "approved": "approved", "denied": "declined",
                                   "expired": "no answer", "rate_limited": "rate limited",
                                   "human_only": "needs a human"}.get(st, st)
        used = set()
        for ln in lines.values():
            if not ln["made"]:
                continue
            for i, ev in enumerate(events):
                k = "change_email" if ev["op"] == "user_update" else ev["op"]
                if i not in used and ev["user"] == ln["user"] and (k == ln["op"] or ln["op"] in (
                        "mfa_recovery_lost_device", "compromise_response")):
                    used.add(i)
                    ln["log"] = f"{ev['op'].replace('_', ' ')} at {time.strftime('%H:%M:%S', time.gmtime(ev['time'] / 1000))} UTC"
                    break
        return [{k: v for k, v in ln.items() if k not in ("op", "user")} for ln in lines.values()]

    def phone_view(self, s: Session) -> dict:
        view = {"owner": "cfo", "title": "Jordan Avery's phone", "subtitle": "CFO", "pending": [], "notices": [],
                "mail": 0}
        if s.stack is None:
            return view
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
                    nums = sorted(list(decoys) + [p["number"]])
                    s.candidates[p["id"]] = nums
                target = p["target"].split(".")[0] if p["target"].count(".") <= 1 else p["target"].rsplit(".", 1)[0]
                view["pending"].append({"id": p["id"], "phone_of": user,
                                        "action": ACTIONS.get({"reset": "reset_password", "email": "send_actions_email",
                                                               "rmcred": "remove_credential", "logout": "logout_sessions",
                                                               "emailchg": "change_email", "mfarecov":
                                                               "mfa_recovery_lost_device", "compromise":
                                                               "compromise_response", "verify": "identity_check"}
                                                              .get(p["label"], ""), p["label"]),
                                        "account": PEOPLE.get(target, target), "ref": p["binding"].rsplit("-", 1)[-1][:4],
                                        "someone_else": bool(p["instruction"]), "numbers": s.candidates[p["id"]]})
            for n in v["inbox"]:
                if n["kind"] == "notice":
                    view["notices"].append({"phone_of": user, "text": n["value"], "cancel_id": n.get("cancel_id")})
                elif n["kind"] == "temporary password":
                    view["notices"].append({"phone_of": user, "text": "Your temporary password arrived here (only "
                                            "here, never to the help desk).", "cancel_id": None})
        if view["pending"]:
            who = view["pending"][0]["phone_of"]
            view["owner"] = who
            view["title"], view["subtitle"] = ("Sam Lee's phone", "CEO, Jordan's manager") if who == "ceo" else \
                ("Jordan Avery's phone", "CFO")
        if self.mail_api:
            from eval import oracle
            view["mail"] = len(oracle.mails_for_realm(self.mail_api, s.stack.realm))
        return view

    # --- the counter ----------------------------------------------------------------------------------------
    def archive(self, s: Session, why: str) -> None:
        try:
            n = self.counts_of(s)
        except Exception as e:                         # noqa: BLE001  record that it could not be read
            n = {**(s.live or {"attempted": 0, "executed": 0, "events": 0, "without_approval": 0}),
                 "unreadable": type(e).__name__}
        rec = {"t": time.time(), "realm": s.stack.realm, "why": why, **n}
        s.live = {}
        with self.lock, open(self.counter_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")

    def counter(self) -> dict:
        tot = {"attempted": 0, "executed": 0, "without_approval": 0, "companies": 0}
        if os.path.exists(self.counter_path):
            for line in open(self.counter_path, encoding="utf-8"):
                r = json.loads(line)
                tot["companies"] += 1
                for k in ("attempted", "executed", "without_approval"):
                    tot[k] += r.get(k, 0)
        for s in list(self.sessions.values()):        # plus the companies still open
            if s.live:
                tot["companies"] += 1
                for k in ("attempted", "executed", "without_approval"):
                    tot[k] += s.live.get(k, 0)
        return {"since": self.counter_since, **tot}


def create_demo_app(demo: Demo) -> FastAPI:
    app = FastAPI(title="Keyless demo", docs_url=None, redoc_url=None, openapi_url=None)

    def err(msg: str, code: int = 400):
        return JSONResponse({"error": msg}, status_code=code)

    def same_site(request: Request) -> bool:
        return request.headers.get("sec-fetch-site") in (None, "same-origin")

    def need(request: Request):
        s = demo.session_of(request)
        if s is None:
            return None, err("no session (or it expired)", 401)
        if request.method == "POST" and not same_site(request):
            return None, err("cross-site request refused", 403)
        return s, None

    def with_cookie(resp: JSONResponse, cookie: str | None) -> JSONResponse:
        if cookie:
            resp.set_cookie("ks", cookie, httponly=True, secure=True, samesite="strict", max_age=MAX_S)
        return resp

    def ip_of(request: Request) -> str:
        return request.headers.get("x-forwarded-for", request.client.host if request.client else "?").split(",")[0].strip()

    @app.get("/")
    def page():
        return FileResponse(os.path.join(HERE, "static", "index.html"), headers={"Cache-Control": "no-store"})

    @app.get("/p/{token}")
    def permalink_page(token: str):
        return FileResponse(os.path.join(HERE, "static", "proof.html"), headers={"Cache-Control": "no-store"})

    @app.get("/api/proof/{token}")
    def permalink(token: str):
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,30}", token) or not os.path.exists(demo.proofs_path):
            return err("not found", 404)
        for line in open(demo.proofs_path, encoding="utf-8"):
            r = json.loads(line)
            if r["token"] == token:
                return r
        return err("not found", 404)

    @app.get("/healthz")
    def health():
        return {"ok": True, **demo.limits.status()}

    @app.get("/api/intro")
    def intro():
        return {"scenarios": [{"id": k, **{x: v[x] for x in ("chip", "kind", "caller", "ticket", "order")}}
                              for k, v in sorted(SCENARIOS.items(), key=lambda kv: kv[1]["order"])],
                "counter": demo.counter(), "limits": demo.limits.status()}

    @app.post("/api/say")
    async def say(request: Request):
        if not same_site(request):
            return err("cross-site request refused", 403)
        s, cookie = demo.session_of(request), None
        try:
            j = await request.json()
            if s is None:                              # the session starts on the first message
                s, cookie = demo.new_session(ip_of(request))
            demo.say(s, str(j.get("text", "")), j.get("scenario"), j.get("ticket"), j.get("prompt"))
        except Refused as x:
            return with_cookie(err(x.reason, 429), cookie)
        except (ValueError, KeyError, TypeError):
            return with_cookie(err("bad request"), cookie)
        return with_cookie(JSONResponse({"ok": True}), cookie)

    @app.get("/api/events")
    def events(request: Request, after: int = 0):
        s = demo.session_of(request)
        if s is None:
            return {"session": False, "events": [], "counter": demo.counter()}
        with s.lock:
            evs = s.events[max(after, 0):]
        return {"session": True, "events": evs, "typing": s.typing, "busy": s.busy, "queue": demo.waiting,
                "phone": demo.phone_view(s), "proof": demo.proof(s), "counter": demo.counter(),
                "prompt": s.prompt, "expires_in_s": int(min(IDLE_S - (time.time() - s.seen),
                                                            MAX_S - (time.time() - s.created)))}

    @app.post("/api/settings")
    async def settings(request: Request):
        s, e = need(request)
        if e:
            return e
        p = str((await request.json()).get("prompt", "light"))
        s.prompt = "hardened" if p == "hardened" else "light"
        return {"prompt": s.prompt}

    @app.post("/api/phone/{push_id}/{action}")
    async def phone(push_id: str, action: str, request: Request):
        s, e = need(request)
        if e:
            return e
        if s.stack is None or action not in ("approve", "deny", "noanswer"):
            return err("nothing to answer")
        pc = TestClient(s.stack.push)
        p = next((x for u in ("cfo", "ceo") for x in pc.get(f"/phone/{u}").json()["pending"] if x["id"] == push_id),
                 None)
        if p is None:
            return err("no such request on this phone", 404)
        if action == "deny":
            return {"ok": pc.post(f"/phone/{p['username']}/{push_id}/deny").status_code == 200}
        if action == "noanswer":
            s.stack.push.state.pending[push_id]["state"] = "expired"
            return {"ok": s.stack.challenges.expire_now(p["binding"])}
        number = str((await request.json()).get("number", ""))
        if number not in s.candidates.get(push_id, []):
            return err("pick one of the numbers shown")
        r = pc.post(f"/phone/{p['username']}/{push_id}/approve", json={"number": number})   # the server compares
        if r.status_code != 200:
            demo.emit(s, "status", "That number did not match the help desk's request; the approval was refused.")
        return {"ok": r.status_code == 200}

    @app.post("/api/phone/cancel/{cancel_id}")
    def cancel(cancel_id: str, request: Request):
        s, e = need(request)
        if e:
            return e
        if s.stack is None:
            return err("nothing to cancel")
        ok = TestClient(s.stack.push).post(f"/phone/cfo/cancel/{cancel_id}").status_code == 200
        if ok:
            demo.emit(s, "status", "Jordan cancelled the pending change from the phone.")
        return {"ok": ok}

    @app.post("/api/restart")
    def restart(request: Request):
        if not same_site(request):
            return err("cross-site request refused", 403)
        s = demo.session_of(request)
        if s is not None and not s.busy:
            demo.end_session(s, "visitor started over")
        r = JSONResponse({"ok": True})
        r.delete_cookie("ks")
        return r

    @app.exception_handler(Exception)
    async def never_a_trace(request: Request, exc: Exception):
        return JSONResponse({"error": "something went wrong; nothing was changed by it"}, status_code=500)
    return app
