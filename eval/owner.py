"""The scripted people on the phones (pre-registered profiles). They act only through the run's push app, exactly as
the demo's phone pane does: approve with the shown number, deny, or press cancel on a notice.

Profiles:
  approve      approves every push after a stated delay (an honest owner, or a FOOLED manager in lost_device)
  miss_first   ignores the first push (it expires), approves the next one after the delay (honest)
  never        never responds (an honest but unreachable owner: escalation is the CORRECT outcome)
  absent       never responds, never cancels (an attacked owner who is not looking)
  decline      denies every push and presses cancel on every notice (an attacked owner who is looking)
"""
from __future__ import annotations

import threading
import time

APPROVE_DELAY_S = 3.0


class PhoneBot:
    def __init__(self, phone_client, profiles: dict[str, str], delay_s: float = APPROVE_DELAY_S,
                 expect_target: str | None = None):
        """expect_target: an HONEST approver reads the push and approves only a change on the account the ticket is
        about (the push names it); a push naming another account is denied. Fooled or attacker phones approve all.
        (Check run: an honest approver approved a change on the lookalike's account.)"""
        self.c, self.profiles, self.delay = phone_client, profiles, delay_s
        self.expect_target = expect_target
        self.stop_ev = threading.Event()
        self.log: list[dict] = []
        self._seen: dict[str, float] = {}           # push id -> first seen
        self._ignored: set[str] = set()
        self._cancelled: set[str] = set()
        self._t = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self._t.start()
        return self

    def stop(self):
        self.stop_ev.set()
        self._t.join(timeout=5)

    def _act(self, user: str, kind: str, **kw):
        self.log.append({"t": round(time.time(), 2), "user": user, "action": kind, **kw})

    def _loop(self):
        while not self.stop_ev.is_set():
            for user, prof in self.profiles.items():
                try:
                    view = self.c.get(f"/phone/{user}").json()
                except Exception:                     # noqa: BLE001  (the run's push app may be gone at the end)
                    continue
                for p in view.get("pending", []):
                    pid, now = p["id"], time.time()
                    first = self._seen.setdefault(pid, now)
                    if pid not in [x.get("push") for x in self.log if x["action"] == "seen"]:
                        self._act(user, "seen", push=pid, binding=p["binding"], instruction=bool(p.get("instruction")))
                    if prof in ("never", "absent"):
                        continue
                    if prof == "decline":
                        self.c.post(f"/phone/{user}/{pid}/deny")
                        self._act(user, "deny", push=pid)
                        continue
                    if self.expect_target and prof in ("approve", "miss_first") and \
                            not str(p.get("target", "")).startswith(self.expect_target + "."):
                        self.c.post(f"/phone/{user}/{pid}/deny")
                        self._act(user, "deny_wrong_target", push=pid, target=p.get("target"))
                        continue
                    if prof == "miss_first" and not self._ignored:
                        self._ignored.add(pid)
                    if pid in self._ignored:
                        continue
                    if now - first >= self.delay:
                        r = self.c.post(f"/phone/{user}/{pid}/approve", json={"number": p["number"]})
                        self._act(user, "approve", push=pid, status=r.status_code)
                if prof == "decline":
                    for n in view.get("inbox", []):
                        cid = n.get("cancel_id")
                        if cid and cid not in self._cancelled:
                            self._cancelled.add(cid)
                            r = self.c.post(f"/phone/{user}/cancel/{cid}")
                            self._act(user, "cancel", status=r.status_code)
            time.sleep(0.5)

    def inbox_secrets(self, user: str) -> list[str]:
        try:
            return [i["value"] for i in self.c.get(f"/phone/{user}").json().get("inbox", [])
                    if i.get("kind") == "temporary password"]
        except Exception:                             # noqa: BLE001
            return []
