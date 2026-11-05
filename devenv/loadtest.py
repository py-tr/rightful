"""Load test ON the control plane (mentor's checklist): N visitors at once, each running the measured attack in both
columns, through 127.0.0.1:8000 (each with its own X-Forwarded-For so the per-IP limit does not merge them). Watches
that every visitor is either served or told why (queue, limit), and samples memory while it runs.

  /opt/keyless/.venv/bin/python -m devenv.loadtest 20
"""
from __future__ import annotations

import subprocess
import sys
import threading
import time

import httpx

BASE = "http://127.0.0.1:8000"


def visitor(i: int, out: list) -> None:
    hdr = {"X-Forwarded-For": f"10.99.0.{i + 1}", "Sec-Fetch-Site": "same-origin"}
    c = httpx.Client(base_url=BASE, timeout=60, headers=hdr)
    t0 = time.time()
    rec = {"i": i, "ok": False, "why": "", "s": 0.0}
    try:
        r = c.post("/api/compare", json={"on": True})
        if r.status_code != 200:
            rec["why"] = f"session refused: {r.text[:80]}"
            return
        cookie = r.headers.get("set-cookie", "").split(";")[0]
        c.headers["Cookie"] = cookie
        intro = c.get("/api/intro").json()
        sc = next(s for s in intro["scenarios"] if s.get("compare_default"))
        r = c.post("/api/say", json={"text": sc["caller"], "scenario": sc["id"], "ticket": sc["ticket"],
                                      "prompt": "light", "model": intro["default_model"]})
        if r.status_code != 200:
            rec["why"] = f"message refused: {r.text[:80]}"
            return
        queued = False
        while time.time() - t0 < 600:
            time.sleep(4)
            j = c.get("/api/events", params={"after": 0, "after_left": 0}).json()
            ev = j.get("events", []) + (j.get("left") or {}).get("events", [])
            queued = queued or any("in the queue" in (e.get("text") or "") for e in ev)
            if sum(1 for e in ev if e.get("who") == "summary") >= 2:
                rec.update(ok=True, why="served" + (" after queueing" if queued else ""))
                return
        rec["why"] = "no summary within 10 min"
    except Exception as e:                             # noqa: BLE001
        rec["why"] = f"{type(e).__name__}: {e}"[:100]
    finally:
        rec["s"] = round(time.time() - t0)
        out.append(rec)


def main(n: int) -> int:
    out: list = []
    mem: list = []
    stop = threading.Event()

    def sample():
        while not stop.is_set():
            m = subprocess.run(["free", "-m"], capture_output=True, text=True).stdout.split("\n")[1].split()
            mem.append(int(m[2]))
            stop.wait(5)
    threading.Thread(target=sample, daemon=True).start()
    ts = [threading.Thread(target=visitor, args=(i, out)) for i in range(n)]
    for t in ts:
        t.start()
        time.sleep(0.3)
    for t in ts:
        t.join()
    stop.set()
    for r in sorted(out, key=lambda r: r["i"]):
        print(r)
    total = subprocess.run(["free", "-m"], capture_output=True, text=True).stdout.split("\n")[1].split()[1]
    print(f"served {sum(r['ok'] for r in out)}/{n}; memory used peak {max(mem)} MB of {total} MB; "
          f"slowest {max(r['s'] for r in out)} s")
    return 0


if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1]) if len(sys.argv) > 1 else 20))
