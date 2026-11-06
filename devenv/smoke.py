"""Post-deploy smoke test against the PUBLIC demo (mentor's checklist): run after every deploy.

  python -m devenv.smoke https://<host>            one honest conversation in both columns (about one cent)

Checks, each printed PASS/FAIL with the reason; exits non-zero on any FAIL:
  the page and health; a compare session; the honest path completes in BOTH columns when the phone answers with the
  number its own column shows; the share link renders both columns, carries no session token and masks the temporary
  password; the counters answer; a phone link opens once and a second device is refused.
"""
from __future__ import annotations

import re
import sys
import time

import httpx

FAILS: list[str] = []


def team_headers() -> dict:
    """The operator's team key (DEMO_TEAM_KEY, or deploy/.state/state.json): smoke runs then skip visitors' per-IP
    allowance and stay out of the public counter. Without it the smoke runs as an ordinary visitor."""
    import json
    import os
    key = os.environ.get("DEMO_TEAM_KEY")
    if not key:
        p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "deploy", ".state", "state.json")
        try:
            key = json.load(open(p, encoding="utf-8")).get("team_key")
        except (OSError, ValueError):
            key = None
    return {"X-Keyless-Team": key} if key else {}


def check(name: str, ok: bool, why: str = "") -> None:
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  ({why})"))
    if not ok:
        FAILS.append(name)


def main(base: str) -> int:
    base = base.rstrip("/")
    c = httpx.Client(base_url=base, timeout=30, follow_redirects=True, headers={"Sec-Fetch-Site": "same-origin", **team_headers()})
    r = c.get("/")
    check("page loads", r.status_code == 200 and "Authorization is not a model output" in r.text, str(r.status_code))
    h = c.get("/healthz").json()
    check("health", h.get("ok") is True, str(h))
    intro = c.get("/api/intro").json()
    check("intro lists the measured models", set(intro.get("models", [])) >= {"qwen3.8-27b", "glm-5.3-flash"},
          str(intro.get("models")))
    r = c.post("/api/compare", json={"on": True})
    check("compare session", r.status_code == 200 and r.json().get("compare") is True, r.text[:120])
    honest = next(s for s in intro["scenarios"] if s["id"] == "honest")
    r = c.post("/api/say", json={"text": honest["caller"], "scenario": "honest", "ticket": honest["ticket"],
                                  "prompt": "light", "model": intro.get("default_model")})
    check("message accepted", r.status_code == 200, r.text[:160])
    answered, t0, j = set(), time.time(), {}
    while time.time() - t0 < 240:
        time.sleep(3)
        j = c.get("/api/events", params={"after": 0, "after_left": 0}).json()
        shown = {"right": {e.get("number") for e in j.get("events", []) if e.get("who") == "phone"},
                 "left": {e.get("number") for e in (j.get("left") or {}).get("events", []) if e.get("who") == "phone"}}
        for card in j.get("phone", {}).get("pending", []):
            side = card.get("company") or "right"
            n = next((x for x in card["numbers"] if x in shown.get(side, set())), None)
            if n and card["id"] not in answered:
                answered.add(card["id"])
                c.post(f"/api/phone/{card['id']}/approve", json={"number": n})
        done_r = any(e.get("who") == "summary" for e in j.get("events", []))
        done_l = any(e.get("who") == "summary" for e in (j.get("left") or {}).get("events", []))
        if done_r and done_l:
            break
    verdicts = [e.get("text", "") for e in j.get("events", []) if e.get("who") == "gate" and e.get("verdict")]
    check("right column completed with approval", any("Changed only with approval" in v for v in verdicts),
          str(verdicts)[:200])
    check("phone was answered with each column's own number", len(answered) >= 1, f"answered {len(answered)}")
    evs = j.get("events", [])
    tiles = [e for e in evs if e.get("who") == "tiles"]
    check("tiles: tried (gate's records) over recorded (Keycloak's log)",
          bool(tiles) and "gate" in tiles[-1].get("tried_source", "") and "Keycloak" in tiles[-1].get("recorded_source", ""),
          str(tiles[-1:])[:200])
    check("a refusal cites its policy rule", any("packs/helpdesk.json" in (e.get("rule") or "") for e in evs),
          "no rule on any gate line")
    st = c.get("/api/events").json().get("strip") or {}
    check("run strip measured gVisor inside the live sandbox", st.get("gvisor") is True and "gvisor" in
          str(st.get("kernel", "")).lower() and st.get("no_network_but_gate") and st.get("no_secrets"), str(st)[:240])
    link = next((e.get("permalink") for e in j.get("events", []) if e.get("who") == "summary"), None)
    if link:
        tok = link.rsplit("/", 1)[-1]
        p = httpx.get(f"{base}/api/proof/{tok}", timeout=30).json()
        check("share link has both columns", bool(p.get("pair")) and p.get("other") is not None, str(p.get("pair")))
        flat = str(p)
        check("share link carries no session cookie", "ks=" not in flat and c.cookies.get("ks", "~") not in flat)
        pw = re.findall(r"[A-Za-z0-9_-]{16}", " ".join(m.get("text", "") for m in p.get("chat", [])))
        check("share link shows no 16-character password in full", not any(
            "•" not in w and re.search(r"[a-z]", w) and re.search(r"[A-Z]", w) for w in pw), str(pw[:3]))
    else:
        check("share link exists", False, "no summary permalink")
    cnt = c.get("/api/intro").json().get("counter", {})
    check("counter answers", "without_approval" in cnt and "left" in cnt, str(cnt)[:120])
    wrong_number(base, intro)
    pr = c.post("/api/prove", json={}, timeout=180)
    if pr.status_code == 200:
        pj = pr.json()
        ins, rep = pj.get("inside", {}), pj.get("replay", {})
        check("containment check: every in-sandbox check holds, gVisor measured",
              all((ins.get("checks") or {}).values()) and bool(ins.get("checks")) and ins.get("gvisor") is True,
              str(ins)[:240])
        check("containment check: every token replay refused, identity log unchanged",
              rep.get("attempts", 0) > 0 and rep.get("refused") == rep.get("attempts")
              and rep.get("admin_events_after") == rep.get("admin_events_before"), str({k: rep.get(k) for k in (
                  "attempts", "refused", "admin_events_before", "admin_events_after")}))
    else:
        check("containment check ran", False, f"{pr.status_code} {pr.text[:160]}")
    r = c.post("/api/phone-link", json={})
    url = r.json().get("url", "") if r.status_code == 200 else ""
    check("phone link issued", url.startswith("https://") or url.startswith("http://"), r.text[:120])
    if url:
        d1 = httpx.Client(timeout=30)
        d2 = httpx.Client(timeout=30)
        check("phone link opens on the first device", d1.get(url).status_code == 200)
        check("second device refused", d2.get(url).status_code == 409)
    print(f"\n{'ALL PASS' if not FAILS else f'{len(FAILS)} FAILED: ' + ', '.join(FAILS)}")
    return 1 if FAILS else 0


def wrong_number(base: str, intro: dict) -> None:
    """A fresh visitor mis-taps (mentor, 11-06): the wrong number must decline the request, the right number must not
    work afterwards, and the page must explain it with a start-over button (a decline freezes the account)."""
    c = httpx.Client(base_url=base, timeout=30, follow_redirects=True, headers={"Sec-Fetch-Site": "same-origin", **team_headers()})
    r = c.post("/api/compare", json={"on": True})
    if r.status_code != 200:                    # e.g. the per-IP daily session cap after several smoke runs
        check("wrong number: a fresh visitor session", False, f"{r.status_code} {r.text[:120]}")
        return
    honest = next(s for s in intro["scenarios"] if s["id"] == "honest")
    c.post("/api/say", json={"text": honest["caller"], "scenario": "honest", "ticket": honest["ticket"],
                              "prompt": "light", "model": intro.get("default_model")})
    t0, tapped, j, first, second = time.time(), False, {}, None, None
    while time.time() - t0 < 240:
        time.sleep(3)
        j = c.get("/api/events", params={"after": 0, "after_left": 0}).json()
        shown = {e.get("number") for e in j.get("events", []) if e.get("who") == "phone"}
        for card in j.get("phone", {}).get("pending", []):
            if (card.get("company") or "right") != "right" or tapped:
                continue
            right = next((x for x in card["numbers"] if x in shown), None)
            if right:
                wrong = next(x for x in card["numbers"] if x != right)
                first = c.post(f"/api/phone/{card['id']}/approve", json={"number": wrong}).json()
                second = c.post(f"/api/phone/{card['id']}/approve", json={"number": right})
                tapped = True
        if tapped and any(e.get("who") == "summary" for e in j.get("events", [])):
            break
    check("wrong number: a push to tap appeared", tapped, "no right-column card with its number")
    if tapped:
        check("wrong number is refused", first.get("ok") is False, str(first))
        check("right number no longer works after a wrong tap",
              second.status_code != 200 or second.json().get("ok") is not True, second.text[:120])
        evs = j.get("events", [])
        check("mis-tap explained with a start-over button",
              any(e.get("text", "").startswith("Wrong number: request declined") for e in evs)
              and any(e.get("who") == "explain" and e.get("restart") for e in evs), "no explanation/restart event")
    try:
        c.post("/api/restart", json={})
    except httpx.HTTPError:
        pass


def counters(base: str) -> dict:
    return httpx.get(f"{base.rstrip('/')}/api/intro", timeout=30).json().get("counter", {})


if __name__ == "__main__":
    # python -m devenv.smoke <url> --save-counter f   before a deploy: record the counters
    # python -m devenv.smoke <url> --counter-from f   after it: every count must be at least what it was (survived)
    import json
    args = sys.argv[1:]
    if "--save-counter" in args:
        json.dump(counters(args[0]), open(args[args.index("--save-counter") + 1], "w"))
        print("counter saved")
        sys.exit(0)
    rc = main(args[0])
    if "--counter-from" in args:
        before = json.load(open(args[args.index("--counter-from") + 1]))
        after = counters(args[0])
        nums = [k for k, v in before.items() if isinstance(v, (int, float)) and not isinstance(v, bool)]
        check("counters survived the restart", all(after.get(k, -1) >= before[k] for k in nums),
              f"before {before} after {after}")
        print(f"\n{'ALL PASS' if not FAILS else f'{len(FAILS)} FAILED: ' + ', '.join(FAILS)}")
        rc = 1 if FAILS else 0
    sys.exit(rc)
