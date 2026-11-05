"""In-process fuzzer for everything that stands between the sandbox and Keycloak (mentor's review: aim where the two
bugs were, then widen). Seeded and reproducible; no model calls, no network, $0.

Targets, in order: the console route (paths + the rebuilt token-endpoint body), the read query decoder, the write
body checker (type coercions, nesting, enum variants, large bodies), the whole broker with no receipts, and the
signature verifier. A FAILURE is any of:
  - a request reaching the (fake) Keycloak that is not exactly one parsed, allowlisted operation;
  - a write reaching Keycloak without a burned receipt (there are none here, so: any write at all);
  - a real token or secret string in a response body;
  - an exception or a 5xx from the broker;
  - a quarantine triggered by a well-formed request.
False rejections of known-legitimate requests are counted separately (a utility bug, like the q= lesson).

Run: python -m devenv.fuzz [N per target] [seed]      (the unit suite runs a small N: tests/test_fuzz.py)
"""
from __future__ import annotations

import json
import random
import sys
import time
from urllib.parse import parse_qsl

import httpx

from broker import runkey
from broker.app import create_app
from broker.challenges import Challenges
from broker.console import ConsoleSession
from broker.keycloak import Keycloak, KeycloakConfig
from gate import Gate, Ledger, Reject, ReceiptStore, load_pack, parse

PACK = load_pack("helpdesk")
U = "d02cbf80-c4a5-4c86-9912-27a5a18fb8cd"
C = "0b9b2a3e-1111-4c86-9912-27a5a18fb8cd"
SECRET_TOKEN = "REAL-SA-TOKEN-zzz"
REALM = "corp"
TOKEN_PATH = f"/realms/{REALM}/protocol/openid-connect/token"

# --- building blocks ------------------------------------------------------------------------------------------
SEGMENT_TRICKS = ["..", ".", "%2e%2e", "%2E%2E", ".%2e", "%2e.", "..;", ";", ";x=y", "%2f", "%2F", "%5c", "\\", "//",
                  "%00", "%20", " ", "\t", "%09", "%c0%ae%c0%ae", "‥", "．．", "%25%32%65", "admin",
                  "ADMIN", "Admin", "realms", "users", U, U.upper(), C, "", "~", "*", "@", "#", "?", "&"]
PREFIXES = ["/resources/", f"/realms/{REALM}/", f"/admin/{REALM}/console/", f"/admin/realms/{REALM}/",
            f"/admin/realms/{REALM}/users/{U}/", "/admin/", "/", "/admin/master/console/", "/realms/master/"]
SUFFIXES = ["reset-password", "execute-actions-email", f"credentials/{C}", "logout", "", "role-mappings/realm",
            "events/config", "admin-events", "clients", "users", f"users/{U}/reset-password", "app.js", "whoami"]
GRANTS = ["authorization_code", "refresh_token", "password", "client_credentials",
          "urn:openid:params:grant-type:ciba", "urn:ietf:params:oauth:grant-type:token-exchange", "", "REFRESH_TOKEN",
          "refresh_token ", "refresh%5Ftoken"]
CLIENTS = ["security-admin-console", "admin-cli", "gate-broker", "gate-ciba", "account", "SECURITY-ADMIN-CONSOLE",
           "security-admin-console ", "", "security-admin-console%00"]
FIELDS = ["grant_type", "client_id", "code", "redirect_uri", "code_verifier", "refresh_token", "scope", "username",
          "password", "client_secret", "auth_req_id", "subject_token", "audience", "requested_subject"]
WEIRD_VALUES = ["", "x", "0", "-1", "1e9", "true", "null", "[]", "{}", "a" * 5000, "%00", "‮", "..", "😀",
                "'; DROP TABLE x;--", "${jndi:ldap://x}", "{{7*7}}"]


def rand_path(r: random.Random) -> str:
    p = r.choice(PREFIXES)
    for _ in range(r.randint(0, 4)):
        p += r.choice(SEGMENT_TRICKS) + r.choice(["/", "/", "", "//"])
    p += r.choice(SUFFIXES)
    if r.random() < 0.3:
        p += r.choice(["/", "?", "?a=1", "?q=", "?q=manager:ceo", "?search=x%40y", "?max=%zz", "#frag", "?lifespan=900",
                       "?a=1&a=2", "?search=%25%32%65"])
    return p


def rand_form(r: random.Random) -> bytes:
    pairs = [("grant_type", r.choice(GRANTS)), ("client_id", r.choice(CLIENTS))]
    for _ in range(r.randint(0, 4)):
        pairs.append((r.choice(FIELDS), r.choice(WEIRD_VALUES + ["c1", "v", "http://gate:8080/admin"])))
    r.shuffle(pairs)
    raw = "&".join(f"{k}={v}" for k, v in pairs)
    if r.random() < 0.15:
        raw = r.choice([raw + "&", "&" + raw, raw.replace("=", "%3D", 1), raw + "&grant_type=password",
                        raw.encode("utf-16").decode("latin-1"), json.dumps(dict(pairs))])
    return raw.encode("utf-8", "surrogatepass")


def rand_json_body(r: random.Random, depth: int = 0):
    kind = r.randint(0, 9 if depth < 3 else 5)
    if kind == 0:
        return r.choice([True, False, None, 0, 1, -1, 1.5, 10 ** 30])
    if kind <= 3:
        return r.choice(WEIRD_VALUES + ["password", "UPDATE_PASSWORD", "CONFIGURE_TOTP", "jordan@corp.example"])
    if kind <= 5:
        return [rand_json_body(r, depth + 1) for _ in range(r.randint(0, 3))]
    keys = ["type", "temporary", "value", "email", "attributes", "enabled", "username", "credentials", "realmRoles",
            "requiredActions", "Type", "type ", "__proto__", "constructor"]
    return {r.choice(keys): rand_json_body(r, depth + 1) for _ in range(r.randint(0, 4))}


VALID_WRITES = [
    ("PUT", f"/admin/realms/{REALM}/users/{U}/reset-password", {"type": "password", "temporary": True}),
    ("PUT", f"/admin/realms/{REALM}/users/{U}/execute-actions-email?lifespan=600", ["UPDATE_PASSWORD"]),
    ("PUT", f"/admin/realms/{REALM}/users/{U}", {"email": "jordan.new@corp.example"}),
    ("DELETE", f"/admin/realms/{REALM}/users/{U}/credentials/{C}", None),
    ("POST", f"/admin/realms/{REALM}/users/{U}/logout", None),
    ("POST", f"/gate/v1/actions/mfa-recovery-lost-device/{U}", None),
]


def near_valid(r: random.Random) -> tuple[str, str, bytes]:
    """A legitimate write with one or two mutations: where a checker is most likely to be wrong."""
    m, t, b = r.choice(VALID_WRITES)
    b = json.loads(json.dumps(b))
    for _ in range(r.randint(1, 2)):
        k = r.randint(0, 9)
        if isinstance(b, dict) and b and k <= 3:
            key = r.choice(list(b))
            b[key] = r.choice(["true", 1, "True", None, [b[key]], {"$ne": None}, "password ", "PASSWORD",
                               "pass​word", "jordan@corp.example\nBcc: x@evil", "jordan@corp.example\n",
                               "jordan@corp.example\r", "a@b@c", "@evil", 1e309, 1.0, 0, False])
        elif isinstance(b, dict) and k <= 6:
            b[r.choice(["value", "attributes", "username", "enabled", "credentials", "realmRoles", "Type", "email ",
                        "requiredActions", "groups", "federationLink"])] = rand_json_body(r)
        elif isinstance(b, list) and k <= 6:
            b = r.choice([b + ["CONFIGURE_TOTP"], b + ["UPDATE_PROFILE"], ["update_password"], [], b * 50,
                          ["UPDATE_PASSWORD", None], [["UPDATE_PASSWORD"]], "UPDATE_PASSWORD"])
        elif k == 7:
            t = t.replace("lifespan=600", r.choice(["lifespan=1", "lifespan=99999999", "lifespan=-5", "lifespan=6e2",
                                                    "lifespan=600&lifespan=1", "lifespan=600&redirect_uri=http://evil",
                                                    "client_id=evil&lifespan=600"])) if "?" in t else t + "?x=1"
        elif k == 8:
            b = b if b is not None else r.choice([{}, [], "x", {"a": 1}])
        else:
            m = r.choice(["PUT", "POST", "DELETE", "GET"])
    raw = json.dumps(b).encode() if b is not None else b""
    if raw and r.random() < 0.2:                     # textual variants json.dumps never produces
        raw = r.choice([raw.replace(b'"type"', b'"type":"x","type"', 1), raw + b" ", b"\xef\xbb\xbf" + raw,
                        raw.replace(b": ", b":"), raw + b"\x00", raw.replace(b"true", b"TRUE"), raw[:-1]])
    return m, t, raw


# --- target 1: the console route ------------------------------------------------------------------------------
def fuzz_console(n: int, seed: int) -> dict:
    r = random.Random(seed)
    seen = []

    def handler(req):
        seen.append(req)
        if req.url.path == TOKEN_PATH:
            return httpx.Response(200, json={"access_token": "h.p.REALSIG", "refresh_token": "h.p.REALSIG2"})
        return httpx.Response(200, text="ok")
    s = ConsoleSession("http://kc:8080", "http://gate:8080", REALM, "helpdesk-console", "pw")
    s.http = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    fails, errors = [], 0
    for i in range(n):
        method = r.choice(["GET", "GET", "POST", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"])
        path = r.choice([rand_path(r), TOKEN_PATH, TOKEN_PATH + r.choice(["/", ";x", "%2f", "/../token"])])
        body = rand_form(r) if method == "POST" else (b"" if r.random() < 0.8 else b"x")
        headers = {"Content-Type": "application/x-www-form-urlencoded",
                   r.choice(["X-HTTP-Method-Override", "X-Forwarded-Host", "X-Original-URL", "Origin", "Cookie",
                             "Authorization", "Host"]): r.choice(["PUT", "evil", "/admin/realms/corp", "Bearer h.p.x"])}
        before = len(seen)
        try:
            status, _, data = s.handle(method, path, headers, body)
        except Exception as e:                                      # noqa: BLE001  (any exception is a finding)
            errors += 1
            fails.append(f"exception {type(e).__name__}: {method} {path[:80]}")
            continue
        for req in seen[before:]:
            up = req.url.raw_path.decode("latin-1").split("?")[0]
            ok_get = req.method in ("GET", "HEAD") and up.startswith(s.routes) and not any(
                t in up for t in ("..", "%", ";", "//", "\\"))
            ok_post = False
            if req.method == "POST" and up == TOKEN_PATH:
                form = dict(parse_qsl(req.content.decode()))
                g = form.get("grant_type")
                ok_post = g in s.TOKEN_GRANTS and form.get("client_id") == s.CONSOLE_CLIENT \
                    and set(form) <= s.TOKEN_GRANTS[g]
            bad_hdr = [k for k in req.headers if k.lower() not in
                       ("accept", "accept-language", "content-type", "authorization", "host", "cookie",
                        "content-length", "accept-encoding", "connection", "user-agent")]
            if not (ok_get or ok_post) or bad_hdr:
                fails.append(f"REACHED {req.method} {up[:90]} hdr={bad_hdr} (sent {method} {path[:60]})")
        if b"REALSIG" in (data or b""):
            fails.append(f"real token in response: {method} {path[:80]}")
    return {"target": "console route", "cases": n, "failures": fails[:20], "n_failures": len(fails),
            "exceptions": errors, "reached_upstream": len(seen)}


# --- targets 2 and 3: the grammar (read query decoder, write body checker) ------------------------------------
def fuzz_grammar(n: int, seed: int) -> dict:
    r = random.Random(seed)
    fails, accepted = [], {"read": 0, "write": 0, "composite": 0}
    write_paths = [f"/admin/realms/{REALM}/users/{U}/reset-password", f"/admin/realms/{REALM}/users/{U}",
                   f"/admin/realms/{REALM}/users/{U}/execute-actions-email", f"/admin/realms/{REALM}/users/{U}/logout",
                   f"/admin/realms/{REALM}/users/{U}/credentials/{C}",
                   f"/gate/v1/actions/mfa-recovery-lost-device/{U}"]
    for i in range(n):
        method = r.choice(["GET", "PUT", "POST", "DELETE"])
        if r.random() < 0.5:
            method, target, body = near_valid(r)
            _check_one(method, target, body, fails, accepted)
            continue
        if r.random() < 0.5:
            target = r.choice(write_paths)
            if r.random() < 0.5:
                target = target.replace(r.choice(["/", "users", U, "corp"]), r.choice(SEGMENT_TRICKS) or "/", 1)
        else:
            target = rand_path(r)
        if r.random() < 0.4:
            q = "&".join(f"{r.choice(['search', 'max', 'first', 'q', 'lifespan', 'exact', 'x', 'search%00'])}="
                         f"{r.choice(WEIRD_VALUES + ['jordan', '%40', '%2540', '900', 'a%20b'])}"
                         for _ in range(r.randint(1, 3)))
            target += ("&" if "?" in target else "?") + q
        body = json.dumps(rand_json_body(r)).encode() if method in ("PUT", "POST") and r.random() < 0.8 else b""
        if r.random() < 0.05:
            body = b'{"type":"password","temporary":true,"value":"' + b"A" * 2_000_000 + b'"}'
        _check_one(method, target, body, fails, accepted)
    return {"target": "grammar (reads + write bodies)", "cases": n, "accepted": accepted, "failures": fails[:20],
            "n_failures": len(fails)}


def _body_conforms(op_name: str, canon: bytes) -> str | None:
    """The canonical body may contain only what the pack declares, with exact JSON types."""
    spec = PACK["writes"][op_name]["body"]
    data = json.loads(canon) if canon else None
    if spec["type"] == "none":
        return None if not canon else "a body on a no-body operation"
    if spec["type"] == "array_enum":
        if not isinstance(data, list) or not data or any(not isinstance(x, str) or x not in spec["enum"] for x in data):
            return f"array outside the enum: {data!r:.80}"
        return None
    if not isinstance(data, dict):
        return "object expected"
    extra = set(data) - set(spec["fields"])
    if extra:
        return f"undeclared field(s) {sorted(extra)[:3]}"
    for k, v in data.items():
        f = spec["fields"][k]
        if "enum" in f and not any(type(v) is type(e) and v == e for e in f["enum"]):
            return f"{k}={v!r} is not exactly one of {f['enum']}"
        if f.get("type") == "string" and not isinstance(v, str):
            return f"{k} is not a string"
    return None


def _check_one(method: str, target: str, body: bytes, fails: list, accepted: dict) -> None:
    try:
        op = parse(PACK, method, target, body)
    except Reject:
        return
    except Exception as e:                                          # noqa: BLE001
        fails.append(f"exception {type(e).__name__}: {method} {target[:80]} body={body[:60]!r}")
        return
    accepted[op.kind] = accepted.get(op.kind, 0) + 1
    # Oracle: what the gate would forward is canonical and re-parses to the same operation and hash.
    canon_target = op.path + ("?" + "&".join(f"{k}={v}" for k, v in op.query) if op.query else "")
    try:
        again = parse(PACK, method, canon_target, op.canonical_body)
    except Exception as e:                                          # noqa: BLE001
        fails.append(f"canonical form does not re-parse ({type(e).__name__}): {method} {target[:80]}")
        return
    if (again.name, again.request_hash) != (op.name, op.request_hash):
        fails.append(f"canonical form changes meaning: {method} {target[:80]}")
    if any(t in op.path for t in ("..", "%", ";", "//", "\\", " ")):
        fails.append(f"accepted a tricky path: {method} {op.path[:80]}")
    if op.kind == "write":
        if len(op.canonical_body) > 10_000:
            fails.append(f"accepted a huge write body ({len(op.canonical_body)} bytes): {op.name}")
        why = _body_conforms(op.name, op.canonical_body)
        if why:
            fails.append(f"{op.name}: accepted body does not conform ({why}); sent {body[:80]!r}")
        for k, v in op.query:
            allowed = PACK["writes"][op.name].get("query", {})
            if k not in allowed:
                fails.append(f"{op.name}: undeclared query key {k!r} accepted")


# --- target 4: the whole broker, no receipts ------------------------------------------------------------------
def fuzz_broker(n: int, seed: int, tmp: str) -> dict:
    r = random.Random(seed)
    upstream = []

    def handler(req):
        if req.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": SECRET_TOKEN, "expires_in": 300})
        upstream.append((req.method, req.url.raw_path.decode("latin-1")))
        if req.method == "GET":
            return httpx.Response(200, json={"id": U, "username": "cfo", "attributes": {"manager": ["ceo"]}})
        return httpx.Response(204)
    kc = Keycloak(KeycloakConfig("http://kc", REALM, "b", "s", "c", "s"),
                  http=httpx.Client(base_url="http://kc", transport=httpx.MockTransport(handler)))
    receipts = ReceiptStore(":memory:")
    gate = Gate(PACK, receipts, Ledger(f"{tmp}/fuzz-ledger-{seed}.jsonl"))
    app = create_app(gate, kc, Challenges(kc, receipts, min_poll_interval=0))
    from fastapi.testclient import TestClient
    c = TestClient(app, raise_server_exceptions=False)
    fails, quarantines_wellformed, statuses, unsendable = [], 0, {}, 0
    for i in range(n):
        run = f"fz-{seed}-{i}"
        method = r.choice(["GET", "PUT", "POST", "DELETE", "PATCH"])
        path = rand_path(r) if r.random() < 0.7 else r.choice(
            [f"/admin/realms/{REALM}/users/{U}/reset-password", f"/gate/v1/actions/compromise-response/{U}",
             f"/gate/v1/challenges/chl_{i}/send", f"/admin/realms/{REALM}/users?search=cfo&max=5"])
        body = json.dumps(rand_json_body(r)).encode() if method != "GET" and r.random() < 0.7 else b""
        if r.random() < 0.4:
            method, path, body = near_valid(r)
        before = len(upstream)
        try:
            resp = c.request(method, path, content=body, headers={"X-Gate-Run": run})
        except httpx.InvalidURL:
            unsendable += 1                 # this client cannot send raw control bytes; the edge target covers those
            continue
        except Exception as e:                                      # noqa: BLE001
            fails.append(f"client exception {type(e).__name__}: {method} {path[:80]}")
            continue
        statuses[resp.status_code] = statuses.get(resp.status_code, 0) + 1
        if resp.status_code >= 500:
            fails.append(f"{resp.status_code} on {method} {path[:80]}")
        if SECRET_TOKEN in resp.text:
            fails.append(f"secret in response: {method} {path[:80]}")
        for m, p in upstream[before:]:
            if m != "GET":
                fails.append(f"WRITE REACHED KEYCLOAK without a receipt: {m} {p[:90]} (sent {method} {path[:60]})")
        try:
            wellformed = True
            parse(PACK, method, path, body)
        except Reject:
            wellformed = False
        except Exception:                                           # noqa: BLE001
            wellformed = False
        if wellformed and resp.status_code == 403 and '"quarantined": true' in resp.text.replace('":true', '": true'):
            quarantines_wellformed += 1
            fails.append(f"quarantine on a well-formed request: {method} {path[:80]}")
    return {"target": "broker (no receipts)", "cases": n, "status_counts": statuses, "upstream_reads": len(upstream),
            "failures": fails[:20], "n_failures": len(fails), "wellformed_quarantines": quarantines_wellformed,
            "not_sendable_by_this_client": unsendable}


# --- target 5: the signature verifier -------------------------------------------------------------------------
def fuzz_signatures(n: int, seed: int) -> dict:
    r = random.Random(seed)
    master = bytes(range(32))
    fails = []
    now = time.time()
    for i in range(n):
        run = r.choice(["run-1", "", "run-1\n", "run-2", "x" * 70, "run-1 ", "RUN-1"])
        ts = r.choice([str(int(now)), str(now), "", "nan", "inf", "-inf", "1e400", "0x10", " 1", str(int(now) + 10 ** 9),
                       "١٢٣", str(int(now)) + "\x00"])
        good = runkey.sign(runkey.task_key(master, "run-1"), "run-1", str(int(now)), "GET", "/x", b"")
        sig = r.choice([good, good.upper(), good[:-1], good + "0", "", "z" * 64, "\u0000" * 64, "0" * 64, good[::-1]])
        try:
            res = runkey.verify(master, run, ts, sig, "GET", "/x", b"", now=now)
        except Exception as e:                                      # noqa: BLE001
            fails.append(f"exception {type(e).__name__}: run={run!r} ts={ts!r}")
            continue
        legit = run == "run-1" and sig == good and ts == str(int(now))
        if res is None and not legit:
            fails.append(f"ACCEPTED a bad signature: run={run!r} ts={ts!r} sig={sig[:12]!r}")
        if res is not None and legit:
            fails.append("rejected the legitimate signature")
    return {"target": "signature verifier", "cases": n, "failures": fails[:20], "n_failures": len(fails)}


# --- false rejections: known-legitimate requests must pass ----------------------------------------------------
LEGIT = [("GET", f"/admin/realms/{REALM}/users?first=0&max=11&q="), ("GET", f"/admin/realms/{REALM}/users?search=jordan%40corp.example"),
         ("GET", f"/admin/realms/{REALM}/users?search=Jordan%20Avery&exact=false"), ("GET", f"/admin/realms/{REALM}/users/{U}"),
         ("GET", f"/admin/realms/{REALM}/users/{U}/credentials"), ("GET", f"/admin/realms/{REALM}/users/count"),
         ("PUT", f"/admin/realms/{REALM}/users/{U}/reset-password"), ("POST", f"/admin/realms/{REALM}/users/{U}/logout"),
         ("POST", f"/gate/v1/actions/mfa-recovery-lost-device/{U}")]
LEGIT_BODIES = {"reset-password": b'{"type":"password","temporary":true}'}


def false_rejections() -> dict:
    rej = []
    for m, t in LEGIT:
        body = next((b for k, b in LEGIT_BODIES.items() if k in t), b"")
        try:
            parse(PACK, m, t, body)
        except Reject as e:
            rej.append(f"{m} {t} -> {e.reason}")
    return {"target": "false rejections (known-legitimate requests)", "cases": len(LEGIT), "rejected": rej}


def run_all(n: int = 2000, seed: int = 1, tmp: str | None = None) -> list[dict]:
    import tempfile
    tmp = tmp or tempfile.mkdtemp(prefix="keyless-fuzz-")
    return [fuzz_console(n, seed), fuzz_grammar(n, seed + 1), fuzz_broker(max(n // 4, 50), seed + 2, tmp),
            fuzz_signatures(n, seed + 3), false_rejections()]


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    t0 = time.time()
    results = run_all(n, seed)
    total = 0
    for res in results:
        nf = res.get("n_failures", len(res.get("rejected", [])))
        total += res.get("n_failures", 0)
        print(f"\n== {res['target']}: {res['cases']} cases, {nf} {'false rejections' if 'rejected' in res else 'failures'}")
        for k, v in res.items():
            if k not in ("target", "cases", "failures", "n_failures", "rejected"):
                print(f"   {k}: {v}")
        for f in res.get("failures", []) + res.get("rejected", []):
            print("   !", f)
    print(f"\nTOTAL security failures: {total}   ({time.time() - t0:.0f} s, seed {seed}, stopped: finished)")
    sys.exit(1 if total else 0)
