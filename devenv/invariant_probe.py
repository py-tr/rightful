"""The invariant, tested against Keycloak itself (no gate in between): nothing reachable from the sandbox holds a
credential that can write. Local Docker only, no model calls, $0. Run: python -m devenv.invariant_probe

1. Tokens: every token the browser side could hold (a signature-broken copy, as the console receives) and the REAL
   view-only console token the broker keeps. Each is replayed directly against every write in the pack and the
   dangerous admin writes. Pass = every one refused AND Keycloak's admin-event log unchanged.
2. The manager attribute (the approver relationship): can the broker's own service account (manage-users) change it?
   Reported as measured; the README wording follows the result.
3. Brute-force protection: repeated wrong passwords lock the account.
"""
from __future__ import annotations

import json
import sys

import httpx

from devenv import keycloak_local as kl

REALM = "corp"


def token(base: str, data: dict, auth=None) -> str:
    r = httpx.post(f"{base}/realms/{REALM}/protocol/openid-connect/token", data=data, auth=auth, timeout=15)
    r.raise_for_status()
    return r.json()["access_token"]


def main() -> int:
    base = kl.start()
    env = kl.bootstrap(base)
    a = kl.master_admin(base)
    cfo, ceo = env["users"]["cfo"], env["users"]["ceo"]
    user = f"/admin/realms/{REALM}/users/{cfo}"
    cred = "0b9b2a3e-1111-4c86-9912-27a5a18fb8cd"
    # The console user's REAL token (what the broker holds; the browser only ever gets a signature-broken copy).
    real = token(base, {"grant_type": "password", "client_id": "admin-cli", "username": env["console"][0],
                        "password": env["console"][1]})
    h, p, _ = real.split(".")
    tokens = {"real view-only console token": real, "signature-broken copy (browser)": f"{h}.{p}.brokerfakeAAAA",
              "no token": None}
    writes = [  # every write in the pack, then the ones an attacker would want most
        ("PUT", f"{user}/reset-password", {"type": "password", "temporary": True, "value": "Pwned-123456"}),
        ("PUT", f"{user}/execute-actions-email", ["UPDATE_PASSWORD"]),
        ("DELETE", f"{user}/credentials/{cred}", None),
        ("POST", f"{user}/logout", None),
        ("PUT", user, {"email": "attacker@evil.example"}),
        ("PUT", user, {"attributes": {"manager": ["jordan.avery.c"]}}),
        ("POST", f"/admin/realms/{REALM}/users", {"username": "backdoor", "enabled": True}),
        ("DELETE", f"/admin/realms/{REALM}/users/{ceo}", None),
        ("PUT", f"/admin/realms/{REALM}/events/config", {"adminEventsEnabled": False}),
        ("PUT", f"/admin/realms/{REALM}", {"bruteForceProtected": False}),
    ]
    before = len(kl.admin_events(base, REALM, env["reconciler"]))
    results, failures = [], []
    for tname, tok in tokens.items():
        hdr = {"Authorization": f"Bearer {tok}"} if tok else {}
        for m, path, body in writes:
            r = httpx.request(m, base + path, json=body, headers=hdr, timeout=15)
            ok = r.status_code in (401, 403)
            results.append(f"{'refused' if ok else 'ACCEPTED'} {r.status_code} {tname}: {m} {path.split(REALM)[-1][:60]}")
            if not ok:
                failures.append(results[-1])
    after = len(kl.admin_events(base, REALM, env["reconciler"]))
    print("\n".join(results))
    print(f"\nINVARIANT tokens x writes: {len(results)} attempts, {len(failures)} accepted; "
          f"Keycloak admin events during the replay: {after - before}")

    # 2. The manager attribute vs the broker's own service account (manage-users).
    sa = token(base, {"grant_type": "client_credentials"}, auth=env["broker"])
    u = httpx.get(base + user, headers={"Authorization": f"Bearer {sa}"}).json()
    u["attributes"] = {**(u.get("attributes") or {}), "manager": ["jordan.avery.c"]}
    put = httpx.put(base + user, json=u, headers={"Authorization": f"Bearer {sa}"})
    now = a.get(user).json().get("attributes", {}).get("manager")
    changed = now != ["ceo"]
    print(f"MANAGER attribute via the broker's service account: PUT {put.status_code}; manager now {now} -> "
          f"{'CHANGED (not protected)' if changed else 'unchanged (protected)'}")
    # ...while the one legitimate user update the gate can forward (change_email: exactly {"email": ...}) still works
    # and leaves the protected attributes alone.
    em = httpx.put(base + user, json={"email": "jordan.new@corp.example"}, headers={"Authorization": f"Bearer {sa}"})
    after_u = a.get(user).json()
    email_ok = em.status_code == 204 and after_u.get("email") == "jordan.new@corp.example" \
        and after_u.get("attributes", {}).get("manager") == ["ceo"]
    print(f"CHANGE_EMAIL via the broker's service account: PUT {em.status_code}; email {after_u.get('email')}, manager "
          f"{after_u.get('attributes', {}).get('manager')} -> {'works' if email_ok else 'BROKEN'}")

    # 3. Brute-force protection: wrong passwords for a user who has one.
    jid = env["users"]["jordan.avery.c"]
    a.put(f"/admin/realms/{REALM}/users/{jid}/reset-password",
          json={"type": "password", "temporary": False, "value": "Right-Pass-123"}).raise_for_status()
    for _ in range(6):
        httpx.post(f"{base}/realms/{REALM}/protocol/openid-connect/token",
                   data={"grant_type": "password", "client_id": "admin-cli", "username": "jordan.avery.c",
                         "password": "wrong"})
    right = httpx.post(f"{base}/realms/{REALM}/protocol/openid-connect/token",
                       data={"grant_type": "password", "client_id": "admin-cli", "username": "jordan.avery.c",
                             "password": "Right-Pass-123"})
    st = a.get(f"/admin/realms/{REALM}/attack-detection/brute-force/users/{jid}").json()
    locked = right.status_code != 200 and st.get("disabled")
    print(f"BRUTE FORCE: after 6 wrong passwords the right one gets {right.status_code}; status {json.dumps(st)} -> "
          f"{'locked' if locked else 'NOT locked'}")
    kl.stop()
    ok = not failures and after == before and not changed and email_ok and locked
    print("\nRESULT:", "ALL HOLD" if ok else "SOMETHING DOES NOT HOLD")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
