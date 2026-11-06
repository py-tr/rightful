"""The accounts-payable pack's stop rules (mentor, 11-06), checked on a local ERPNext before anything else is built:
  1. the gate's API user can write Bank Account (and read Supplier) and is REFUSED everywhere else;
  2. ERPNext's own change log (Version) records a bank change made by that user: field, old, new, user, time;
  3. that user cannot switch the witness off (track_changes via Customize Form / Property Setter / DocType) and cannot
     edit or delete Version records;
  4. a separate read-only witness user can read the Version log.
If 2 or 3 fails, the pack is a slide (no independent witness = a mock).

Local test site only (fictional data; Administrator password is the local stack's default).
  python -m devenv.erp_witness_check [http://127.0.0.1:8095]
"""
from __future__ import annotations

import json
import secrets
import sys

import requests

B = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8095"
H = {"Host": "frontend"}
RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + (f"  ({detail})" if detail else ""))


def admin_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(H)
    s.post(f"{B}/api/method/login", data={"usr": "Administrator", "pwd": "admin"}).raise_for_status()
    return s


def ensure(s, doctype: str, name: str, body: dict) -> None:
    r = s.get(f"{B}/api/resource/{doctype}/{requests.utils.quote(name, safe='')}")
    if r.status_code == 200:
        return
    r = s.post(f"{B}/api/resource/{doctype}", json=body)
    if r.status_code >= 400 and "DuplicateEntryError" not in r.text:
        raise SystemExit(f"create {doctype} {name}: {r.status_code} {r.text[:300]}")


def api_user(s, email: str, role: str) -> dict:
    ensure(s, "User", email, {"email": email, "first_name": email.split("@")[0], "send_welcome_email": 0,
                              "user_type": "System User", "roles": [{"role": role}]})
    u = s.get(f"{B}/api/resource/User/{email}").json()["data"]
    if role not in [r["role"] for r in u.get("roles", [])]:
        s.put(f"{B}/api/resource/User/{email}", json={"roles": u.get("roles", []) + [{"role": role}]}).raise_for_status()
    sec = s.post(f"{B}/api/method/frappe.core.doctype.user.user.generate_keys", data={"user": email}).json()["message"]
    key = s.get(f"{B}/api/resource/User/{email}").json()["data"]["api_key"]
    return {"Authorization": f"token {key}:{sec['api_secret']}", **H}


def perm(s, role: str, doctype: str, **rights) -> None:
    """A Custom DocPerm row (Role Permission Manager): only the rights given."""
    existing = s.get(f"{B}/api/resource/Custom DocPerm", params={
        "filters": json.dumps([["parent", "=", doctype], ["role", "=", role]]), "fields": json.dumps(["name"])}).json()
    if existing.get("data"):
        return
    body = {"parent": doctype, "parenttype": "DocType", "parentfield": "permissions", "role": role, "permlevel": 0,
            **{k: 1 for k, v in rights.items() if v}}
    r = s.post(f"{B}/api/resource/Custom DocPerm", json=body)
    if r.status_code >= 400:
        raise SystemExit(f"perm {role} {doctype}: {r.status_code} {r.text[:300]}")


def main() -> int:
    s = admin_session()
    for role in ("AP Gate", "AP Witness"):
        ensure(s, "Role", role, {"role_name": role, "desk_access": 1})
    perm(s, "AP Gate", "Bank Account", read=1, write=1, create=1)
    perm(s, "AP Gate", "Supplier", read=1)
    perm(s, "AP Gate", "Bank", read=1)
    perm(s, "AP Witness", "Version", read=1)
    perm(s, "AP Witness", "Bank Account", read=1)
    s.post(f"{B}/api/method/frappe.sessions.clear")         # permission cache
    gate = api_user(s, "ap-gate@example.com", "AP Gate")
    wit = api_user(s, "ap-witness@example.com", "AP Witness")

    # fictional supplier and its account (created by Administrator: the ERP's own setup)
    for bank in ("Example Savings Bank", "Example New Bank"):
        ensure(s, "Bank", bank, {"bank_name": bank})
    ensure(s, "Supplier Group", "Example Suppliers", {"supplier_group_name": "Example Suppliers", "is_group": 0})
    ensure(s, "Supplier", "Brightline Fasteners (example)",
           {"supplier_name": "Brightline Fasteners (example)", "supplier_group": "Example Suppliers"})
    found = s.get(f"{B}/api/resource/Bank Account", params={
        "filters": json.dumps([["party", "=", "Brightline Fasteners (example)"]])}).json()["data"]
    if found:
        ba = found[0]["name"]
    else:
        ba = s.post(f"{B}/api/resource/Bank Account", json={
            "account_name": "Brightline AR", "bank": "Example Savings Bank", "party_type": "Supplier",
            "party": "Brightline Fasteners (example)", "bank_account_no": "7731000021"}).json()["data"]["name"]
    bt = s.get(f"{B}/api/resource/DocType/Bank Account").json()["data"]
    check("Bank Account has track_changes on", bt.get("track_changes") == 1, f"track_changes={bt.get('track_changes')}")

    # 1. least privilege
    new_no = str(4400000000 + secrets.randbelow(99999999))
    r = requests.put(f"{B}/api/resource/Bank Account/{requests.utils.quote(ba, safe='')}", headers=gate,
                     json={"bank": "Example New Bank", "bank_account_no": new_no})
    check("gate user can change a supplier bank account", r.status_code == 200, f"HTTP {r.status_code}")
    r = requests.get(f"{B}/api/resource/Supplier/Brightline Fasteners (example)", headers=gate)
    check("gate user can read the supplier", r.status_code == 200, f"HTTP {r.status_code}")
    for what, method, path, body in (
            ("create a supplier", "POST", "Supplier", {"supplier_name": "Evil Co", "supplier_group": "Example Suppliers"}),
            ("edit the supplier", "PUT", "Supplier/Brightline Fasteners (example)", {"supplier_name": "x"}),
            ("read the Administrator user", "GET", "User/Administrator", None),
            ("create a payment entry", "POST", "Payment Entry", {"payment_type": "Pay"}),
            ("edit a purchase invoice", "GET", "Purchase Invoice", None),
            ("create a role", "POST", "Role", {"role_name": "Escalate"})):
        r = requests.request(method, f"{B}/api/resource/{path}", headers=gate, json=body)
        refused = r.status_code in (401, 403) or (r.status_code == 200 and method == "GET" and not r.json().get("data"))
        check(f"gate user refused: {what}", refused, f"HTTP {r.status_code}")

    names = [u["name"] for u in requests.get(f"{B}/api/resource/User", headers=gate).json().get("data", [])]
    check("gate user sees no account beyond itself and the witness (Frappe lists those two by default)",
          set(names) <= {"ap-gate@example.com", "ap-witness@example.com"}, f"visible: {names}")

    # 2. the witness records it
    vs = requests.get(f"{B}/api/resource/Version", headers=wit, params={
        "filters": json.dumps([["ref_doctype", "=", "Bank Account"], ["docname", "=", ba]]),
        "fields": json.dumps(["name", "owner", "creation", "data"]), "order_by": "creation desc", "limit_page_length": 1})
    data = vs.json().get("data", []) if vs.status_code == 200 else []
    rec = data[0] if data else {}
    changed = json.loads(rec.get("data") or "{}").get("changed", [])
    check("witness user can read the Version log", vs.status_code == 200 and bool(data), f"HTTP {vs.status_code}")
    check("Version log records the gate user's change (field, old, new, user)",
          rec.get("owner") == "ap-gate@example.com" and any(c[0] == "bank_account_no" and c[2] == new_no for c in changed),
          f"owner={rec.get('owner')} changed={changed}")

    # 3. the gate user cannot switch the witness off or touch it
    for what, method, path, body in (
            ("turn off track_changes on the DocType", "PUT", "DocType/Bank Account", {"track_changes": 0}),
            ("add a Property Setter for track_changes", "POST", "Property Setter",
             {"doctype_or_field": "DocType", "doc_type": "Bank Account", "property": "track_changes", "value": "0",
              "property_type": "Check"}),
            ("edit a Version record", "PUT", f"Version/{rec.get('name', 'x')}", {"data": "{}"}),
            ("delete a Version record", "DELETE", f"Version/{rec.get('name', 'x')}", None)):
        r = requests.request(method, f"{B}/api/resource/{path}", headers=gate, json=body)
        check(f"gate user refused: {what}", r.status_code in (401, 403, 417), f"HTTP {r.status_code}")
    r = requests.post(f"{B}/api/method/frappe.client.set_value", headers=gate,
                      data={"doctype": "DocType", "name": "Bank Account", "fieldname": "track_changes", "value": 0})
    check("gate user refused: set_value track_changes", r.status_code in (401, 403, 417), f"HTTP {r.status_code}")
    bt = s.get(f"{B}/api/resource/DocType/Bank Account").json()["data"]
    check("track_changes still on afterwards", bt.get("track_changes") == 1)
    ok = all(o for _, o, _ in RESULTS)
    print(f"\n{'ALL PASS: the witness is independent' if ok else 'FAILED: see above (stop rule)'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
