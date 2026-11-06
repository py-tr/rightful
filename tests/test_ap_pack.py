"""The accounts-payable pack (packs/ap.json) with a fake ERPNext: grammar, the adapter, the supplier-contact resolver."""
import json
from urllib.parse import unquote

import httpx
import pytest

from broker.approvers import SupplierContactResolver
from broker.erpnext import ERPNext
from gate import load_pack
from gate.grammar import Reject, canonical_iban, parse

PACK = load_pack("ap")


class FakeERP:
    def __init__(self):
        self.suppliers = ["Brightline Fasteners (example)", "Tiny Parts (example)"]
        self.accounts = {
            "Brightline AR - Example Savings Bank": {"party_type": "Supplier", "party": "Brightline Fasteners (example)",
                                                     "bank": "Example Savings Bank", "bank_account_no": "7731000021",
                                                     "iban": None, "is_default": 1, "disabled": 0,
                                                     "is_company_account": 0},
            "Brightline backup - Example New Bank": {"party_type": "Supplier", "party": "Brightline Fasteners (example)",
                                                     "bank": "Example New Bank", "bank_account_no": "7731000099",
                                                     "iban": None, "is_default": 0, "disabled": 0,
                                                     "is_company_account": 0},
            "Corp receiving - Example Savings Bank": {"party_type": None, "party": None, "bank": "Example Savings Bank",
                                                      "bank_account_no": "1000000001", "iban": None, "is_default": 0,
                                                      "disabled": 0, "is_company_account": 1}}
        self.puts = []

    def handler(self, req: httpx.Request) -> httpx.Response:
        path = unquote(req.url.path)
        if req.method == "GET" and path == "/api/resource/Supplier":
            return httpx.Response(200, json={"data": [{"name": n} for n in self.suppliers]})
        if req.method == "GET" and path == "/api/resource/Bank Account":
            rows = [{"name": n, **a} for n, a in self.accounts.items()]
            f = json.loads(req.url.params.get("filters") or "[]")
            for field, _, value in f:
                rows = [r for r in rows if r.get(field) == value]
            return httpx.Response(200, json={"data": rows})
        if path.startswith("/api/resource/Bank Account/"):
            name = path.split("/api/resource/Bank Account/", 1)[1]
            if name not in self.accounts:
                return httpx.Response(404, json={})
            if req.method == "PUT":
                body = json.loads(req.content)
                self.puts.append((name, body))
                if body.get("is_default"):
                    for a in self.accounts.values():
                        if a["party"] == self.accounts[name]["party"]:
                            a["is_default"] = 0
                self.accounts[name].update(body)
            return httpx.Response(200, json={"data": {"name": name, **self.accounts[name]}})
        return httpx.Response(404, json={})


@pytest.fixture
def erp(tmp_path):
    fake = FakeERP()
    e = ERPNext("http://erp", "token k:s", b"k" * 32, str(tmp_path / "approved.json"),
                http=httpx.Client(base_url="http://erp", transport=httpx.MockTransport(fake.handler)))
    e._index()
    return e, fake


def ref(e, name):
    return e.ref("Bank Account", name)


def test_iban_is_canonical_and_checked():
    assert canonical_iban("de89 3704 0044 0532 0130 00") == "DE89370400440532013000"
    with pytest.raises(Reject):
        canonical_iban("DE89370400440532013001")
    a = parse(PACK, "PUT", "/ap/v1/bank-accounts/0b9b2a3e-1111-4c86-9912-27a5a18fb8cd/details",
              b'{"iban":"de89 3704 0044 0532 0130 00"}')
    b = parse(PACK, "PUT", "/ap/v1/bank-accounts/0b9b2a3e-1111-4c86-9912-27a5a18fb8cd/details",
              b'{"iban":"DE89370400440532013000"}')
    assert a.request_hash == b.request_hash


@pytest.mark.parametrize("method,path,body", [
    ("PUT", "/ap/v1/bank-accounts/Acme%20Supplies%20-%20Deutsche%20Bank/details", b"{}"),
    ("PUT", "/ap/v1/bank-accounts/Acme Supplies/details", b"{}"),
    ("POST", "/api/method/frappe.client.set_value", b"{}"),
    ("POST", "/api/method/frappe.model.rename_doc.rename_doc", b"{}"),
    ("PUT", "/api/resource/Bank Account/x", b"{}"),
    ("DELETE", "/ap/v1/bank-accounts/0b9b2a3e-1111-4c86-9912-27a5a18fb8cd/details", b""),
    ("PUT", "/ap/v1/bank-accounts/0b9b2a3e-1111-4c86-9912-27a5a18fb8cd/details", b'{"party":"Evil"}'),
    ("PUT", "/ap/v1/bank-accounts/0b9b2a3e-1111-4c86-9912-27a5a18fb8cd/details", b'{"party_type":"Customer"}'),
    ("PUT", "/ap/v1/bank-accounts/0b9b2a3e-1111-4c86-9912-27a5a18fb8cd/default", b'{"iban":"DE89370400440532013000"}'),
])
def test_grammar_refuses_names_methods_deletes_and_party_fields(method, path, body):
    with pytest.raises(Reject):
        parse(PACK, method, path, body)


def test_a_set_default_request_hashes_differently_from_an_iban_edit():
    ref_ = "0b9b2a3e-1111-4c86-9912-27a5a18fb8cd"
    d = parse(PACK, "PUT", f"/ap/v1/bank-accounts/{ref_}/default", b"")
    e = parse(PACK, "PUT", f"/ap/v1/bank-accounts/{ref_}/details", b'{"iban":"DE89370400440532013000"}')
    assert d.name != e.name and d.request_hash != e.request_hash     # a receipt for one can never redeem the other


def test_resolver_takes_the_approver_from_the_account_record(erp):
    e, _ = erp
    r = SupplierContactResolver(e, {"Brightline Fasteners (example)": "brightline-ap"})
    acc = ref(e, "Brightline AR - Example Savings Bank")
    assert r.approver_for(acc, "supplier_contact", r.subject_name(acc)) == ("brightline-ap", False, "")
    company = ref(e, "Corp receiving - Example Savings Bank")
    approver, human_only, why = r.approver_for(company, "supplier_contact", "x")
    assert human_only and approver == "" and "not a supplier" in why
    tiny = SupplierContactResolver(e, {})
    assert tiny.approver_for(acc, "supplier_contact", "x")[1] is True       # no registered contact -> human only


def test_push_label_names_old_and_new_last_four_and_tripwire_is_per_supplier(erp):
    e, _ = erp
    r = SupplierContactResolver(e, {"Brightline Fasteners (example)": "brightline-ap"})
    acc = ref(e, "Brightline AR - Example Savings Bank")
    lab = r.label({"user": acc, "operation": "change_bank_details", "body": {"bank_account_no": "4400002210"}})
    assert lab == "bank0021to2210"
    other = ref(e, "Brightline backup - Example New Bank")
    assert r.tripwire_key(acc) == r.tripwire_key(other)                      # one supplier, one tripwire


def test_write_aborts_when_the_account_changed_after_approval(erp):
    e, fake = erp
    acc = ref(e, "Brightline AR - Example Savings Bank")
    snap = e.snapshot(acc)
    fake.accounts["Brightline AR - Example Savings Bank"]["bank_account_no"] = "9999999999"   # changed in between
    r = e.forward({"method": "PUT", "path": f"/ap/v1/bank-accounts/{acc}/details",
                   "body": b'{"bank_account_no":"4400002210"}', "receipt": "rcp_1", "snapshot": snap})
    assert r.status_code == 409 and not fake.puts


def test_company_account_is_never_written(erp):
    e, fake = erp
    acc = ref(e, "Corp receiving - Example Savings Bank")
    r = e.forward({"method": "PUT", "path": f"/ap/v1/bank-accounts/{acc}/details",
                   "body": b'{"bank_account_no":"4400002210"}', "receipt": "rcp_1", "snapshot": e.snapshot(acc)})
    assert r.status_code == 403 and not fake.puts


def test_payment_check_matches_approval_and_flags_changes_made_without_one(erp):
    e, fake = erp
    sup = "Brightline Fasteners (example)"
    assert e.payment_check(sup)["verdict"] == "hold"                         # nothing approved on record yet
    e.seed_approved(sup, "Brightline AR - Example Savings Bank")
    assert e.payment_check(sup)["verdict"] == "matches"
    acc = ref(e, "Brightline AR - Example Savings Bank")
    ok = e.forward({"method": "PUT", "path": f"/ap/v1/bank-accounts/{acc}/details",
                    "body": b'{"bank_account_no":"4400002210"}', "receipt": "rcp_1", "snapshot": e.snapshot(acc)})
    assert ok.status_code == 200 and e.payment_check(sup)["verdict"] == "matches"    # approved through a receipt
    e.forward({"method": "PUT", "path": f"/ap/v1/bank-accounts/{acc}/details",
               "body": b'{"bank_account_no":"5500003311"}', "receipt": None, "snapshot": "skip"})   # someone's word
    pc = e.payment_check(sup)
    assert pc["verdict"] == "hold" and "outside the gate" in pc["why"]
    fake.accounts["Brightline AR - Example Savings Bank"]["is_default"] = 0           # a direct ERPNext edit
    fake.accounts["Brightline backup - Example New Bank"]["is_default"] = 1
    assert e.payment_check(sup)["verdict"] == "hold"


def test_reads_show_last_four_only_and_opaque_references(erp):
    e, _ = erp
    sup = e.ref("Supplier", "Brightline Fasteners (example)")
    r = e.forward({"method": "GET", "path": f"/ap/v1/suppliers/{sup}/bank-accounts"})
    rows = r.json()
    assert rows and all(set(x) == {"account", "bank", "number_last4", "iban_last4", "is_default"} for x in rows)
    assert "7731000021" not in r.text and "Brightline AR" not in r.text
