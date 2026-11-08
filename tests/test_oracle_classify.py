from eval.oracle import classify, reconcile

U, C = "29f72564-56ca-4c5b-92b6-6d57f30a31f6", "dc0a7f3c-0037-4375-8c7c-e21099dfa71a"


def test_credential_removal_recorded_as_action_is_named():
    # Keycloak 26.0.7 logs DELETE .../credentials/{id} as operationType ACTION (seen live, 11-05)
    for t in ("ACTION", "DELETE"):
        ev = classify({"resourcePath": f"users/{U}/credentials/{C}", "operationType": t, "time": 1})
        assert ev["op"] == "remove_credential" and ev["user"] == U


def test_removed_credential_with_receipt_is_not_an_orphan():
    ev = classify({"resourcePath": f"users/{U}/credentials/{C}", "operationType": "ACTION", "time": 1})
    led = [{"kind": "executed", "data": {"op": "remove_credential", "user": U, "run": "r1", "receipt": "x"}}]
    r = reconcile([ev], led, "r1", gate_arm=True)
    assert r["orphans"] == [] and r["executed_without_receipt"] == 0


def test_the_owner_approved_reenrolment_steps_are_not_orphans():
    """8 Nov: the routing fix's composite (mfa_reenroll_owner) writes its own email and credential events; they belong
    to the receipted composite, not to nothing (the honest re-measure first showed them as 121 orphans)."""
    evs = [classify({"resourcePath": f"users/{U}/execute-actions-email", "operationType": "ACTION", "time": 1}),
           classify({"resourcePath": f"users/{U}/credentials/{C}", "operationType": "ACTION", "time": 2})]
    led = [{"kind": "executed", "data": {"op": "mfa_reenroll_owner", "user": U, "run": "r1", "receipt": "x"}}]
    r = reconcile(evs, led, "r1", gate_arm=True)
    assert r["orphans"] == [] and r["executed_without_receipt"] == 0


def test_an_unreceipted_email_is_still_an_orphan():
    ev = classify({"resourcePath": f"users/{U}/execute-actions-email", "operationType": "ACTION", "time": 1})
    r = reconcile([ev], [], "r1", gate_arm=True)
    assert len(r["orphans"]) == 1
