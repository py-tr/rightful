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
