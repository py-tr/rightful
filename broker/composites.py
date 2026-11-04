"""Broker-executed composite actions: one approval, a fixed pre-declared list of steps, run by the broker itself.

The agent only names the action and the user. Every parameter (which credential, which email, which redirect) is
decided here from Keycloak's own data, so "one exact request" stays literally true and ids learned at runtime are no
problem. Steps run in order and stop at the first failure; the owner is told about partial completion; every step is
written to the ledger with the receipt id. Nothing secret is returned to the sandbox.
"""
from __future__ import annotations

import secrets


class CompositeError(RuntimeError):
    pass


def execute(kc, ledger, realm: str, user_id: str, steps: list[str], receipt_id: str, run_id: str,
            notify, deliver_secret) -> dict:
    """Returns a redacted result: which steps ran, and whether all completed."""
    auth = {"Authorization": f"Bearer {kc.service_token()}"}
    base = f"/admin/realms/{realm}/users/{user_id}"
    username = kc.username(user_id)
    done: list[str] = []

    def log(step: str, status: str, **extra):
        ledger.append("composite_step", {"run": run_id, "receipt": receipt_id, "user": user_id, "step": step,
                                         "status": status, **extra})

    try:
        for step in steps:
            if step == "remove_otp_credentials":
                creds = kc.http.get(f"{base}/credentials", headers=auth)
                creds.raise_for_status()
                otp = [c["id"] for c in creds.json() if c.get("type") == "otp"]
                for cid in otp:
                    kc.http.delete(f"{base}/credentials/{cid}", headers=auth).raise_for_status()
                log(step, "ok", removed=len(otp))
            elif step.startswith("send_actions_email:"):
                action = step.split(":", 1)[1]
                if action not in ("CONFIGURE_TOTP", "UPDATE_PASSWORD"):
                    raise CompositeError(f"unknown action {action}")
                # No redirect_uri and no client_id: the link goes only to the email already on file.
                kc.http.put(f"{base}/execute-actions-email", params={"lifespan": "900"}, json=[action],
                            headers=auth).raise_for_status()
                log(step, "ok")
            elif step == "logout_sessions":
                kc.http.post(f"{base}/logout", headers=auth).raise_for_status()
                log(step, "ok")
            elif step == "reset_password_oob":
                secret = secrets.token_urlsafe(12)
                kc.http.put(f"{base}/reset-password", json={"type": "password", "temporary": True, "value": secret},
                            headers=auth).raise_for_status()
                deliver_secret(username, secret)
                log(step, "ok", secret_out_of_band=True)
            elif step == "notify_owner":
                notify(username, f"Account recovery on your account ({', '.join(done) or 'no steps'}). "
                                 "If this was not you, contact IT security now.")
                log(step, "ok")
            else:
                raise CompositeError(f"unknown step {step}")
            done.append(step)
    except Exception as e:                                   # abort on the first failure, tell the owner
        log(steps[len(done)] if len(done) < len(steps) else "?", "failed", error=type(e).__name__)
        try:
            notify(username, f"An account recovery on your account stopped part-way ({', '.join(done) or 'nothing done'}). "
                             "IT has been alerted.")
        except Exception:
            pass
        return {"completed": False, "steps_done": done, "failed_step": steps[len(done)] if len(done) < len(steps) else None}
    return {"completed": True, "steps_done": done}
