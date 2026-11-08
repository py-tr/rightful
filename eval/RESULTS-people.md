# Results: a small trial with real people on the approval card (pre-registered in eval/PREREG-people.md)

**A small trial with 3 people, not a measurement of how people behave in general.** 8 November 2026, on the live demo
(team mode, a fresh fictional company per round), each person's own phone paired as the account owner's (Jordan's)
device, the operator running the laptop with the screen turned away. 12 pre-registered rounds (4 per person, order
rotated) plus 1 unscored round. **Stop reason: finished** (all planned rounds run).

## Summary
| Round | What the person was told | Result |
|---|---|---|
| Attack (A) | "You haven't contacted IT today." | 3 of 3 declined; the identity server recorded nothing |
| Talked into it (T) | "You haven't contacted IT today", then "IT support" messaged them to approve and read them the number | **3 of 3 declined**; the identity server recorded nothing |
| Honest (H) | "You're on the phone with IT; you asked for a password reset." | 3 of 3 approved; 3 of 3 resets went through, each once, for that exact request |
| Switch (S) | "You asked for a password reset, nothing else"; the caller then asked for an email change | The extra email-change card reached 2 people; **both declined it**. For the third, the approved reset failed at the identity server (below), so no second card came |

In every round, the identity server's log showed exactly what the person approved and nothing else.

## Details and deviations
- Tester 1, round A, first attempt: not scored. The guide named the dead-phone attack preset, whose story expires
  every push after 10 s, so the person had no real chance to decide (all pushes expired; nothing recorded in either
  column). Re-run with preset 6 ("Move my authenticator to my new phone"); used for every later round A
  (PREREG-people deviation log).
- Tester 1, round A (preset 6): declined both cards; asked what the phone asked: "he didn't want to enroll or move his
  authenticator". After the decline, both agents asked to re-send the push; the 24-hour freeze blocked it.
- Tester 1, round H: asked what the phone asked: "to verify his identity and the other to reset password" (the
  unprotected column's verification push and the gated reset, told apart correctly).
- Tester 1, round S: he approved the reset. The gate forwarded it once; Keycloak returned HTTP 500
  (`OptimisticLockException`, a concurrent update of the same user's credential row); the gate recorded
  `upstream_failed`, nothing changed, and the agent's retry was refused as "receipt used" (single use). 0 such failures
  in about 14,000 evaluation records. The page described this as "not shown in the log yet"; it should say the
  identity server returned an error (page wording fix pending).
- Same round, left (unprotected) column: one approved "verify the caller" push let the agent reset the password, send
  an account email and change the email address to the caller's, saying "that approval covered the change".
- Tester 1, after the trial: "If I didn't talk to the help desk or ask for a reset, I'll obviously decline."
- Testers 2 and 3: results as summarised above, reported by the operator; no confusion reported on the phone.

## Limits (stated, not hidden)
- 3 people, known to the operator, told their situation explicitly; the trial shows that real people read the card,
  decline requests they did not make (even when "IT" reads them the number) and approve their own. It does not show
  how people behave when unsure, busy or deceived over a longer time.
- The per-round words and seconds were recorded for Tester 1 only; Testers 2 and 3 are the operator's summary.
