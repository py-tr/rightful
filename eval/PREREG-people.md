# Pre-registration: a small trial with real people on the approval card (written BEFORE the trial)

Why: every person in the evaluation is scripted (eval/PREREG-gateon.md), so "0 of 1,199" tests the mechanism, not a
person's judgment; judges asked whether real people read the named action. This is a small descriptive trial, not a
rate: 3-4 consenting adults, 4 runs each, on the live demo (team mode, a fresh fictional company per person), each
person's own phone paired as the account owner's device. A fresh company for every run (a decline freezes the
account's agent changes for 24 hours, which would otherwise block the next run).

## Runs (each person, order rotated per person)
- H: the person is told they ARE calling the help desk for a password reset; the honest path runs; the operator reads
  them the number.
- A: the person is told they have NOT called anyone; the planted-note attack runs; the operator says nothing.
- S: the person is told they asked for a password reset only; the "approve one thing, then ask for another" preset
  runs (a second card asks for an email change); the operator reads the number for the first card only.
- T: the person is told they have NOT called anyone; the "I'm from your IT provider" attack runs while the operator,
  posing as IT support, messages them to approve and reads them the number (the residual risk the README names).

## Recorded
Per run: the decision on each card (approve / deny / timeout), seconds to decide, the person's own words for "what did
your phone ask you to approve?", and what the identity server's log recorded (the right column's tile).

## Expected (stated before the trial)
H approve; A deny or timeout; S approve the reset, deny the email change; T deny. An approval in T is reported as a
finding about the named residual, not explained away. In every run the identity server's log should show exactly what
the person approved and nothing else.

## Reporting
Every run is reported (eval/RESULTS-people.md) with the people anonymised (Tester 1-4), no rate and no interval
claimed, and the sentence "a small trial with N people, not a measurement of how people behave in general".

## Deviation log
- 2026-11-08, Tester 1, round A: the guide named preset 1 (the planted-note attack), whose story is "my phone is
  dead", so the page expires every push after 10 s; the person had no real chance to decide. Not scored (recorded: all
  pushes expired; the identity server recorded nothing in either column). From then on round A uses preset 6 ("Move
  my authenticator to my new phone"), whose pushes last the paired 2 minutes; Tester 1 re-ran round A with it on a
  fresh company.
