# Pre-registration: every locally run measurement, re-run on Vultr under gVisor (written BEFORE any of these runs)

Why (owner, 8 Nov; judges: "every headline figure on Vultr with gVisor, no local Docker runs"): five measurements ran on
the development machine with plain Docker (runc) sandboxes. Each is re-run here, unchanged in design, on a temporary
Vultr Cloud Compute VM (`deploy/ap_vm.sh`: Keycloak 26.0.7, ERPNext v16, the harness, sandboxes under gVisor `runsc`
driven over ssh exactly as on the evaluation workers). Each re-run is reported next to its local original, never
pooled with it; both stay published. The local originals are not withdrawn.

## System under test
The commit that adds this file (main), deployed to the VM by `deploy.vultr_deploy ap-vm-up` (`git archive HEAD`).
Records carry the commit; any other is a deviation. Concurrency: the harness's `--per-host` may be raised from 3 to 6
on this VM to fit the day; it changes scheduling only, not cases, prompts, models, people or analysis (stated wherever
a number is shown).

## The re-runs, in order (one at a time: each starts its own gate on the VM)
1. **Honest completion on the fixed code** — the design of `eval/PREREG-honestfixed.md` exactly: arms C and D, the 5
   honest cases, 720 runs. Output `vultr-honestfixed`. Cap $4.50.
2. **The demo's attack rate** — the design of `eval/PREREG-demosetup.md` with its Amendment 1 exactly (180 runs: the
   demo's own cases, the left column as the page runs it). Output `vultr-demosetup`. Cap $3.00.
3. **Payments, hostile suite** — `eval/PREREG-ap2.md`'s hostile suite exactly (H_nogate and H_gate, 30 each), so the
   gated and ungated runs share one machine. Output `vultr-ap-hostile`. Cap $1.20.
4. **Regression on the merged code** — the design of `eval/PREREG-regress.md` exactly (arm D, 6 cases, 150 runs).
   Output `vultr-regress`. Cap $1.50.
5. **Payments, forged-letter suites** — `eval/PREREG-ap2.md`'s fixed and harder suites exactly (L_clerk and R_clerk,
   30 each per suite). Outputs `vultr-ap-fixed`, `vultr-ap-harder`. Cap $1.50 together.
Total cap for model calls: $10 (owner approval 8 Nov). VM: ~$0.06 an hour, deleted after filming.

## Outcomes
Each re-run uses its original pre-registration's outcomes, analysis and exclusions, unchanged, and is published as
`eval/RESULTS-vultr-<name>.md` beside the original, with the stop reason (finished / cap / stopped) and cost. No
threshold or direction is claimed in advance. If a re-run's result differs from its local original, both are shown
and the difference is reported, not explained away.

## Stop rules
A cap stops that re-run ("cap"); unfinished re-runs at submission time are reported as unfinished, with the runs
that completed, and nothing is claimed from the missing ones. A bug found mid-run: stop, fix, re-run the affected
runs, log it below.

## Deviation log
(none yet)
