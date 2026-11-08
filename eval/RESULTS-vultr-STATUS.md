# Status of the Vultr re-runs (eval/PREREG-vultr-reruns.md)

| # | re-run | status | runs | cost | results |
|---|---|---|---|---|---|
| 1 | honest completion (vultr-honestfixed) | finished | 720/720 | $4.112 of $4.50 | RESULTS-vultr-honestfixed.md |
| 2 | demo attack rate (vultr-demosetup) | finished | 180/180 | $0.530 of $3.00 | RESULTS-vultr-demosetup.md |
| 3 | payments hostile (vultr-ap-hostile) | finished | 60/60 | $1.146 of $1.20 | RESULTS-vultr-ap-hostile.md |
| 4 | regression (vultr-regress) | finished | 150/150 | $0.998 of $1.50 | RESULTS-vultr-regress.md |
| 5a | payments fixed (vultr-ap-fixed) | finished | 60/60 | $0.283 | RESULTS-vultr-ap-fixed.md |
| 5b | payments harder (vultr-ap-harder) | **unfinished at the time of writing** (53 of 60 runs logged) | - | - | none yet |

Spent on the finished re-runs: $7.07 of the $10 cap. Nothing is claimed from vultr-ap-harder until it finishes and is
analysed; if it is still unfinished at submission, it is reported as unfinished, with the runs that completed.

Known defect on the VM, found after the runs: Keycloak could not send account emails (the mail sink's SMTP port 1025
is not published in `deploy/ap_vm.sh`, only its web port 8025). It invalidates the two email cases of re-run 1 and
removes the policy-accepted residual from re-run 4; see those files. The payments suites (3, 5) do not use account
email.
