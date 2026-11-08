# Status of the Vultr re-runs (eval/PREREG-vultr-reruns.md)

| # | re-run | status | runs | cost | results |
|---|---|---|---|---|---|
| 1 | honest completion (vultr-honestfixed) | finished; its two email cases invalid (VM mail defect) | 720/720 | $4.112 of $4.50 | RESULTS-vultr-honestfixed.md |
| 1b | the two email cases after the mail fix (vultr-honestfixed-mailfix, deviation log) | **running** (started 14:35 UTC) | 0/240 at writing | cap $1.80 | to be added to RESULTS-vultr-honestfixed.md |
| 2 | demo attack rate (vultr-demosetup) | finished | 180/180 | $0.530 of $3.00 | RESULTS-vultr-demosetup.md |
| 3 | payments hostile (vultr-ap-hostile) | finished | 60/60 | $1.146 of $1.20 | RESULTS-vultr-ap-hostile.md |
| 4 | regression (vultr-regress) | finished | 150/150 | $0.998 of $1.50 | RESULTS-vultr-regress.md |
| 5a | payments fixed (vultr-ap-fixed) | finished | 60/60 | $0.283 | RESULTS-vultr-ap-fixed.md |
| 5b | payments harder (vultr-ap-harder) | finished, 1 set-up exclusion | 60/60 (59 analysed) | $0.285 | RESULTS-vultr-ap-harder.md |

Spent on re-runs 1-5: $7.35 of the $10 cap. The mail-fix re-run has its own approved cap of $1.80. If it is still
unfinished at submission, it is reported as unfinished, with the runs that completed, and nothing is claimed from the
missing ones.

The VM defect, found after the runs: Keycloak could not send account emails (the mail catcher's SMTP port 1025 was not
published, and the firewall did not allow it on the Docker bridge). Fixed in `deploy/ap_vm.sh` and on the running VM
(mail container recreated with the port, one ufw rule); checked before the re-run with one direct Keycloak email (HTTP
204, one message delivered to the catcher). The payments suites (3, 5a, 5b) do not use account email.
