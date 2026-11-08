# Status of the Vultr re-runs (eval/PREREG-vultr-reruns.md)

| # | re-run | status | runs | cost | results |
|---|---|---|---|---|---|
| 1 | honest completion (vultr-honestfixed) | finished; its two email cases invalid (VM mail defect), replaced by 1b in the primary | 720/720 | $4.112 of $4.50 | RESULTS-vultr-honestfixed.md |
| 1b | the two email cases after the mail fix (vultr-honestfixed-mailfix, deviation log) | finished, 0/240 email failures, 1 API-error exclusion | 240/240 | $1.493 of $1.80 | RESULTS-vultr-honestfixed.md |
| 2 | demo attack rate (vultr-demosetup) | finished | 180/180 | $0.530 of $3.00 | RESULTS-vultr-demosetup.md |
| 3 | payments hostile (vultr-ap-hostile) | finished | 60/60 | $1.146 of $1.20 | RESULTS-vultr-ap-hostile.md |
| 4 | regression (vultr-regress) | finished | 150/150 | $0.998 of $1.50 | RESULTS-vultr-regress.md |
| 5a | payments fixed (vultr-ap-fixed) | finished | 60/60 | $0.283 | RESULTS-vultr-ap-fixed.md |
| 5b | payments harder (vultr-ap-harder) | finished; the 1 set-up failure (h0027) re-run once as pre-registered, finished | 60/60 (60 analysed) | $0.285 + $0.007 | RESULTS-vultr-ap-harder.md |

Spent on re-runs 1-5: $7.35 of the $10 cap; the mail-fix re-run 1b $1.493 of its own $1.80 cap; the h0027 retry
$0.007. Total $8.85. All re-runs finished.

Primary honest completion on Vultr (1 + 1b combined), C / D: deepseek 84.4% / 66.7%, glm 84.4% / 76.0%, qwen 89.6% /
83.2% (local: 94.8% / 68.8%, 81.1% / 74.7%, 93.8% / 76.0%).

The VM defect, found after the runs: Keycloak could not send account emails (the mail catcher's SMTP port 1025 was not
published, and the firewall did not allow it on the Docker bridge). Fixed in `deploy/ap_vm.sh` and on the running VM
(mail container recreated with the port, one ufw rule); checked before the re-run with one direct Keycloak email (HTTP
204, one message delivered to the catcher). The payments suites (3, 5a, 5b) do not use account email.
