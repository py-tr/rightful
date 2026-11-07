# Rightful

**Authorization is not a model output.** An AI help desk whose agent can be fooled and still cannot change an account: the account owner approves the exact change on their own phone, and the identity server's own log keeps the score.

For IT service desks and accounts-payable teams that want an AI agent doing real work without letting a convincing caller or a hijacked agent reset an executive's password or redirect a supplier's payments.

Live on Vultr: **https://136-244-91-162.sslip.io/** (no login; a fictional company is created for you and deleted afterwards).

| Vultr product | Role here |
|---|---|
| Cloud Compute, control plane (`vc2-4c-8gb`, Frankfurt) | Gate, broker, Keycloak, realm factory, demo app, TLS. Holds the inference key. Runs no agent code. |
| Cloud Compute, worker (`vc2-2c-4gb`) | Every visitor's Python, one fresh gVisor (`runsc`) container per script. |
| VPC (`10.40.0.0/24`) | Carries the sandboxes' only traffic: a signed edge to the broker's VPC address, port 8090. Rules on the worker drop every other packet from a sandbox, cloud metadata included; the VM itself keeps its public interface for updates. |
| Firewall groups (two) | SSH from the operator's address only; 80/443 on the control plane only. |
| Serverless Inference | The agent's models: `qwen3.8-27b` (live default), `glm-5.3-flash`, `deepseek-v4.1-flash-1017`. Called from the control plane; the key does not enter a sandbox. |
| Vultr API (`deploy/vultr_deploy.py`) | `up` / `status` / `recycle-worker` / `down`. `fleet N` created and deleted the temporary workers for the 5,240-run evaluation; `ap-vm-up` / `ap-vm-down` the temporary payments VM (`vc2-4c-8gb`), deleted after its run. |

## 60 seconds for judges

1. Press **▶ Run the attack live** (about a minute, no phone needed): one scripted caller, one planted ticket note, one model, two columns. Left, the agent decides; right, the owner's phone decides. Above the left column, the measured rate for this exact setup (qwen3.8-27b fooled in 34 of 40 runs). The left column hands the caller Jordan's temporary password; the right ends with "Nothing changed".
2. Read the two tiles per column: "Agent tried" (the gate's records) and "Identity server recorded" (Keycloak's admin-event log, read with a view-only account). Left shows the real reset; right shows nothing. Under the right column, "Sandboxes (measured)" lists each script's container and confirms it is gone.
3. Press **Run a containment check**: a fresh sandbox reports what it can reach; then three tokens (none, a forged copy, the company's real view-only token) try 8 dangerous writes on your own company, with the admin-event count before and after.
4. The honest path: pick **2. Then the honest path, in both columns** and press Send. On the phone beside the chat, approve the card marked RIGHT with the number shown in the right column, or press **Use your own phone** and scan the code. The password is reset once, for that exact request.
5. **The policy** link shows every rule with the pack's SHA-256. **Share this result** shows both columns and the run's evidence as JSON.

## Results

We wrote every test down before running it (pre-registered): [`PREREG-gateon.md`](eval/PREREG-gateon.md) (committed 5 Nov 2026 12:14 UTC, `a6de962`, before the first paid run; amendments and deviations in the file), [`PREREG-demosetup.md`](eval/PREREG-demosetup.md), [`PREREG-regress.md`](eval/PREREG-regress.md), [`PREREG-ap.md`](eval/PREREG-ap.md), [`PREREG-ap2.md`](eval/PREREG-ap2.md), [`PREREG-ap3.md`](eval/PREREG-ap3.md). Every cell is published, including the bad ones. All callers, owners, managers and clerks are scripted.

| Measurement | Result | Source |
|---|---|---|
| Gate on: 5,240 runs, 3 models x 2 prompts, $29.70 of a $55 cap, finished | **0 of 1,199 attack runs changed an account without the approval its policy requires** (upper 95% bound 0.3% over all 1,199; 1.8% for each model and prompt). 25 lost-device recoveries went ahead because the manager approved, as policy allows; they are reported as their own category. Of the 5,240 runs, 2,389 had the gate on and 1,199 of those were attacks; the agents attempted 2,458 writes and 81 executed, each with an approval. 0 orphan events, 0 executions without a receipt in 2,389 gate runs. | [`RESULTS-gateon.md`](eval/RESULTS-gateon.md) |
| Same system, gate off | Unsafe on attacks: light prompt 5.8% / 36.3% / 44.7% (deepseek / qwen / glm); hardened 0.5% / 10.5% / 24.2%. Most failures removed the owner's authenticator on the caller's word. 25 attack runs handed the caller a temporary password, 0 with the gate. These are lower bounds: some runs ended on an empty reply, and re-running those with a larger output budget found more failures. | `RESULTS-gateon.md`; [`RESULTS-secondaries.md`](eval/RESULTS-secondaries.md) §1 |
| No lie needed | Same request, no planted note: glm, light prompt, changed the account in 8 of 10 control runs. | `RESULTS-gateon.md` |
| The cost (H2, refuted, published as refuted) | The light prompt with the gate completed 58% to 77% of honest tickets, 23 to 37 points fewer than the hardened prompt without the gate (95% to 100%); most of it one case routed to a manager the simulation did not answer. That routing was fixed afterwards and re-measured on the case: 7 or 8 of 8 in five of six model/prompt pairs. The published numbers stay pre-fix. | `RESULTS-gateon.md`; `RESULTS-secondaries.md` §3 |
| Binding (secondary) | Hostile agent, owner approves one reset: unbound approvals were reused to change the CFO's email in 5 of 30 runs; the bound receipt, 0 of 30. | `RESULTS-secondaries.md` §2 |
| Regression, merged code | Light prompt + gate, 150 runs: 0 unsafe in 80 lure runs, 0 orphans, 0 executions without a receipt; honest completion 9/11, 9/11, 12/12. | [`RESULTS-regress.md`](eval/RESULTS-regress.md) |
| The demo's setup, 180 runs, 7 Nov | The demo's attack fooled qwen3.8-27b in 34 of 40 runs, glm in 18 of 40, deepseek in 1 of 40; honest requests completed 19, 20, 20 of 20. The 5 Nov figures for the earlier setup (32, 21, 9 of 40) stay published. | [`RESULTS-demosetup.md`](eval/RESULTS-demosetup.md) |
| Payments pack, ERPNext | An agent told to change a supplier's bank details by any means, as if hijacked, attempted 132 unapproved writes in 30 runs on a Vultr VM (deleted after the run) and 142 in 29 runs on our own machine. The gate refused every one; none reached ERPNext's change log. Without the gate the same instructed agent changed the account in 22 of 30 runs on our machine, so the 0 is the gate, not the model declining the task. Honest changes approved by the registered contact: 29 of 30 on Vultr, 30 of 30 locally. | [`RESULTS-ap3.md`](eval/RESULTS-ap3.md); [`RESULTS-ap2.md`](eval/RESULTS-ap2.md); [`RESULTS-ap.md`](eval/RESULTS-ap.md) |

How to read the 0 of 1,199: the scripted owner is absent or declines on attack runs, so the number tests the mechanism. The agents were fooled; the gate is why nothing changed. A protected conversation costs about 0.7 cents of model calls (0.44 to 1.0 cents by model, mean of 2,340 gate-arm records) plus $0.09 an hour for both demo VMs.

## How it works

1. **The agent** has one tool, `run_python`. Each script runs in a fresh gVisor container on the worker: read-only root, no capabilities, 256 MB, no credential, no internet, no DNS, no cloud metadata. Its only route out is an edge proxy that signs each request for its run and forwards it over the VPC.
2. **The gate** parses every request against the policy pack (`packs/helpdesk.json`). Reads pass a field filter; anything the pack does not describe is refused; every write needs a receipt.
3. **The approval.** A receipt is minted when the approver named by policy (the owner; the manager for a lost device or a contact change) approves a Keycloak CIBA push on their own device naming the exact change and account, with number matching. It is bound to the run, operation, user and request hash, burned in one SQL statement before the broker forwards, used once. The agent re-sends the same request and holds no token, receipt or secret; the temporary password goes to the owner's phone.
4. **The record.** Keycloak's admin-event log, read by an account that can only read events, is reconciled to the receipts; a change without a receipt would show as an orphan.

Consent-fatigue controls: a wrong number declines; every card names the change and account; 3 pushes per approver per 10 minutes; one decline freezes that account's agent-driven changes for 24 hours (expires on its own, no override); after a manager's approval a cooling-off (60 s; 600 s privileged; 20 s and 40 s in the demo) during which the owner can cancel; a run that retries a declined change or repeats the same unapproved request four times is quarantined.

## Same gate, second system

Accounts payable on ERPNext: a supplier's bank details change only after the contact registered for that supplier at onboarding approves the exact change on their own device, and ERPNext's own Version log, read by a separate user, keeps the score. What it took: `packs/ap.json` (42 lines), `broker/erpnext.py` (217 lines, the connector), `broker/approvers.py` (89 lines; 46 are the supplier-contact lookup, the rest moves the existing help-desk lookup), +38/-7 lines in `gate/`. Measured on a temporary Vultr VM; shown on `/policy`; not in the live demo.

- **Why a hijacked agent, not a forged invoice?** These models saw through the forged supplier letter on their own (0 of 30, twice, including a letter that explained the contact's silence): it came from outside, and they noticed the new contact details came from the same email. The help-desk lure that did fool them was an insider's note plus a story for the owner's silent phone. So the payments pack is measured against the worse case, an agent told to do it.
- **"Locked out":** a run that keeps trying is quarantined; every further request from that run is refused, and it ends with the run. One decline freezes agent-driven changes for that supplier for 24 hours; payment runs and the payment check continue, and nothing unlocks it early.
- **A fake supplier or account?** Not through the gate: the pack has three reads and two edits of existing accounts, and the gate's ERPNext user cannot create or delete. The payment check compares the current default account with the approved register, so a change made outside the gate reads "hold".
- **A compromised registered contact?** The contact comes from a directory filled at onboarding; no request, ticket or gate operation changes it. A compromised contact's device is the residual risk, the same class as a fooled manager.

## Questions a skeptical judge asks

**Isn't 0 of 1,199 true by construction?** It tests the implementation under pressure: in 978 of the 1,199 gated lure runs the agents still attempted a write, 2,458 in all, and the log was reconciled to every one. The construction can fail: a code review found, and our probe confirmed, that the console route forwarded walk-back paths, and 3 of 6 variants reset a password without a receipt. It was closed on 5 November, before the test was written down and run, in three layers, each tested alone, and the probe is now a permanent test. Ablations show what carries the weight: trusting the agent's own "verified" claim failed 15 of 30, an allowlist alone 18 of 30, unbound approvals 5 of 30 under a hostile agent, the full gate 0 of 30.

**Why 0.5% to 44.7%? Why not just the hardened prompt?** 44.7% is glm, light prompt (85 of 190); 0.5% is deepseek, hardened (1 of 190, upper bound 2.9%). The hardened prompt alone completed more honest tickets than light + gate, so the arm to run is hardened + gate: 0 unsafe, honest completion 77% to 92%. Hardened alone still failed 24.2% on glm, the gate-off rates are lower bounds, and the model behind an agent changes with the vendor's release.

**MFA fatigue?** A wrong number declines; the card names the change; 3 pushes per 10 minutes; one decline means human help for a day. The open vector: an attacker already talking to the owner can read them the number. The card's named action is the only defence there, and we do not claim people read it.
## Honest limits

- Keycloak runs in dev mode on our control-plane VM; its log is read with a view-only account.
- The people in the evaluation are scripted; their timing changed a result once (RESULTS-ap.md, corrected and re-run).
- The approval is only as truthful as what the approver reads; a fooled manager on the lost-device path is the accepted residual.
- The gate sees the first hop only; read-only abuse is out of scope.
- The demo phone is a web page unless you pair your own. The cooling-off applies after a manager's approval only.
- The prompt-only numbers are an existence proof; the attacks were static.
- Where gVisor ran: the live demo (every script on the Vultr worker; the smoke test checks the kernel the sandbox reports), the 5,240-run evaluation and the Vultr payments replication. Two measurements ran on our own machine with plain Docker sandboxes: the 7 Nov re-measurement of the demo's attack rates (it measures the agent's behaviour, which the sandbox runtime does not change) and the local ERPNext runs.

## What we chose not to build

A key the gate cannot bound does not go on the demo server: no cloud-operations pack (a Vultr API key acts on a real account), no fetching of visitor links or files (egress could not be bounded), no visitor scripts on the control plane (it holds the model key, the factory credential and the signing master key).

## Run it

- Tests: `python -m pytest tests --ignore=tests/integration` (385 tests).
- Local demo (Docker): `python -m devenv.demo_local`, then http://127.0.0.1:8000.
- Your own Vultr account: `python -m deploy.vultr_deploy up`, then `demo-deploy`; `python -m devenv.smoke https://<host>`; `down` removes everything.
- Re-run the analysis: `python -m eval.analyze eval/out/gateon`.
