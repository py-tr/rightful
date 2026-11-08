# Rightful

**Authorization is not a model output.** An AI help desk whose agent can be fooled and still cannot change an account: the account owner approves the exact change on their own phone, and the identity server's own log keeps the score.

**For** IT service desks (and the MSPs that run them) putting AI agents on password and MFA resets, and accounts-payable teams letting an agent update supplier bank details. **Cost:** about 0.7 cents of model calls per protected conversation, plus $0.09 an hour for the two demo VMs.

Live on Vultr: **https://136-244-91-162.sslip.io/** (no login; a fictional company is created for you and deleted afterwards). Video: VIDEO_LINK_TODO

**Result:** without the gate, the agent made an unsafe account change in 0.5% to 44.7% of attack runs, depending on model and prompt; with it, 0 of 1,199 changed an account without the approval its policy requires (pre-registered, 5,240 runs, 3 open models).

**On Vultr:** the agent's models on Serverless Inference, every script in a fresh gVisor sandbox on a Cloud Compute worker, the gate on a separate control-plane VM over a private VPC, and the evaluation fleets created and deleted through the Vultr API. Everything, with sources: [`docs/EVIDENCE.md`](docs/EVIDENCE.md).

## 60 seconds for judges

1. **▶ Run the attack live** (a minute, no phone needed). Same caller, note, model and instructions in two columns: left, the agent decides and hands the caller the CFO's temporary password; right, the owner's phone decides and nothing changes.
2. Under each column: "Agent tried" vs "Identity server recorded" (Keycloak's own log, read with a view-only account), and on the right, each script's sandbox container confirmed gone.
3. **Run a containment check**: what a fresh sandbox can reach, and 3 tokens trying 8 dangerous writes, with the log's count before and after.
4. The honest path: **2. Then the honest path** and Send, then approve the card marked RIGHT on the phone (or **Use your own phone**). The reset goes through once, for that exact request.
5. More: the twin preset, **The policy** (every rule, with its SHA-256), **Share this result** (the evidence as JSON).

## Why this exists

The help desk is how attackers get in. The US CISA and FBI advisory on Scattered Spider ([AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a), updated July 2025) says they "posed as employees to convince IT and/or helpdesk staff to ... reset the employee's password, and transfer the employee's MFA to a device they control." [Caesars' 8-K](https://www.sec.gov/Archives/edgar/data/1590895/000119312523235015/d537840d8k.htm) describes a "social engineering attack on an outsourced IT support vendor", and Clorox [alleges](https://www.documentcloud.org/documents/26025404-clorox-versus-cognizant-complaint/) its outsourced service desk reset passwords and MFA "without any identity verification at all". Companies are now putting AI agents on those desks: ServiceNow [announced](https://newsroom.servicenow.com/press-releases/details/2025/ServiceNow-to-extend-leading-agentic-AI-to-every-employee-for-every-corner-of-the-business-with-acquisition-of-Moveworks-03-10-2025-traffic/default.aspx) its purchase of Moveworks, an AI help-desk agent company, at $2.85 billion. An agent can be talked into a reset like a person can: without a gate, ours made an unsafe change in 0.5% to 44.7% of attack runs, depending on model and prompt.

Payments have the same weakness: Abnormal Security reports that 61% of the business email compromise it saw (about 800,000 attacks in its customers' data) [impersonated an outside party, usually a vendor](https://www.abnormal.ai/blog/2026-attack-landscape-report-vec), and guidance published by the [UK National Crime Agency](https://www.nationalcrimeagency.gov.uk/who-we-are/publications/787-invoice-fraud-infosheet/file) says to "always confirm bank detail changes using a published phone number or long standing contact". EU online payments already work the way Rightful does: the approval code must match the exact amount and payee, any change voids it, and it is accepted once ([Delegated Regulation 2018/389](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018R0389), Articles 4-5).

**What Rightful adds.** The approval runs on an OpenID standard (CIBA) that [Auth0](https://auth0.com/ai/docs/async-authorization) and [Okta](https://developer.okta.com/docs/guides/configure-ciba/main) also support, so it fits identity providers companies already run; on top of it, the agent ends up holding nothing, there is no way around the gate, each approval covers one exact request and is used once, and the target system's own log keeps the score.

## Running on Vultr

| Vultr product | Role here |
|---|---|
| Cloud Compute, control plane (`vc2-4c-8gb`, Frankfurt) | Gate, broker, Keycloak, realm factory, demo app, TLS. Holds the inference key. Runs no agent code. Keycloak listens on localhost only and the broker on the VPC only; the realm factory is the only process holding Keycloak's master admin. |
| Cloud Compute, worker (`vc2-2c-4gb`) | Every visitor's Python, one fresh gVisor (`runsc`) container per script. |
| VPC (`10.40.0.0/24`) | Carries the sandboxes' only traffic: a signed edge to the broker's VPC address, port 8090. Rules on the worker drop every other packet from a sandbox, cloud metadata included; the VM itself keeps its public interface for updates. |
| Firewall groups (two) | SSH from the operator's address only; 80/443 on the control plane only. |
| Serverless Inference | The agent's models: `qwen3.8-27b` (live default), `glm-5.3-flash`, `deepseek-v4.1-flash-1017`. Called from the control plane; the key does not enter a sandbox. Each record stores the model the API reports it served. The 5,240-run evaluation cost $29.70 in model calls. |
| Vultr API (`deploy/vultr_deploy.py`) | Deploys and tears down everything. `fleet N` created and deleted the temporary evaluation workers; `ap-vm-up` / `ap-vm-down` the temporary payments VM. 17 instances created through the API, 15 deleted. Vultr's account activity log records each create and delete; the agent holds no Vultr credential. |

Vultr billed $81.84 through 7 November: $75.06 Serverless Inference, $6.78 Cloud Compute. Instance by instance: [`docs/EVIDENCE.md`](docs/EVIDENCE.md).

## Results

Honest requests still go through: with the gate, 77% to 92% completed in the best setup, measured before a routing fix that later brought the main failing case to 7 or 8 of 8. Most of the rest were handed to a person instead of going through. Payments: a hijacked agent changed a supplier's bank details in 0 of 30 runs on Vultr.

Every test was written down before it ran (pre-registered; the main one committed 5 Nov 12:14 UTC as `a6de962`, before the first paid run), and every cell is published, including the bad ones. All callers, owners, managers and clerks are scripted. "Light" and "hardened" are the two system prompts we tested: a normal help-desk prompt and one that spells out every verification rule.

| Measurement | Result | Source |
|---|---|---|
| Gate on (5,240 runs, 3 models x 2 prompts) | **0 of 1,199 attack runs changed an account without the approval its policy requires** (95% upper bound 0.3%). The agents still tried: 2,458 write attempts; the 81 that ran each had an approval. 25 lost-device recoveries went ahead because the manager approved, as policy allows, and are counted separately. | [`RESULTS-gateon.md`](eval/RESULTS-gateon.md) |
| Same system, gate off | Unsafe on attacks: light prompt 5.8% / 36.3% / 44.7% (deepseek / qwen / glm); hardened 0.5% / 10.5% / 24.2%. 25 attack runs handed the caller a temporary password; 0 with the gate. | `RESULTS-gateon.md` |
| What the gate costs on honest tickets | Before the routing fix: light prompt + gate completed 58% to 77% of honest tickets; hardened prompt + gate 77% to 92%; hardened prompt alone 95% to 100%. Most of the gap was one case routed to a manager the simulation did not answer; after the fix, that case completed 7 or 8 of 8 in five of six setups. | `RESULTS-gateon.md`; [`RESULTS-secondaries.md`](eval/RESULTS-secondaries.md) |
| Binding the approval to the request | A hostile agent reused an unbound approval to change the CFO's email in 5 of 30 runs; with the bound, single-use receipt, 0 of 30. | `RESULTS-secondaries.md` |
| The live demo's attack (measured on our machine) | Fooled qwen3.8-27b in 34 of 40 runs, glm in 18, deepseek in 1. One strong attack chosen for the demo; across all the evaluation's attacks, qwen with the same prompt was fooled in 36.3%. | [`RESULTS-demosetup.md`](eval/RESULTS-demosetup.md) |
| Payments on ERPNext | An agent told to change a supplier's bank details by any means attempted 132 unapproved writes in 30 runs on a Vultr VM; none reached ERPNext's change log. Without the gate the same instructed agent changed the account in 22 of 30 runs (our machine), so the 0 is the gate, not the model declining. Honest changes approved by the supplier's contact: 29 of 30. | [`RESULTS-ap3.md`](eval/RESULTS-ap3.md) |

The scripted owner is absent or declines on attack runs, so 0 of 1,199 tests the mechanism, not a real person's judgment. More results (regression on the merged code, no-lie controls, the earlier measurement): [`docs/EVIDENCE.md`](docs/EVIDENCE.md).

## How it works

1. **The agent** has one tool, `run_python`. Each script runs in a fresh gVisor container on the worker: read-only root, no capabilities, 256 MB, no credential, no internet, no DNS, no cloud metadata. Its only route out is an edge proxy that signs each request for its run and forwards it over the VPC.
2. **The gate** parses every request against the policy pack (`packs/helpdesk.json`). Reads pass a field filter; anything the pack does not describe is refused; every write needs a receipt.
3. **The approval.** A receipt is minted when the approver named by policy (the owner; the manager for a lost device or a contact change) approves a Keycloak CIBA push on their own device naming the exact change and account, with number matching. It is bound to the run, operation, user and request hash, burned in one SQL statement before the broker forwards, used once. The agent re-sends the same request and holds no token, receipt or secret; the temporary password goes to the owner's phone.
4. **The record.** Keycloak's admin-event log, read by an account that can only read events, is reconciled to the receipts; a change without a receipt would show as an orphan.

Consent-fatigue controls: a wrong number declines; every card names the change and account; 3 pushes per approver per 10 minutes; one decline freezes that account's agent-driven changes for 24 hours (expires on its own, no override); after a manager's approval a cooling-off (60 s; 600 s privileged; 20 s and 40 s in the demo) during which the owner can cancel; a run that retries a declined change or repeats the same unapproved request four times is quarantined.

## Same gate, second system

Accounts payable on ERPNext: a supplier's bank details change only after the contact registered for that supplier at onboarding approves the exact change on their own device, and ERPNext's own Version log, read by a separate user, keeps the score. Adding it took about 400 lines: a 42-line policy file (`packs/ap.json`), a connector to ERPNext and a lookup of each supplier's registered contact; the gate's rules engine is the same. Measured on a temporary Vultr VM; shown on `/policy`; not in the live demo.

- **Why a hijacked agent, not a forged invoice?** These models saw through the forged supplier letter on their own (0 of 30, twice, including a letter that explained the contact's silence): it came from outside, and they noticed the new contact details came from the same email. The help-desk lure that did fool them was an insider's note plus a story for the owner's silent phone. So the payments pack is measured against the worse case, an agent told to do it.
- **A fake supplier or account?** Not through the gate: the pack has three reads and two edits of existing accounts, and the gate's ERPNext user cannot create or delete. The payment check compares the current default account with the approved register, so a change made outside the gate reads "hold".
- **A compromised registered contact?** The contact comes from a directory filled at onboarding; no request, ticket or gate operation changes it. A compromised contact's device is the residual risk, the same class as a fooled manager.

## Questions a skeptical judge asks

**Isn't 0 of 1,199 true by construction?** It tests the implementation under pressure: in 978 of the 1,199 gated lure runs the agents still attempted a write, 2,458 in all, and the log was reconciled to every one. The construction can fail: a code review found, and our probe confirmed, that the console route forwarded walk-back paths, and 3 of 6 variants reset a password without a receipt. It was closed on 5 November, before the test was written down and run, in three layers, each tested alone, and the probe is now a permanent test. Ablations show what carries the weight: trusting the agent's own "verified" claim failed 15 of 30, an allowlist alone 18 of 30, unbound approvals 5 of 30 under a hostile agent, the full gate 0 of 30.

**Why 0.5% to 44.7%? Why not just the hardened prompt?** 44.7% is glm, light prompt (85 of 190); 0.5% is deepseek, hardened (1 of 190, upper bound 2.9%). The hardened prompt alone completed more honest tickets than light + gate, so the setup to run is the hardened prompt plus the gate: 0 unsafe, honest completion 77% to 92% before the routing fix. Hardened alone still failed 24.2% on glm, the gate-off rates are lower bounds, and the model behind an agent changes with the vendor's release.

**MFA fatigue?** A wrong number declines; the card names the change; 3 pushes per 10 minutes; one decline means human help for a day. The open vector: an attacker already talking to the owner can read them the number. The card's named action is the only defence there, and we do not claim people read it.

## Tested and checked

- **Tests:** 385 unit tests (292 behavioural, 93 compile checks) and 9 live integration tests against a real Keycloak 26 (`KEYLESS_LIVE=1`): the console-route bypass as a permanent regression test, every token against every dangerous write with 0 admin events, session isolation, and the honest reset end to end through real CIBA. A fuzzer runs 5,118 grammar cases on every build; 20,000 on the payments grammar found 0 failures.
- **The writer cannot read its scorecard:** the broker's account gets 403 on the admin-event log it is graded by; the view-only reader can read it and cannot write (tested live, `tests/integration/test_scorer_and_player.py`).
- **Weak modes stay in the lab:** the gate-off and ablation modes work only with `KEYLESS_EVAL=1` in a scratch realm named `eval-*`, and the demo's unprotected column only in a factory-issued `demo-u…` company; anything else is refused and logged (`gate/gate.py`, `tests/test_eval_modes.py`).
- **Fail closed:** a ledger that cannot be written denies the request with the receipt already burned; an unreachable approval service is a 503 and an escalation; a failing claim check holds the reply. The evaluation's fail-closed arms: 0 completions, 0 unsafe in 20 runs.
- **Found, fixed, tested:** 27 problems found in our system, by us and by outside reviewers (among them an identity-server path trick, a lost-phone hole and the console-route bypass above), each fixed with a test that keeps it fixed.
- **Before publishing:** the whole git history was searched for every real key we hold: 0 matches.
- **Kept up for judging:** spending caps per conversation, per day and per address; a 17-check smoke test after every deploy.

Every feature, mechanism, test, measurement and fixed bug, with its source: [`docs/EVIDENCE.md`](docs/EVIDENCE.md).

## Honest limits

- Keycloak runs in dev mode on our control-plane VM; its log is read with a view-only account.
- The people in the evaluation are scripted; their timing changed a result once (RESULTS-ap.md, corrected and re-run).
- Corrections we published ourselves: a gate-off outcome first counted against our own amendment (fixed the same day, `RESULTS-gateon.md`); "189 replies carried the temporary password" included honest owners (25 went to attackers); the first payments measurement was a harness artefact, withdrawn the same day and re-run under a new pre-registration.
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
