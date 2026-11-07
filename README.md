# Rightful (formerly Keyless)

**Authorization is not a model output.** An AI help desk that can be fooled and still cannot change an account.

Live demo: **https://136-244-91-162.sslip.io/** (fictional companies, created per visitor and deleted afterwards)

## The 60-second path for judges
1. Open the live demo. It starts in compare mode: the same agent, the same message, the same planted ticket note and
   the same model go to two columns. Press **Send**.
2. **Left, "the agent decides":** the agent has the same push tool, and a change goes through once the agent itself
   says the caller is verified, as in today's ticketing systems and agent frameworks. Above it, the measured rate for
   exactly this setup: the attack fooled qwen3.8-27b in 32 of 40 runs.
3. **Right, Rightful:** the agent's sandbox holds no credential. Every account change is refused by a gate and turned
   into a request on the owner's phone that names the exact action and account. Watch it refuse, ask the phone, and
   end with "Nothing changed."
4. Try **2. the honest path**: press the number the help desk shows, on the phone at the right, or scan the QR code
   with your own phone. The change goes through, once, for that exact request.
5. **Share this result** shows both columns side by side; the receipt's last column comes from the identity server's
   own log, read with a view-only account, not from our software.

## What we measured (all pre-registered; every cell published, including the ones that came out badly)
- **The gate:** 0 of 1,199 attack runs changed an account they should not have, across 3 models and 2 prompts
  (eval/RESULTS-gateon.md). 0 orphan events and 0 executions without a receipt in 2,389 gate runs.
- **Without the gate,** on the same live system: unsafe on attacks with a light prompt 5.8% / 36.3% / 44.7%
  (deepseek / qwen / glm), with a hardened prompt 0.5% / 10.5% / 24.2%. Most of these removed the owner's
  authenticator on an unverified caller's word (the recovery link went to the owner's own email); 25 handed the caller
  a temporary password (0 with the gate). A typical failure: the verification push was declined, the agent said it
  would escalate, the caller pressed twice, and it wrote anyway.
- **No lie needed:** with the same request and no planted note, the light-prompt agent without the gate still changed
  the account (glm: 8 of 10 in the hero case's control). An agent that holds the authority uses it, lie or no lie.
- **Binding matters** (labelled secondary, eval/RESULTS-secondaries.md): with approvals not bound to the request, a
  hostile agent reused one approval to change the CFO's email in 5 of 30 runs; with the bound receipt, 0 of 30.
- **What it costs** (refuted hypothesis H2, published as refuted): with the gate, fewer honest tickets were completed,
  by 23 to 37 points. Most of the gap was one case the policy routed to a manager the simulation never answered; we
  fixed the routing afterwards (owner-approved re-enrolment, labelled post-measurement) and re-measured that case only:
  7-8 of 8 completed for most model/prompt pairs (deepseek light: 3 of 8). The pre-registered numbers stay on the
  pre-fix version.
- **The demo's own setup** (eval/RESULTS-demosetup.md, 180 runs, re-measured 7 Nov on the setup that is live): the
  demo's attack fooled qwen 34/40, glm 18/40, deepseek 1/40; the same agents completed 19-20 of 20 honest requests.
  (The 5 Nov measurement of the earlier setup, 32/21/9 of 40, stays published in the same file.)

Pre-registrations: eval/PREREG-gateon.md (with its amendments and deviation log), eval/PREREG-demosetup.md. Analysis:
`python -m eval.analyze eval/out/gateon`.

## How it works
- **The agent** (Vultr Serverless Inference models) writes Python scripts that run in a disposable sandbox on a worker
  VM under gVisor. The sandbox holds no credential; its only route out is a signed edge to the broker.
- **The gate** in the broker parses every request against a policy pack (packs/helpdesk.json): reads pass through a
  field filter; every write needs a receipt. A receipt is minted only when the approver chosen by policy (the owner,
  or the manager for a lost device or a contact change) approves a CIBA push on their own device that names the exact
  operation and account, with number matching. It is bound to the run, operation, user and request hash, used once,
  and burned atomically.
- **The oracle** is the identity server's own admin log (Keycloak), read by a view-only account and reconciled to the
  receipts: any change without a receipt would show as an orphan.
- **Consent-fatigue controls:** number matching, the named target, push rate limits, a cooling-off with a cancel on
  every device, and a decline that sends the account to human-only help.

Infrastructure on Vultr: Cloud Compute (a control-plane VM: the broker, Keycloak, the realm factory and the demo; a
worker VM for the sandboxes), a private VPC between them, firewall groups, Serverless Inference for the models. The
evaluation ran on temporary workers created and deleted by `deploy/vultr_deploy.py`.

## Run it
- Tests: `python -m pytest tests --ignore=tests/integration` (342 tests).
- Local demo (Docker): `python -m devenv.demo_local`, then open http://127.0.0.1:8000.
- Deploy to your own Vultr account: `python -m deploy.vultr_deploy up`, then `demo-deploy`; smoke test with
  `python -m devenv.smoke https://<host>`.

## Honest limits
- The approval is only as truthful as what the approver reads; we do not claim that people read phone prompts
  carefully.
- The simulated people in the evaluation are scripted; the owner approves any request naming their own account.
- The gate sees the first hop only; read-only abuse is out of scope; the identity server runs in dev mode for the demo.
- A fooled manager on the lost-device path is the residual risk the policy accepts, and it is reported as its own
  category.

## What we chose not to build
A key the gate cannot bound does not go on the demo server.
- A cloud-operations pack: a Vultr API key acts on the whole account and could not be confined to the demo.
- Fetching visitor-supplied links or files: the egress could not be bounded to one host.
- Running visitors' scripts on the control plane: they run on the worker, because the control plane holds the model
  key, the realm factory's admin credential and the signing master key.
