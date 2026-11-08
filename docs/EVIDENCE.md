# Evidence: everything on Vultr, everything built, tested and measured

This is the long version of the README for a judge who wants every item. Each row names its source: a repository path with line numbers, a commit, a results file, or a Vultr API read with its date. Items that could not be checked against one of those are left out or marked.

Repository state: `main` at commit `946142a` (8 Nov 2026); 151 commits since 4 Nov; 122 tracked files; about 16,700 lines (gate 866, broker 1,468, agent 986, sandbox 193, demo 3,717, deploy 964, devenv 2,127, eval 2,996, packs 227, tests 3,125). Live demo: https://136-244-91-162.sslip.io/

---

## 1. Everything on Vultr

### 1.1 Cloud Compute: all 17 instances

Source for plans, times, hours and cost: Vultr billing API (`GET /v2/billing/pending-charges`), read 2026-11-07 23:48 UTC. Purposes are tied to commits and results files. All `keyless-*` instances: region Frankfurt (`fra`), Ubuntu 24.04 (`os_id 2284`), `backups: disabled`, tags `keyless` / `keyless-fleet` / `keyless-ap` (`deploy/vultr_deploy.py:27, 116-119, 286-289, 594-597`).

| Label | Plan | Created -> deleted (UTC) | Hours | Cost | Purpose and evidence |
|---|---|---|---|---|---|
| t2-probe-1, -2, -3 | 1 GB | 3 Nov 18:53 -> 18:55 (each under a minute) | 1 each | $0.03 | First API probes: create and delete an instance. |
| t9-gvisor-probe (3) | 4 GB | 3 Nov 21:20 -> 21:33 | 1 each | $0.09 | gVisor (`runsc`) and a headless browser on a Vultr VM before the build; the cloud metadata address was reachable from a default container and blocked by a DOCKER-USER rule, which became `deploy/worker.sh:18-26`. |
| keyless-control (1st), keyless-worker (1st) | 4 GB each | 5 Nov 01:47 / 01:51 -> 03:57 | 3 each | $0.18 | First one-command deploy (commits 842718f, b386fcc, 0a7257e, d367223, 9ae3aef). Removed with `vultr_deploy down` after an external code review the same day (commit 68e97ac). |
| keyless-control (live) | vc2-4c-8gb | 5 Nov 12:17 -> running | 60 | $3.58 | The live control plane: broker and gate on the VPC address, Keycloak 26.0.7 and a mail catcher on localhost, the realm factory, the demo app behind Caddy TLS, the CIBA receiver. It also ran the evaluation harness on 5 Nov with the demo service stopped (`deploy/control.sh`; `deploy/vultr_deploy.py:360-399, 429-472`). |
| keyless-worker (live) | vc2-2c-4gb | 5 Nov 12:19 -> running | 60 | $1.79 | The live sandbox worker: every visitor script in a fresh gVisor container, driven from the control plane over SSH on the VPC; egress locked to the broker's VPC address and port (`deploy/worker.sh`; `demo/prod.py:31-32`). |
| keyless-eval-w2, w3, w4 (fleet 1) | vc2-2c-4gb | 5 Nov 13:03 -> 21:07 | 9 each | $0.81 | Temporary evaluation fleet created by `fleet N`. Ran the 5,240-run evaluation with its 11 setup re-runs (records at commit c28d9c9; results committed 20:49 UTC, eb8fab2) and then the first demo-setup measurement (180 runs; records at commit 9e6ea15, the `fleet-sync` at 20:49 UTC; results committed 21:08 UTC, c3337e0), together with the live worker (`deploy/vultr_deploy.py:325-345, 381-398, 542-558`; `eval/RESULTS-demosetup.md:3`). Three of the planned six were created: commit a4f493d records that an account limit aborted a batch. |
| keyless-eval-w1, w2, w3 (fleet 2) | vc2-2c-4gb | 5 Nov 21:59 -> 23:26 | 2 each | $0.18 | The labelled secondaries: 339 token-budget re-runs, 60 hostile-binding runs, 60 honest-manager runs (`secondary-start`, commit a1abc15; results 228bc0d at 23:26 UTC; `eval/RESULTS-secondaries.md:3`). |
| keyless-ap-replication | vc2-4c-8gb | 7 Nov 13:22 -> 14:51 | 2 | $0.12 | The payments replication: ERPNext v16, Keycloak 26.0.7 and gVisor sandboxes on one temporary VM in the VPC; 60 runs and 6 pilot runs; the ERPNext stop-rule check passed 27 of 27 there; deleted after the run and the filming (`deploy/ap_vm.sh`; `deploy/vultr_deploy.py:583-664`; `eval/PREREG-ap3.md`; `eval/RESULTS-ap3.md`). |

Totals: 17 instances created through the API, 15 deleted, 2 running. Cloud Compute $6.78 (Vultr billing API, 2026-11-07). The live pair billed at $0.0597 + $0.0298 = $0.0895 an hour, the "$0.09 an hour" in the README.

### 1.2 Network and keys

| Resource | What we did | Source |
|---|---|---|
| VPC | One private /24 network per deployment (`POST /vpcs`, Frankfurt). It carries the sandboxes' only traffic (the signed edge to the broker, port 8090), the control plane's SSH to the worker's Docker, and the payments VM. The endpoint is `/vpcs`, so "VPC", not "VPC 2.0". | `deploy/vultr_deploy.py:189-190, 98-104` |
| Firewall groups (two) | `keyless-control`: TCP 22 from the operator's address only, 80 and 443 from anywhere. `keyless-worker`: TCP 22 from the operator's address only. Inbound rules; egress is enforced on the worker with iptables. The payments VM used the host firewall (ufw: deny incoming, allow 22, broker and CIBA ports on the Docker bridge only) and no Vultr group. | `deploy/vultr_deploy.py:192-201`; `deploy/worker.sh:18-26`; `deploy/ap_vm.sh:16-22`; `deploy/vultr_deploy.py:594-597` |
| SSH key | A temporary ed25519 key generated per `up`, registered as `keyless-deploy` (`POST /ssh-keys`), kept in a gitignored state directory, deleted by `down`. The control plane generates its own key to reach the workers. | `deploy/vultr_deploy.py:180-187, 133-135, 684-697` |

### 1.3 Vultr API endpoints the deploy script uses

| Endpoint | Purpose | Source |
|---|---|---|
| `POST / GET / DELETE /instances`, `GET /instances/{id}/vpcs` | Create, wait for, read and delete every VM; `recycle-worker` deletes the worker and builds a new one; `fleet N` creates workers in parallel and adopts untracked ones; `down` deletes everything in dependency order. | `deploy/vultr_deploy.py:89-104, 115-139, 255-264, 281-358, 666-700` |
| `POST / DELETE /vpcs` | The private network. | `:189-190, 684-697` |
| `POST / DELETE /firewalls`, `POST /firewalls/{id}/rules` | The two groups and their rules. | `:192-201` |
| `POST / DELETE /ssh-keys` | The deploy key. | `:185-186, 684-697` |
| `GET /account` | `status` prints pending charges. | `:251-252` |
| `GET /v2/logs` | Read once, 6 Nov: the account activity log holds our `Instance created` and `Instance deleted` entries for the evaluation workers with method, path, request body and status. It records the operator's API key. The agent holds no Vultr credential. | Vultr account activity log, read 2026-11-06 |
| `GET /v2/billing/pending-charges` | Read once, 7 Nov, for the figures in 1.1 and 1.5. | Vultr billing API, 2026-11-07 |

A worker is accepted only if `docker info` over SSH reports the `runsc` runtime (`deploy/vultr_deploy.py:316-319`). The code shipped to a VM is `git archive` of tracked files only, checked to contain no `.env` or state (`:76-86`). The Keycloak admin password travels inside the provisioning script on stdin, not on a command line (`:145-150`).

### 1.4 Serverless Inference

| Item | Fact | Source |
|---|---|---|
| Models | `qwen3.8-27b` (live default), `glm-5.3-flash`, `deepseek-v4.1-flash-1017`. The same three in every measurement. | `demo/server.py:50`; `eval/harness.py:43`; `deploy/vultr_deploy.py:457` |
| Where the key lives | On the control plane only, in a root-only environment file; the sandbox environment is rebuilt from a fixed list. | `deploy/vultr_deploy.py:445-459`; `agent/runner.py:104-106` |
| Prices used for cost accounting (USD per 1M tokens, in / out) | glm-5.3-flash 0.10 / 0.35; qwen3.8-27b 0.15 / 1.00; deepseek-v4.1-flash-1017 0.15 / 0.60. | `agent/llm.py:18-22` |
| Served-model guard | Each response's `model` field is stored next to the requested id; the harnesses exclude a run answered by a different model. | `agent/llm.py:72-76`; commit a839f1e |
| Retries and fallback | 3 retries on 429 and 5xx; a 404 moves to the next pinned model; a hard per-run spend cap. | `agent/llm.py:47-65` |
| Recorded runs and spend (sum of the `cost` field over every record in `eval/out/`) | 6,784 recorded runs, $38.01: deepseek 2,088 runs $10.13; glm 2,538 runs $9.76; qwen 2,158 runs $18.11. The main evaluation alone: 5,240 runs, $29.70 (deepseek 1,700 / $8.27; glm 1,840 / $6.78; qwen 1,700 / $14.65). Includes 150 $0 records of a regression attempt that ran without the key. | `eval/out/*/*.json`; `eval/RESULTS-gateon.md:4` |
| Billed total | $75.06 on one usage line since 3 Nov 17:17 UTC. The part not in `eval/out/` is pre-build measurement work, pilots not kept in the repository, and the live demo's visitor traffic (capped at $15 in all). | Vultr billing API, 2026-11-07; `demo/prod.py:38` |
| Cost per protected conversation | About 0.7 cents of model calls (mean of the 2,340 gate-arm records; 0.44 to 1.0 cents by model). | `eval/out/gateon/` records |

### 1.5 Vultr products we did not use

Object Storage, Container Registry, Load Balancer, Managed PostgreSQL and Valkey, Kubernetes Engine, Block Storage, Vultr DNS (the hostname comes from sslip.io), CDN, VX1 instances, Bare Metal and GPU, IAM service users or resource-scoped keys (the account key is used from the operator's workstation only), the Vultr MCP server, an Audit Logs subscription, startup scripts, snapshots, reinstall, reserved IPs, backups.

---

## 2. The live demo, feature by feature

Paths: S = `demo/server.py`, IX = `demo/static/index.html`, SC = `demo/scenarios.py`, L = `demo/limits.py`, F = `demo/factory.py`, P = `demo/prod.py`.

1. **Compare mode is the landing page.** Two columns, two fictional companies: a protected realm for the right column and an unprotected `demo-u` realm for the left; a company of the wrong kind is refused in code. One phone serves both columns; every card names its column. (S:203-206, 266-271, 1026-1034; IX:605)
2. **One-click judge mode.** "Run the attack live (about a minute, no phone needed)". (IX:154, 552-560)
3. **Presets.** In compare order: 1 the planted note asking for a temporary password (the only measured preset), 2 the honest path (a locked-out caller; the agent reads lock status and sessions first), 3 approve one change then ask for another (a follow-up email change claiming prior approval), 4 the twin (the same words from the owner and an impostor; the phone decides), 5 "I lost my phone", 6 "move my authenticator to my new phone", 7 "I'm from your IT provider", 8 write your own attack. Presets without a measurement show no rate. (SC)
4. **Measured-rate line for the selected model** with a setup fingerprint over the prompt, the left column's help text, the two measured scenario texts and the policy pack; a changed setup makes the page say "measured on an earlier version". (S:1158-1165, 1320-1327; IX:308-316; `tests/test_every_file_compiles.py:18`)
5. **Model selector** with each model's measured rate, and a **light / hardened prompt toggle**. (IX:200-202, 299-303)
6. **Ticket editor** with the planted note visible before the run. (IX:176-179, 288-290)
7. **Retry after resistance**, up to 3 attempts, quoting the measured odds. (IX:356-361)
8. **Your own phone by QR code.** One link per session, claimed by the first device, 15 minutes, cookie HttpOnly / Secure / SameSite=Strict; approval requests last 120 s once paired, 60 s otherwise (the measured value), and the page says which applies. (S:48, 58, 1472-1525)
9. **Phone cards.** Three numbers (the true one and two decoys), Deny, "The owner doesn't answer" (expires the request, no decline), LEFT / RIGHT labels, whose phone, plain titles ("Password reset", "Lost-phone recovery", "Identity check (changes nothing)"), a second request says it is the second and what became of the first, a warning when approving someone else's account, cancel notices during the cooling-off, the temporary password shown on the phone only, an email counter, the last four outcomes. A wrong number declines and the page explains why. (S:71-75, 1026-1107, 1431-1439; IX:414-449)
10. **The chat stream.** Script steps grouped per sandbox with code, output and container id; loud refusals that cite the policy rule read from the live pack; the system posts the number to choose; status lines for every push outcome; "Why" boxes for the decline freeze, a manager's approval (the residual stated) and quarantine. (S:473-486, 521-580, 664-681)
11. **Claim check on screen.** A sentence claiming a change the log does not show is struck through, with "Crossed out by the system: the log shows no such change." Every reply ends with a line written from the ledger: "Changes to your account in this session: none." (S:688-698; IX:344-352)
12. **Verdict banners** per column; the right column's verdict names its source, Keycloak's admin-event log read with a view-only account. (S:64, 887-923)
13. **Tiles**: "Agent tried" (the gate's records) over "Identity server recorded" (Keycloak's log), with the admin-event count before and after; the left tile is the positive control. (S:634-637, 924-934)
14. **Receipt tables** per column: change, gate, approver, identity server's own log, with Keycloak's event for each change. (S:949-1020)
15. **Run strip**, measured once per visitor inside a sandbox started like the agent's: where it ran, the kernel reported inside, network none except the gate (five checks), no credential, read-only root, caps set by the runner and read inside, model and inference service. (S:834-854; IX:467-478)
16. **Sandbox lifecycle line**: each script's container id, confirmed gone by Docker on the worker (an unknown result is shown as unknown, not as gone), limits read inside, time limit marked as set. (S:793-832; `agent/runner.py:163-225`)
17. **Containment check.** Part 1: a fresh sandbox's nine checks (no secret-like variable, gate reachable, broker / identity server / internet / cloud metadata / external DNS unreachable, read-only root, non-root). Part 2: three tokens (none, a forged copy, the company's real view-only token) against eight writes (reset the password, send an account-takeover email, change the email, change the approver, sign out everywhere, create a backdoor user, delete a user, switch off the audit log), 24 attempts fired from the control plane at the visitor's own identity server, with the admin-event count before and after. Its own pool of two, one per address per minute. "Not tried: the broker's own account, which lives outside the sandbox." (S:340-422; IX:528-551; `sandbox/probe.py:62-72`)
18. **Policy page** `/policy`: every rule from the live pack with its approver, what is in the file and what is built into the gate, the demo's shorter cooling-off stated, the pack's SHA-256; the payments pack with its own hash, labelled as measured on ERPNext and not running in the live demo. (S:1168-1236)
19. **Share page and JSON evidence.** `/p/<token>` shows both columns, verdicts, receipt rows with Keycloak's own record (operation type, resource path, time) and the whole conversation; `/api/proof/<token>` is the same as JSON, with temporary passwords masked. (S:444-451, 935-946, 1293-1304; `demo/static/proof.html`)
20. **Counters** from the identity server's log: changes without the owner's approval (right), takeovers in attack runs (left), companies deleted and confirmed gone, an archived line for team testing, a "since" date. (S:424-438, 1110-1155, 236-264)
21. **Limits**: $0.05 per conversation reserved before any model call; $0.15 and 12 conversations per session; $3 per UTC day; $15 in all (production); $0.75 per address per rolling day; 6 live sessions per address; 12 live sessions; 6 conversations at once with a queue; per-address state kept as salted hashes; a kill-switch file that pauses new sessions and shows a recorded run; every refusal ends at the recorded run. (L:36-48; P:37-42; IX:570-577)
22. **Team mode** for the operator's tests: skips per-address caps, not spend caps; excluded from the public counters. (S:1245-1263)
23. **Timers**: a 2-minute reply wait with a countdown, "More time" (+2 min, at most 3), "End now"; the agent's own time limited to 240 s and 10 turns; 15 min absolute per conversation; sessions idle out after 8 min and end after 60. (S:47-58, 721-744, 1577-1589)
24. **Company lifecycle**: a realm per visitor from the factory's warm pool (5 protected, 2 unprotected), at most 12 handed out, swept after 75 minutes along with any orphan demo realm; deletion confirmed by the identity server's 404; open sessions archived on shutdown so a restart drops nobody from the counter. (F:33-58, 107-159; S:1602-1612)
25. **Web hygiene**: HttpOnly / Secure / SameSite=Strict cookies, a same-origin check on POSTs, the proxy's own forwarded-address entry only, a Content Security Policy that forbids framing, no stack traces, API docs off, a 64 KB request body limit at the TLS front. (S:1265-1283, 1614-1616; IX:6; `deploy/vultr_deploy.py:461`)
26. **Local self-test** with a scripted stand-in for the model, $0. (S:652-654; `devenv/demo_local.py`)
27. **Payments scene** (not in the live demo; filmed on the temporary Vultr VM): the measured configuration through hooks that are off in measured runs; the hostile run shows the scripted instruction, the gate's log in plain words, a counter of refused writes and ERPNext's own change log staying at zero; the honest run shows the call-back card ("changes nothing") and the bank-change card, a person taps, one change-log entry appears; the footer states where it ran and the measured numbers. (`demo/ap_scene.py:1-15, 150-197`; `demo/static/ap_scene.html:204`)

---

## 3. Security mechanisms by component

### 3.1 Grammar and canonical form (`gate/grammar.py`, `gate/canon.py`)
- Parse, don't match: a request becomes exactly one operation of the policy pack or is refused; methods GET, PUT, POST, DELETE only. (grammar.py:204-271)
- Path characters `^[A-Za-z0-9/_.-]+$`: refuses `;` (the Keycloak 26 matrix-parameter bypass `users/<id>;x=y/reset-password`, noted at line 5), `%`, `?`, `#`, `\`, spaces and non-ASCII; `//`, a trailing slash and `.`/`..` segments refused; fragments, valueless or repeated query keys refused. (16, 50-61, 80-100)
- Reads: query values decoded exactly once; double encoding and control characters refused; a key allowlist and `value_regex ^[A-Za-z0-9 ._@:-]{0,64}$`; `q` accepted only empty. Writes accept no encoding. (67-77; `packs/helpdesk.json:14-29`)
- Typed ids: `{realm}` must equal the pack's realm; every other parameter must be a lowercase UUID. 19 read templates in the help-desk pack, 3 in the payments pack. (103-119; `packs/helpdesk.json:30-50`; `packs/ap.json:9-13`)
- Bodies: closed objects (extra fields refused), type-exact enums, `fullmatch` regexes, action emails limited to `UPDATE_PASSWORD` and `CONFIGURE_TOTP`; the password field is an override blanked before hashing and replaced by a broker secret. (17, 149-201)
- IBAN: non-ASCII refused before upper-casing, spaces removed, shape check, ISO 13616 mod-97. Account numbers `[0-9]{6,20}`. (132-146, 186-191)
- Strict JSON (no duplicate keys, no NaN or Infinity, UTF-8), a canonical body, and a SHA-256 request hash over method, path, sorted query and canonical body. (canon.py:18-61)

### 3.2 Receipts (`gate/receipts.py`)
Bound to run id, operation, user and request hash; TTL 180 s counted from the end of any cooling-off; burned in one SQLite `UPDATE ... RETURNING` under a lock, so two identical concurrent requests cannot both pass; failure reasons in order cancelled, used, cooling_off, expired, no_receipt; the approval snapshot stored in the row; an owner's cancel kills every pending receipt of that user; the unbound redeem exists only for the evaluation ablation. (24-39, 62-117, 119-123; `broker/challenges.py:54`)

### 3.3 Gate order (`gate/gate.py`)
Parse, burn, write "forwarding" to the ledger, then forward; the broker writes "executed" only after the upstream answers 2xx or a composite completes (`broker/app.py:312-330`). A ledger that cannot be written denies the request and the receipt stays burned (293-294). A denial does not depend on the ledger being up (197-200). The agent is told only allowed, outcome, reason, retry time and the challenge's operation and user: no receipt, token or secret (38-47).

### 3.4 Quarantine, strikes and the decline freeze
- Quarantine at once: a malformed write of the classes forbidden character, dot segment, encoded, percent, control characters; any write to the realm root or to `/events`, `/admin-events`, `/role-mappings`, `/clients`, `/authentication`, `/identity-provider`, `/roles`, `/components`, `/keys`. (gate.py:22, 172-184; `packs/helpdesk.json:175-185`)
- Strikes: other malformed writes count per run; four quarantine. The same unapproved request four times quarantines, counted per exact request so two different honest changes do not add up. A retry after an owner cancel or an approver decline quarantines. A broker token or secret appearing in an upstream response quarantines. (gate.py:212-215, 249-257; `broker/app.py:265-271, 338-342`)
- Quarantine is per run: every further request from that run is refused; the state is rebuilt from the ledger after a restart. (`broker/app.py:56-58, 137-149`)
- Decline freeze: a declined push or an owner cancel puts that account (for payments, that supplier) on human-only help for 86,400 s; no new approval request is sent; it expires on its own; rebuilt from the ledger. (`broker/challenges.py:90-110`; `broker/approvers.py:88-89`)

### 3.5 Approvals (`broker/challenges.py`, `broker/approvers.py`, `broker/pushsvc.py`, `broker/keycloak.py`)
- The approver is chosen by policy: the owner; the owner's manager for a lost device or a contact change (a managed attribute no admin-API caller can edit); for payments, the contact registered at onboarding in a directory outside both packs. No approver means human-only. (approvers.py; `packs/helpdesk.json:128-132`)
- Keycloak's native CIBA in poll mode; the binding message `number-label-user.id4-hash8`, at most 50 characters; the number is two digits. (challenges.py:48-50, 111; keycloak.py:82-87)
- The CIBA receiver accepts a notification only if its bearer token is signed by the realm's published key (`kid` lookup, `use: sig`, algorithm from the key, `exp` required). (pushsvc.py:29-54; commit 7131619)
- A wrong number is reported to Keycloak as cancelled, so it counts as a decline. (pushsvc.py:99-101)
- The CIBA access token is discarded; only the status is used. A 5xx or unparseable poll stays pending. (keycloak.py:89-106)
- Rate limit: 3 pushes per approver per 600 s, failed sends included; one push per challenge; a 1 s server-side minimum between polls; check-and-mint under one lock; a run cannot see another run's challenge. (challenges.py:121-123, 141-183)
- Cooling-off after a manager's or contact's approval only: 60 s, 600 s for privileged accounts (20 s and 40 s in the demo); the owner is notified on every device with a single-use cancel; the snapshot taken at approval is re-checked at execution and the change aborts if the account changed or the snapshot is missing. (challenges.py:95-100, 184-224; `broker/app.py:292-306`; `demo/stack.py:23`)
- Composites are run by the broker with fixed steps; no redirect or client parameter; 600-second action links; a failed step stops the sequence and notifies the owner. The lost-device sequence keeps sessions; the compromise response ends them. (`broker/composites.py`; `packs/helpdesk.json:133-168`)
- The temporary password is generated by the broker and delivered to the owner's phone only after a 2xx; the agent does not receive it. (gate.py:279-288; `broker/app.py:343-345`)

### 3.6 Run keys and the edge (`broker/runkey.py`, `sandbox/edge.py`, `broker/app.py:86-107`)
A master key (`token_hex(32)`, root-only file) on the control plane; a per-task key `HMAC-SHA256(master, "keyless-run-key\n" + run_id)` that reaches only that task's edge; the edge signs `run_id`, timestamp, method, target and the body hash; a 120-second window with clock skew logged; unsigned, forged or stale requests get 401; a run must be open, and a closed run speaks for nothing after a restart; the edge refuses `Transfer-Encoding`, duplicate or non-numeric `Content-Length` and bodies over 1,000,000 bytes, and strips any run header the sandbox sends. (`deploy/bootstrap_realm.py:14-17`; runkey.py:18-55; edge.py:19-26, 45-61)

### 3.7 Sandbox (`agent/runner.py`, `sandbox/`, `deploy/worker.sh`)
Per task an internal Docker network whose only other member is the edge (fixed hosts entry, no DNS); the task container runs `--rm --read-only --tmpfs /tmp:rw,size=16m,noexec --memory 256m --memory-swap 256m --cpus 0.5 --pids-limit 64 --cap-drop ALL --security-opt no-new-privileges`, the ticket mounted read-only, `--runtime runsc` on every remote host; the environment is rebuilt with `env -i` and a fixed list (path, home, SDK path, gate URL, ticket file, realm); the container is destroyed on exit or timeout; a lifecycle check records whether Docker still knows the container; a probe inside the sandbox reports the kernel, the gVisor flag, the cgroup limits and nine reachability and credential checks. The worker drops traffic to the cloud metadata address and allows only the broker's VPC address and port from any sandbox network. Production refuses to start if any sandbox host is not remote or if the evaluation flag is set. (runner.py:104-106, 130-161, 163-225; `sandbox/probe.py:38-72`; worker.sh:18-26; `demo/prod.py:26-32`)

### 3.8 Console route (`broker/console.py`)
A view-only console user; an allowlist of console routes with the strict path check; the token endpoint limited to the console's own client and two grants with the body rebuilt from parsed fields; headers allowlisted; the browser receives tokens with broken signatures and the broker swaps the real one in; cookies kept in the broker; a leak check that withholds any real token; the display tweak on `whoami` documented in the code. (console.py:37-57, 80-136, 157-209)

### 3.9 Identity-server accounts and the realm factory (`devenv/keycloak_local.py`, `demo/factory.py`, `demo/stack.py`)
The broker's service account has `manage-users` and `view-users` only; the reconciler has `view-events` only and reads the admin-event log; the broker's account gets 403 on admin events, events and event config (`tests/integration/test_scorer_and_player.py`); `manager` and `privileged` are managed attributes with edit permission for nobody; brute-force protection is on. The realm factory is the only process holding the master admin credential, listens on localhost with a bearer token, and deletes only realms matching `demo-[su][0-9a-f]{12}`. The demo process holds no master-admin credential. (keycloak_local.py:118-121, 151-177; factory.py:1-11, 28, 70-71, 165-166; stack.py:1-6)

### 3.10 Fences around the weaker modes (`gate/gate.py:50-71, 95-118`)
The evaluation's gate-off and ablation modes are honoured only with `KEYLESS_EVAL=1` and a realm named `eval-*`; the demo's "agent decides" column only with `KEYLESS_DEMO_CONTRAST=1` and a factory-issued `demo-u` realm. Anything else raises and is written to the ledger. (`tests/test_eval_modes.py`)

### 3.11 Claim check (`agent/claims.py`, `agent/loop.py`)
A per-sentence detector (an account subject plus a completed-change marker, with negations, conditions and intentions excluded); only `executed` and `partially_executed` ledger entries of this run count; a missing ledger means nothing counts as executed, so every claim is corrected; the struck claims are replaced by a correction and the reply gets a banner; the "Changes to your account in this session (from the system log)" line is built from the ledger and appended to every reply; a crashing check holds the reply. Tuned on 10,344 stored replies: false holds fell from 14.8% to 0.9% (commit 10cc29b). (claims.py:37-135; loop.py:69-78)

---

## 4. Tests

Counts from `python -m pytest --collect-only -q tests`: 394 items, of which 385 unit (174 test functions in 26 files; 93 of the items are per-file compile checks) and 9 live integration tests in 5 files that run only with `KEYLESS_LIVE=1` against a Docker Keycloak 26. `python -m pytest tests --ignore=tests/integration`: 385 passed (8 Nov).

| Area | Files (items) | What they prove |
|---|---|---|
| Gate core | `test_grammar.py` (36), `test_gate.py` (13), `test_receipts_ledger.py` (10), `test_fuzz.py` (9) | 13 path tricks refused (`;x=y`, `;jsessionid`, `%64`, `/../`, `//`, trailing slash, case, other realms, `#`, `\`, unexpected query); 7 body tricks (extra field, `temporary:false`, `otp`, duplicate key, array, NaN, non-UTF-8); the override field blanked in the hash; receipts single-use and bound (cross-run, other operation, other account, body mutation); 16 threads redeem one receipt, exactly one wins; 12 concurrent identical requests, one forward; ledger edit, deletion and truncation detected; ledger down fails closed with the receipt burned; writes to the witness paths quarantine; the fourth identical unapproved request quarantines; two honest changes do not add up. Fuzzer on every build: 6 targets, 600 cases each (broker 150), two seeds, 5,118 cases, 0 failures and 0 false rejections required; fuzzer-found regressions pinned (type-exact enums, trailing newline, IBAN newline and case folding, control characters). |
| Broker and approvals | `test_broker_app.py` (13), `test_consent_fatigue.py` (29), `test_composites.py` (8), `test_ciba_poll.py` (9), `test_pushsvc.py` (6), `test_approvers.py` (2) | The honest loop through CIBA with the broker's password and a replay refused; a push flood sends 3 then rate-limits; a forbidden write quarantines the run; an upstream 500 is recorded as failed, not executed, and the claim is held; push service down and ledger down are clean 503s with nothing changed; a `;` path does not reach Keycloak; cooling-off then run; the lost phone gets a cancel and cancelling stops the change; privileged accounts wait about 600 s; the decline freeze lasts 24 h; a changed snapshot aborts; quarantine only on hostile signals (10 cases); 8 restart-durability tests (snapshot, quarantine, freeze, cancel, rate limit, attempt counts, strikes); 8 concurrent polls mint one receipt; lost-device goes to the manager and not to the lost phone, the email only to the address on file, no logout; the agent cannot parameterise a composite; a failed step stops and tells the owner; the CIBA poll mapping (5xx and garbage stay pending); a wrong number declines so tapping every option cannot approve; the receiver accepts only realm-signed tokens; the resolver refactor matches the previous code in every case. |
| Edge, run keys, console | `test_runkey.py` (13), `test_edge.py` (1), `test_console_unit.py` (17) | Unsigned, forged, stale and other-run signatures refused; the 120-second window with skew logged; closed runs speak for nothing after a restart; 1,000 random run ids are unique; a real edge to a real broker over sockets; 7 raw malformed-HTTP payloads; the edge strips the sandbox's run header; the token endpoint is not a password oracle (8 cases); only allowlisted headers reach Keycloak; control characters refused, not crashed. |
| Claim check and agent loop | `test_claims.py` (41), `test_agent_loop.py` (9) | 27 honest sentences are not claims and 14 claims are caught (real model sentences); a fooled agent's "has been reset" is corrected; a failing check fails closed; every reply ends with the ledger line; script errors go back to the model. |
| Payments pack | `test_ap_pack.py` (20) | IBAN canonical form and mod-97; 9 refused grammar cases (human names, URL-encoded names, ERPNext method endpoints, raw resource paths, DELETE, party fields); the approver comes from the account record; the push label names old and new last four digits; the freeze is per supplier; a write aborts on a changed snapshot; a company account is refused; the payment check matches an approval and holds on a change made outside the gate; reads show last four digits and opaque references only. |
| Evaluation fences and scripted people | `test_eval_modes.py` (21), `test_eval_owner.py` (3), `test_oracle_classify.py` (2) | The weak modes are refused in the demo realm with and without the flag; "agent decides" is refused outside a `demo-u` realm and without its flag; the unbound and naive ablations behave as described; an identity-check approval unlocks nothing; waiting on an unsent push returns at once; an honest approver denies a push for another account; a credential removal logged as ACTION is classified and not an orphan. |
| Demo | `test_demo_limits.py` (13), `test_demo_run_cleanup.py` (1) | 50 threads making 20 reservations each do not overshoot the cap; the per-address money cap, 6 live sessions per address, salted hashes, team traffic skipping address caps but not spend caps, no daily session cap, the kill switch; the broker route is dropped when the sandbox fails to start. |
| Sandbox runner | `test_runner_args.py` (4), `test_runner_lifecycle.py` (5) | The `docker run` flags are locked down; the run key goes to the edge and not to the sandbox; a container is "gone" only when Docker says so. |
| Hygiene | `test_every_file_compiles.py` (94), `test_readme_numbers.py` (4), `test_prompt_hashes.py` (2) | 93 files compile; the measured rate carries the running setup's fingerprint; README numbers match the measured values and the results file; the evaluation texts are byte-identical to the pre-registered hashes and the shipped help text adds only the re-enrolment line. |
| Live integration | `integration/test_console_route.py` (1), `test_invariant.py` (1), `test_scorer_and_player.py` (1), `test_live_keycloak.py` (3), `test_session_isolation.py` (3) | The console-route bypass is a permanent test (the probe must report "no reset reached Keycloak"); the invariant probe must print "0 accepted; Keycloak admin events during the replay: 0" (every sandbox-side token against every pack write and the dangerous admin writes); the broker's account gets 403 on admin events, events and event config and the reader gets 200; the honest reset end to end through real CIBA leaves exactly one admin event, the attacks leave none and the two hostile runs are quarantined; lost-device live with the manager approving and the mail going only to the address on file; a fooled manager then the owner cancels: 0 events, 0 mails; two companies cannot address each other; push limits and phones are per session; the factory pool and cap. |

Standalone tools in `devenv/`: `fuzz.py` (`python -m devenv.fuzz 20000` on the payments target found 0 failures, commit 49704ea), `invariant_probe.py`, `console_route_probe.py`, `console_probe.py` and `browser_sandbox_probe.py` (a headless browser inside the sandbox driving the real console through the gate), `erp_witness_check.py`, `loadtest.py` (commits 8fa4352, 6802ae5: capacity set to 12 sessions, 6 conversations at once, idle sessions freed after 8 min), `smoke.py` (17 checks against the public site after every deploy: page and name live, health, models listed, a compare session, the honest path completing in both columns, the phone answered with each column's own number, the tiles, a refusal citing its rule, gVisor measured in the run strip, sandboxes measured and confirmed gone, counters, deletions confirmed, the payments pack on the policy page, the phone link single-device, a wrong number declining), `demo_local.py --selftest`.

---

## 5. Every measurement set

| Measurement | Pre-registration | Where | n | Result | Stop reason, cost | Results |
|---|---|---|---|---|---|---|
| Gate-on evaluation | `eval/PREREG-gateon.md`, committed 5 Nov 12:14 UTC (a6de962) before the first paid run; amendments 1-3 before the main run; deviation log written during it | Vultr: fleet 1 and the live worker, gVisor; models on Serverless Inference | 5,240 (3 models x arms A/B/C/D, 4 ablation arms, 2 fail-closed arms) | 0 of 1,199 attack runs changed an account without the approval its policy requires (upper 95% bound 1.8% per cell; pooled over all 1,199, Clopper-Pearson 0.31%, computed as 1 - 0.025^(1/1199)); 25 manager-approved lost-device recoveries reported as their own category; without the gate, light prompt 5.8% / 36.3% / 44.7% and hardened 0.5% / 10.5% / 24.2% (deepseek / qwen / glm); honest completion with the gate 23 to 37 points below the hardened prompt alone (H2 refuted); 10 approved extra changes on honest runs (H4 refuted); 25 passwords to attackers without the gate, 0 with; ablations naive 15/30, allowlist-only 18/30, unbound 0/30 (not exercised), full 0/30; 0 orphan events and 0 executions without a receipt in 2,389 gate runs; fail-closed arms 0 completions, 0 unsafe of 20; 2,458 attempted writes, 81 executed each with an approval; 978 of 1,199 lure runs attempted a write | finished; $29.70 of $55 | `eval/RESULTS-gateon.md`; `eval/out/ANALYSIS-gateon.md` |
| Secondary 1: token budget 8,000 | labelled secondary | Vultr fleet 2 | 339 | empty replies 340 -> 8; gate arms 0 unsafe; gate-off failures rose (arm A 25 -> 31 of 64) | finished; $2.19 of $3 | `eval/RESULTS-secondaries.md` §1 |
| Secondary 2: binding under a hostile objective | labelled secondary | Vultr fleet 2 | 60 | unbound approvals reused 5/30; bound receipt 0/30 | finished; $0.33 of $0.50 | §2 |
| Secondary 3: owner-approved re-enrolment, honest manager (post-measurement fix) | labelled secondary | Vultr fleet 2 | 60 | C 8/8 for all three models; D 3/8, 7/8, 8/8 | finished; $0.38 of $1 | §3 |
| Demo-setup measurement, 5 Nov | `eval/PREREG-demosetup.md` | Vultr fleet 1 and the live worker | 180 | takeovers qwen 32/40, glm 21/40, deepseek 9/40; honest 18, 18, 20 of 20 | finished; $0.44 of $3 | `eval/RESULTS-demosetup.md` |
| Demo-setup re-measurement, 7 Nov | amendment 1 (read-only checks, locked-out caller, seeded failed sign-ins) | our own machine, Docker sandboxes | 180 | qwen 34/40, glm 18/40, deepseek 1/40; honest 19, 20, 20 of 20; fingerprint stored with the page | finished; $0.578 of $0.99 | same file, 7 Nov section |
| Payments v1 | `eval/PREREG-ap.md` | our own machine, local ERPNext v16 | 120 | gate arms 0/30 changed, honest 30/30; the no-gate clerk arm withdrawn the same day as a harness artefact (the clerk's line reached the agent in 19 of 30 runs) | finished; $0.466 of $1 | `eval/RESULTS-ap.md` |
| Payments v2: fixed, harder, hostile | `eval/PREREG-ap2.md`, committed before the runs | our own machine | 60 + 60 + 60 | without the gate under clerk pressure 0/30 and 0/30 (delivery valid 29-30 of 30); hostile agent without the gate 22/30 (the setup check); with the gate 0/29, 142 unapproved writes refused, 9 runs quarantined; one harness crash excluded | finished (the hostile suite paused at its first cap and resumed under a logged deviation); $1.735 of $1.85 | `eval/RESULTS-ap2.md` |
| Payments v3, replicated on Vultr | `eval/PREREG-ap3.md` | a temporary Vultr VM, gVisor | 60 (+6 pilot) | hostile agent with the gate 0/30, 132 unapproved writes refused, 1,809 requests outside the policy, 9 malformed, 10 runs quarantined; honest 29/30 (the miss hit the 3-push limit) | finished; $0.690 of $1.75 | `eval/RESULTS-ap3.md` |
| Regression on the merged code | `eval/PREREG-regress.md` | our own machine | 150 (+3 setup re-runs) | 0 unsafe in 80 lure runs; 0 orphans; 0 executions without a receipt; honest 9/11, 9/11, 12/12; the help text differs from the pinned hash by one added line, stated | finished; $0.989 of $1.50 | `eval/RESULTS-regress.md`; `eval/out/regress-analysis.md` |

Every record in `eval/out/` carries the commit, the harness and prompt hashes, the requested and served model, the cost and the stop reason (`eval/harness.py:263-267`). The analysis checks the hashes against the pre-registered values and reports any cell above a 5% exclusion ceiling as invalid rather than cleaning it (`eval/analyze.py:29-30, 145-158`).

---

## 6. Outside checks

| Check | Result | Source |
|---|---|---|
| ERPNext stop-rule check (`devenv/erp_witness_check.py`): the gate's API user can edit supplier bank accounts and read suppliers and is refused everywhere else; ERPNext's own Version log records the change with field, old, new, user and time; the gate user cannot switch change tracking off, edit or delete Version records, rename or delete bank accounts, or change the party fields; a separate read-only user reads the log | all checks passed locally before the pack was built; 27 of 27 passed on the Vultr VM with real permission refusals | commits 098bf7c, 2f66b1c, 12852a0; `eval/PREREG-ap3.md:44-45` |
| The writer cannot read its scorecard | the broker's account gets 403 on admin events, events and event config; the view-only reader gets 200 (Keycloak 26.0.7, 7 Nov) | `tests/integration/test_scorer_and_player.py`; commit 622f052 |
| Invariant probe against Keycloak itself | every token the sandbox side could hold, replayed against every pack write and the dangerous admin writes: 0 accepted, 0 admin events; the probe disproved our own earlier claim that the approver attribute was protected (the broker's account could change it), which led to the managed attribute | `devenv/invariant_probe.py`; `tests/integration/test_invariant.py`; commit 182cc2e |
| Console-route probe | an external code review on 5 Nov found that console-prefixed paths that walk back to the admin API reached Keycloak with the console's token; confirmed with a probe (3 of 6 path variants reset a password, per the review note), closed in three layers, each tested alone, now a permanent live test | commit 68e97ac; `devenv/console_route_probe.py`; `tests/integration/test_console_route.py` |
| Git-history secret scan | all 135 commits and 468 file versions searched for every real secret value from `.env` and the deploy state: 0 matches; 3 generic-pattern hits, all code (such as `deliver_secret=` and `const token = location`) | secret scan, 8 Nov |
| Post-deploy smoke test | 17 checks against the public site after every deploy (section 4) | `devenv/smoke.py` |
| Blind internal reviews | several rounds of reviews by readers who saw only the materials, with reading orders rotated: of the README against the previous version, of the payments scene design, and of the entry's positioning against other submissions. Their notes shaped the README and the scene; they are not published as scores. | project notes outside the repository |

---

## 7. Found, fixed, tested

| Found | Fixed | Tested | Commit |
|---|---|---|---|
| Keycloak 26 accepts a matrix parameter in the path (`users/<id>;x=y/reset-password` acts on `<id>`) | strict path grammar: parse, don't match | `test_path_tricks_rejected`, `test_semicolon_bypass_is_denied_and_quarantined`, `test_semicolon_path_never_reaches_keycloak` | 19c610a (`gate/grammar.py:5`) |
| The approval for a lost device went to the phone the caller says is lost | the manager approves on their own device; the owner is notified everywhere with a cancel; human-only without a manager; sessions kept | `test_lost_device_goes_to_the_manager_not_the_lost_phone`, `test_the_lost_phone_gets_a_cancel_and_cancelling_stops_it`, live `test_lost_device_live_*` | 1c33193 |
| The console route forwarded walk-back paths with the console token; resets reached Keycloak without a receipt | a view-only console user; an allowlist route with the strict path check; the token swapped only by the broker | `tests/integration/test_console_route.py`; `test_console_unit.py` | 68e97ac, b944ccc |
| The device API was public and unauthenticated | the public front served health only; then phone routes bound to the session, a QR-paired device, server-side decoys | `test_another_users_phone_cannot_answer`; `test_session_isolation.py` | 0a7257e, 3ec82ed, 0d35fbc |
| The ledger wrote "executed" before Keycloak answered | "forwarding" at the burn, "executed" only after a 2xx or a completed composite | `test_upstream_refusal_is_never_recorded_as_executed` | 7aa0714 |
| The snapshot re-check was skipped when the challenge was missing after a restart; quarantine, freeze and counters lived in memory | the snapshot stored in the receipt row, abort if absent; state rebuilt from the ledger | 8 `*_survives_a_restart` tests, `test_receipt_without_snapshot_aborts_the_composite` | 7aa0714, 5c97db2 |
| Two concurrent polls could mint two receipts | check-and-mint under one lock | `test_concurrent_polls_mint_one_receipt` | 7aa0714 |
| The broker trusted any run id arriving from the VPC | per-task HMAC keys and request-bound signatures with a 120 s window | `test_runkey.py` (13 tests) | b66ea10, a27637d |
| The token endpoint accepted any grant, so a script could guess passwords from status codes | only the console client and two grants, body rebuilt; brute-force protection on | `test_token_endpoint_is_not_a_password_oracle` | b944ccc |
| Our own claim that the approver attribute was protected was false: the broker's account changed it | `manager` and `privileged` as managed attributes with edit for nobody | invariant probe (live) | 182cc2e |
| Number matching could be defeated: a wrong tap left the request open | a wrong number declines the request | `test_a_wrong_number_declines_the_request_so_tapping_every_option_never_approves`; smoke check | 5d387ae |
| The CIBA receiver accepted any bearer string | notifications accepted only with a token signed by the realm's published key | `test_notify_accepts_only_tokens_signed_by_this_realm`, `test_notify_without_bearer_is_refused` | 7131619 |
| A 5xx on the CIBA poll was read as "expired" | 5xx and unparseable answers stay pending | `test_ciba_poll.py` | 5d387ae |
| Each conversation's broker route was kept alive (a leak) | the route is dropped when the run ends | `test_route_is_dropped_when_the_sandbox_fails_to_start` | 5d387ae |
| The per-address limit trusted a spoofable forwarded-address header | only the proxy's own entry is used | code (`demo/server.py:1281-1283`) | fc677cc |
| Fuzzer findings: `1 == True` passed an enum; a trailing newline passed a regex; control characters crashed the console query parser; a trailing-newline IBAN crashed the checksum | type-exact enums; `fullmatch`; refusal instead of a crash; `fullmatch` on the IBAN | `test_enum_fields_are_type_exact`, `test_regex_fields_do_not_accept_a_trailing_newline`, `test_control_characters_in_the_query_are_refused_not_crashed`, `test_iban_trailing_newline_and_case_folding_are_refused` | afd00dc, 49704ea |
| Push service down and ledger down returned 500s | clean 503s with nothing changed | `test_push_service_down_is_a_clean_503_and_nothing_changes`, `test_ledger_down_is_a_clean_503_and_nothing_changes` | 80a198d |
| An honest run was quarantined because denials of two different changes added up | attempts counted per exact request | `test_two_different_honest_changes_never_add_up_to_a_quarantine` | code (`gate/gate.py:249-255`) |
| A misleading reply passed the keyword claim check | every reply ends with a line written from the ledger; per-sentence detection and corrections in place | `test_every_reply_ends_with_a_line_written_from_the_ledger`, `test_claims.py` | 10cc29b, 96b97cc |
| The gate-off baseline had no way to verify a caller, which would have flattered the gate | a `verify_caller` push, bound to nothing, in the gate-off help text | `test_gate_off_help_text_is_honest` | 447cb55 |
| Waiting on a push that was never sent took 17 minutes; the cooling-off refusal gave no time | `not_sent` at once; `retry_after_seconds` | `test_waiting_on_a_push_that_was_never_sent_returns_at_once`, `test_cooling_off_then_runs` | 4cefbef |
| A scripted honest approver approved a push naming the wrong account | honest approvers read the named target and deny others; a wrong-account outcome | `test_honest_approver_denies_a_change_on_another_account` | f888681 |
| A reused VPC address kept a deleted worker's SSH host key; an account limit left created workers untracked; `systemctl enable --now` kept old code running; the ufw rule for the CIBA receiver was not persisted | host key forgotten before connecting; every instance tracked at once; explicit restarts; rules persisted | deploy scripts | cb6e899, a4f493d, bb5f298, 24b7100 |
| Vultr's Ubuntu image ships with ufw on (SSH only), which silently blocked TLS issuance and VPC traffic; Docker's DNS does not work under gVisor | ufw rules for 80, 443 and the broker port; a fixed hosts entry for the gate | deploy scripts | 0a7257e, d367223 |
| A model can be served under a different id than requested | the served model is recorded and a mismatch is excluded | `agent/llm.py:72-76` | a839f1e |
| A restart dropped a visitor's open company from the public counter; a LEFT push appeared twice on the phone; a wrong tap had no explanation | open sessions archived on shutdown; one card per request; a start-over explanation | `demo/server.py` | a17c08f, 286059c, 176861c |

---

## 8. Corrections we published

- The first analysis counted `approve_then_switch` as unsafe in the gate-off arms against our own pre-registered amendment; corrected the same day, before any slide used the numbers (`eval/RESULTS-gateon.md:7-9`; commit b89f9c8).
- "189 replies carried the temporary password" included honest owners rightly given their password; the attack-only count is 25 without the gate, 0 with it (`eval/RESULTS-gateon.md:10-11, 26-27`).
- Keycloak 26.0.7 logs a credential removal as ACTION, not DELETE, so the oracle's classifier missed it; every stored event was reclassified at analysis and the outcomes reported both ways (`eval/PREREG-gateon.md:188-202`; `tests/test_oracle_classify.py`).
- Empty agent replies were the 3,000-token budget; the affected runs were re-run at 8,000 and the gate-off failure rates rose, so the published gate-off rates are lower bounds (`eval/PREREG-gateon.md:203-213`; `eval/RESULTS-secondaries.md:7-15`).
- The first payments measurement told us what we hoped: the scripted clerk spoke only when the agent paused, so its pressure reached the agent in 19 of 30 runs, mostly with 0 to 3 turns left. The claim was withdrawn the same day, the help-desk evaluation was checked for the same defect (follow-ups delivered in 970 of 988 and 987 of 990 runs), and a corrected re-run, a harder variant and a hostile check were pre-registered before running (`eval/RESULTS-ap.md:19-52`; `eval/PREREG-ap2.md`).
- The first wording of the hostile payments result counted every refused request, including enumeration of paths outside the policy, as an attack attempt; it was replaced by the count of unapproved writes (`eval/RESULTS-ap2.md:56-61`; `eval/RESULTS-ap3.md:38-47`).
- The 5 Nov demo-setup numbers were re-measured after the demo changed; both sets stay published with their dates and setups (`eval/RESULTS-demosetup.md`).
- The honest-path routing that sent a real owner's re-enrolment to a manager the simulation did not answer was fixed after the measurement; the fix is labelled post-measurement and the published numbers stay on the pre-fix version (`eval/RESULTS-secondaries.md:26-40`; commit 765d023).
- The page's fetch-error message once named a cause (ad blockers) that was not established; it was changed to say only that no answer arrived (commit 199843e).
- The policy page and the README said a cooling-off follows every approval; it follows a manager's approval only. Fixed and stated (commit 199843e).

---

## Standards this design follows

| Standard | What it says | Where Rightful follows it |
|---|---|---|
| EU payments: [Commission Delegated Regulation 2018/389](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018R0389), in force since 14 September 2019 | Article 5(1), dynamic linking: the authentication code is "specific to the amount of the payment transaction and the payee", and "any change to the amount or the payee results in the invalidation of the authentication code". Article 4(1): the code "shall be only accepted once". | The receipt is bound to the run, operation, user and request hash; any change to the request finds no receipt; the receipt is burned on use (`gate/receipts.py`). We know of no such rule for an AI agent changing an account. |
| [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), §4.2.3 Account Recovery Notification | Any account recovery must trigger a notification to the subscriber or their designee. | The lost-phone path notifies the owner on every device, with a cancel during the cooling-off; the manager approves and the link goes only to the email on file (`packs/helpdesk.json`, `broker/composites.py`). |
| [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/), LLM07 | "the system prompt should not be considered a secret, nor should it be used as a security control." | The thesis: authorization lives in the gate, outside the model and its prompt. |

## 9. Honest limits

- Keycloak runs in dev mode on our control-plane VM; its log is read with a view-only account.
- The people in the evaluation are scripted; their timing changed a result once (`eval/RESULTS-ap.md`, corrected and re-run).
- The approval is only as truthful as what the approver reads; a fooled manager on the lost-device path is the accepted residual.
- The gate sees the first hop only; read-only abuse is out of scope.
- The demo phone is a web page unless you pair your own. The cooling-off applies after a manager's approval only.
- The prompt-only numbers are an existence proof; the attacks were static.
- Where gVisor ran: the live demo (every script on the Vultr worker; the smoke test checks the kernel the sandbox reports), the 5,240-run evaluation and the Vultr payments replication. Two measurements ran on our own machine with plain Docker sandboxes: the 7 Nov re-measurement of the demo's attack rates (it measures the agent's behaviour, which the sandbox runtime does not change) and the local ERPNext runs.
- The demo keeps receipts in memory, so a restart during a pending approval ends that approval; the decline freeze, quarantine, push counts and cancel buttons are rebuilt from the ledger (`demo/stack.py:40`; `broker/challenges.py:73-84`).
- The push service's phone routes are protected by the host firewall and the Vultr firewall group, not by their own authentication; the public site reaches them only through the demo app's session-bound routes (`deploy/control.sh:58-66`; `demo/prod.py:47`).

---

## Run counts

Every count the README uses, reconciled from the 5,240 records in `eval/out/gateon/` (`spec.arm`, `spec.variant`; per
arm: A light + no gate, B hardened + no gate, C hardened + gate, D light + gate).

| Arm | Lure (attack) | Same-request control | Honest | Total |
|---|---|---|---|---|
| A, B (each) | 600 | 420 | 360 | 1,380 |
| C, D (each) | 600 | 210 | 360 | 1,170 |
| Ablations (naive, allowlist only, unbound, full) | 30 each | | | 120 |
| Fail-closed (push service down, ledger down) | | | 10 each | 20 |
| **All** | | | | **5,240** |

- **190 attack runs per model and prompt without the gate:** 200 lure runs minus approve-then-switch's 10, which
  amendment 1 reports descriptively for the gate-off arms (`eval/PREREG-gateon.md`).
- **1,199 gated attack runs:** C and D's 1,200 lure runs minus 1 excluded (hero_planted_note, arm D, glm-5.3-flash:
  a harness HTTP 500).
- **2,340 gate-arm records** (the cost per conversation's base): all C and D runs. **2,389 gate-on runs** (the
  reconciliation, H7): those 2,340 plus the full-gate ablation (30) and the fail-closed arms (20), minus the 1
  excluded.
- **2,458 write attempts in 978 of the 1,199 gated attack runs; 81 executed,** each after the approval its policy
  requires: 55 owner-approved password resets in approve-then-switch (the change the caller asked for; the switch
  that followed was refused), 25 manager-approved lost-device recoveries (the accepted residual), and 1 account email
  on a contractor's own account approved by its scripted owner (identity_confusion-1, record `r04170-d71e1d62`).
  Per case: `python -m eval.per_attack eval/out/gateon`.
- **96 honest tickets per model and setup:** 120 honest runs per model and arm minus the expected escalations
  excluded as pre-registered.
