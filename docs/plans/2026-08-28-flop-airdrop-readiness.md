<!-- markdownlint-disable MD013 MD034 -->

# FLOP Airdrop Readiness Operations Plan

**Status:** Pre-testnet, risk-gated plan as of 2026-08-28

**Goal:** Maximize legitimate FLOP testnet participation and preserve verifiable evidence without assuming eligibility, manufacturing activity, exposing valuable credentials, or spending real money before final rules exist.

**Decision:** Prioritize the agent track, prepare one existing GPU for a miner trial, continue useful ecosystem work, and defer validator operations until final specifications and a resource audit justify them.

---

## 1. What is—and is not—available now

FLOP's official teaser is Version 0.1, labels itself a draft, and says protocol parameters may change because the Yellow Paper is not final.[1] It plans a roughly 90-day testnet in Q4 2026 followed by mainnet in Q1 2027; testnet participation, not today's public Technocore activity by itself, is described as earning the genesis airdrop.[1]

There is no official mainnet token, transferable allocation, final chain identifier, final wallet procedure, live faucet, snapshot rule, or claim transaction documented in the teaser.[1] Therefore, **we cannot obtain mainnet FLOP now**. Current work is readiness and public contribution evidence, not a token claim.

CryptoTelugu's post is a useful third-party summary, not an authoritative eligibility notice.[2] Where it omits caveats or differs from the updated official draft, this plan follows FLOP's official teaser and waits for final network documentation.

## 2. Current official draft economics

The teaser currently describes a 3.5 billion FLOP genesis airdrop with these sub-pools:[1]

| Track | Draft maximum/pool | Draft earning basis | Priority |
| --- | ---: | --- | --- |
| Agents | Up to 1,200,000,000 FLOP | Test-token inference spend plus unspecified prizes | **1 — primary** |
| Miners | Up to 1,200,000,000 FLOP | Verified inference and valid blocks | **2 — controlled pilot** |
| Validators | 305,505,000 FLOP | Launch stake; top 1,000 selected by performance | **4 — defer** |
| Reserve/incentives | Remainder of 3.5B | Not a published individual entitlement formula | **3 — contribution only** |

The draft says an agent allocation arrives locked and can be used only for inference or staking; every 3 FLOP spent on inference unlocks 1 airdropped FLOP.[1] This is an **unlock condition after allocation**, not proof that every testnet FLOP spent produces a guaranteed mainnet allocation at a fixed rate. Allocation scoring, prizes, anti-sybil rules, caps, snapshots, and exact settlement mechanics remain unspecified.

## 3. Existing evidence inventory

Preserve one coherent contributor identity rather than fragmenting evidence:

- Stable Technocore DID: `did:key:z6MkmdfTpA9HRsUUtvSQn1TdLDbvwzzo7rFYCWn6Ukp3uXVU`.
- Public project: `https://github.com/0xAJPanda/technocore-sentinel`.
- Public documentation, threat model, architecture diagrams, and Apache-2.0 license.
- Public Awesome Technocore contribution: `https://github.com/zunmax/awesome-technocore/pull/16`.
- Locally verified Sentinel result: 126 tests passing normally and under `python -O` at the recorded v0.2 release checkpoint.

The repository must continue to say that Sentinel makes no airdrop-eligibility claim. Public contribution evidence may support future discretionary prizes, but no official scoring formula currently assigns it a token value.

### Submission evidence still requiring manual confirmation

Do not mark an interest form complete from memory. For each official miner, validator, or creator/KOL form:

1. Open only a link reached from `https://flop.finance` or `https://x.com/flop_labs`.
2. Review every field and submit truthful information manually.
3. Save a private screenshot or confirmation identifier with the date.
4. Do not store email addresses, wallet secrets, browser cookies, or form answers in this public repository.
5. Never submit duplicate forms unless FLOP explicitly asks for an update.

## 4. Track strategy

### Track A — Agent participation (primary)

**Why:** It matches Sentinel's purpose, has a draft pool up to 1.2B FLOP, and rewards actual inference demand.[1]

**Build before testnet:**

1. Maintain the versioned Sentinel CLI/JSON contract and bounded reference consumer.
2. Demonstrate Claude, Codex, or Hermes calling Sentinel to obtain sanitized findings and coverage health.
3. Keep Technocore messages as untrusted data; the agent may summarize a Sentinel report but must not execute room content or follow discovered URLs.
4. Publish reproducible setup instructions, a threat model, and a real demo artifact.
5. Add public CI when GitHub workflow authorization is available; until then, continue stating local verification only.

**When the official testnet opens:**

1. Verify the announcement through at least two official FLOP-controlled surfaces.
2. Record the official chain/network identifier, client release checksum, faucet URL, eligibility terms, start/end block or time, and claim rules.
3. Use a new, testnet-only wallet or network identity created for FLOP; do not import a valuable wallet, Technocore signing key, SSH key, or browser identity.
4. Claim only free official faucet tokens.
5. Run useful, reproducible inference workloads tied to Sentinel development, testing, documentation, security evaluation, or public examples.
6. Enforce per-run, daily, and total test-token budgets even if tokens are free.
7. Record transaction/session IDs, model, task category, input/output hashes where safe, FLOP spent, result, and timestamp—never private prompts or secrets.
8. Stop if rewards require fake traffic, circular self-dealing, identity multiplication, undisclosed referrals, or unsafe wallet approvals.

**Agent unlock planning:** If a mainnet allocation is `A`, fully unlocking it under the current draft requires `3 × A` of subsequent inference spend.[1] Do not interpret this formula as a promise that testnet spend yields `A`, and do not commit real capital until final fees, lock rules, and market/liquidity risks are known.

### Track B — Miner participation (controlled pilot)

**Why:** The draft pool is also up to 1.2B FLOP and the provisional minimum is one GPU with at least 16GB VRAM.[1]

**Pre-testnet gate:**

- Use existing hardware only; buy no GPU, VPS, power equipment, or storage for draft economics.
- Confirm the exact GPU has at least 16GB VRAM and passes a sustained stability test.
- Measure wall power, thermals, throttling, inference throughput, and local electricity rate.
- Isolate the miner in a dedicated non-privileged environment with no access to wallets, SSH keys, Hermes/OpenClaw credentials, or home-directory secrets.
- Require signed/checksummed official binaries or reproducible source builds.
- Deny inbound internet exposure unless official networking documentation makes it necessary and a separate security review approves it.

**Testnet pilot:**

1. Start with one GPU and a small uptime window.
2. Confirm valid jobs and rewards through an independently readable testnet path.
3. Calculate cost per verified inference and stop if electricity, failure rate, or hardware stress is unreasonable.
4. Expand only after seven stable days and published scoring rules.
5. Keep an append-only private operations log with job/session identifiers and no secrets.

### Track C — Ecosystem/creator contribution (continue, no entitlement claim)

- Ship the Sentinel CLI/JSON agent workflows and a reproducible demo.
- Maintain the Awesome Technocore PR and respond to factual review feedback.
- Publish technical material explaining safe consumption of hostile agent-room data.
- Report reproducible bugs privately before public disclosure when security-sensitive.
- Avoid repetitive posts, low-effort room messages, manufactured engagement, or claims of endorsement.

The draft reserves part of the airdrop for ecosystem growth and mentions prizes, but it publishes no formula guaranteeing a reward for GitHub work, posts, forms, or Technocore messages.[1]

### Track D — Validator participation (defer)

The draft recommends 8+ CPU cores, 64GB RAM, 2TB NVMe, and redundant 1Gbps connectivity, while limiting the active set to 1,000 and evaluating uptime, block production, accuracy, and latency.[1] Validator allocations are bonded as launch stake and exposed to slashing rather than arriving as liquid rewards.[1]

Do not pursue this track until:

- final requirements and slashing rules are published;
- a live host audit proves capacity and redundancy;
- a failure/recovery runbook exists;
- operations will not destabilize existing services;
- the user explicitly accepts the stake and availability risk.

## 5. Evidence ledger

Create a private, backed-up CSV or SQLite ledger outside the Git repository with:

- `track`: agent, miner, validator, ecosystem;
- `official_network` and chain identifier;
- `account_or_address`: public identifier only;
- `session_or_tx_id`;
- `timestamp_utc`;
- `activity_type`;
- `faucet_received` and `test_flop_spent`;
- `verified_compute` or validation metrics;
- `artifact_url` or local evidence hash;
- `official_rule_version`;
- `notes` with no secrets.

Every entry must link to a real independently verifiable event. Never fabricate traffic or backfill unsupported estimates.

## 6. Go/no-go gates

| Gate | Proceed only when | Stop when |
| --- | --- | --- |
| Official launch | Two official FLOP-controlled sources agree | Link is third-party, shortened, or contradictory |
| Software supply chain | Source/release/checksum is verifiable | Binary is unsigned, replaced, or asks to disable security |
| Wallet | Dedicated empty testnet identity; official chain known | Valuable wallet, seed import, unlimited approval, or unclear chain |
| Faucet | Official and free | Payment, deposit, bridging, or private-key request |
| Agent spend | Useful tasks, capped budget, recorded sessions | Wash activity, circular spend, runaway loops, or unclear fees |
| Miner | Existing hardware, stable thermals, measured cost | Instability, unsafe power/temperature, or negative economics |
| Validator | Final specs and audited dedicated capacity | Draft-only requirements, insufficient redundancy, or slashing ambiguity |
| Claim | Official contract/address and dry-run simulation | Urgent DMs, unofficial forms, blind signatures, or broad approvals |

## 7. Milestones

### M0 — Now

- [ ] Verify and privately record any already-submitted official interest forms.
- [ ] Publish Sentinel's CLI/JSON agent contract and workflows with local protocol tests and a real demo.
- [ ] Keep the official-source monitor active; alert only on material changes.
- [ ] Prepare an isolated testnet wallet procedure, but do not generate or fund it yet.
- [ ] Inventory one 16GB+ GPU candidate without changing host configuration.

### M1 — Official testnet documentation published

- [ ] Diff final rules against this plan.
- [ ] Verify client source/releases, chain identity, faucet, eligibility, and anti-sybil terms.
- [ ] Perform a security and resource audit.
- [ ] Create the dedicated testnet identity and evidence ledger.

### M2 — First seven testnet days

- [ ] Run low-volume Sentinel-related agent inference.
- [ ] Run one-GPU miner pilot if the hardware gate passes.
- [ ] Reconcile every recorded event through the normal network read path.
- [ ] Publish a factual participation report without wallet secrets or reward projections.

### M3 — Remaining testnet

- [ ] Scale only the track with verified useful output and acceptable cost.
- [ ] Maintain uptime and evidence quality; do not chase vanity transaction counts.
- [ ] Re-evaluate rules weekly and after every official release.

### M4 — Mainnet/claim

- [ ] Verify final allocation and unlock terms independently.
- [ ] Simulate or dry-run any claim transaction.
- [ ] Require explicit user authorization before signing, claiming, staking, approving, bridging, or spending.
- [ ] Keep any mainnet FLOP isolated until contract, liquidity, tax, and custody risks are understood.

## 8. Success criteria

The plan succeeds if we have:

1. One public, useful agentic-workflow integration with reproducible evidence.
2. One coherent identity and honest activity ledger.
3. Useful testnet inference rather than manufactured volume.
4. A measured one-GPU pilot only if economically and operationally safe.
5. No leaked credentials, valuable-wallet exposure, unauthorized transactions, duplicate claims, or unsupported reward promises.

It does **not** define success as receiving a particular allocation; FLOP controls eligibility and the official rules are unfinished.

## Sources

[1] https://flop.finance/teaser — FLOP teaser and draft network economics
[2] https://x.com/CryptoTeluguO/status/2092649224739733541 — CryptoTelugu third-party tokenomics summary
