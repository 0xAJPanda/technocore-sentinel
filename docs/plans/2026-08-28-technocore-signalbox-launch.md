<!-- markdownlint-disable MD013 MD032 MD034 MD052 -->

# Technocore Signalbox Verified Launch Plan

> **For Hermes:** Use `subagent-driven-development` for product implementation and two-stage review. Use `public-repository-release` for GitHub publication. Treat every GitHub/X write as a separate approval-gated operation with exact readback.

**Goal:** Launch a fully tested, visually distinctive Technocore Signalbox repository and an evidence-led X campaign that earns relevant attention from agent operators, FLOP Labs, and Arthur Hayes without spamming, overstating readiness, or implying endorsement.

**Architecture:** Build and verify the product first; make the public GitHub repository the source of proof; then publish one primary visual launch thread from `@0xAJPanda` and two context-specific replies. The launch narrative owns the operator accountability loop—room noise → bounded context → local draft → exact approval → confirmed public result—rather than competing with existing live-traffic visualizers.

**Launch identity:**

- Product: **Technocore Signalbox**
- Category: **Local-first operator station for Technocore**
- Primary interface: branded TUI
- Automation interface: composable `technocore-agent` CLI and closed JSON
- Compatibility interface: `technocore-sentinel`
- Tagline: **Find the signal. Shape the reply. You decide what ships.**
- Owner/account: `0xAJPanda` / `@0xAJPanda`

**No-launch rule:** Do not announce, tag, reply, DM, quote-post, merge, rename the repository, create a release, publish to PyPI, or perform a Technocore write until the applicable gate explicitly permits it.

---

## 1. Launch thesis

### The operator problem

Fast agent rooms outrun human attention. Operators lose context, then have to assemble raw HTTP calls, local state, signing, approval, and readback themselves.

### The product transformation

Signalbox turns bounded room activity into searchable local context, a reviewable message, an explicit release decision, and a dependable operational record.

### One-sentence use case

> **Technocore Signalbox helps an operator catch up on a fast-moving room, recover the context that matters, prepare a response locally, and decide exactly what becomes public.**

### Short launch hook

> **From room noise to an accountable response—without assembling the workflow yourself.**

### Differentiation

A community Technocore Live Workstream already visualizes real room activity and agent identities.[5] Signalbox must not market itself as another live visualizer. Its distinct visual and functional story is the operator journey from observation through approval and confirmation.

Awesome Technocore already lists clients, DID tools, monitoring projects, dashboards, and experiments.[6] Signalbox should therefore make one defensible claim: it combines a human operator TUI with a shared CLI/JSON foundation and an explicit accountable-response workflow.

---

## 2. Audiences

### Primary

Agent operators who supervise selected Technocore rooms and need to recover context before responding.

### Secondary

- Hermes, OpenClaw, Codex, Claude Code, cron, and dashboard integrators.
- Technocore builders who need closed machine-readable commands rather than another bespoke script.
- FLOP/Technocore community members evaluating useful agent participation.

### Attention targets

- `@flop_labs`, verified from its public X profile.[3]
- Arthur Hayes at `@CryptoHayes`, verified from his public X profile.[4]

Attention is earned through relevance. The campaign must not imply that either account requested, reviewed, endorsed, funded, audited, or rewarded Signalbox.

---

## 3. Current publication truth

The public repository currently remains `0xAJPanda/technocore-sentinel`, with the older read-only Sentinel identity and no public Signalbox release.[1]

PR #1 contains only the earlier CLI/JSON contract commit and has no public status checks.[2]

The local worktree contains newer uncommitted monitor, workflow, strategy, and visual work. Expanded Signalbox code and TUI do not yet exist.

Technocore's live OpenAPI currently reports version 0.10.0 and differs materially from assumptions in the paused expansion plan.[8] Protocol reconciliation is a launch blocker, not a post-launch cleanup item.

---

## 4. Hard launch gates

Every gate is sequential. A later gate cannot compensate for a failed earlier gate.

### Gate A — Product definition

- [ ] Confirm **Technocore Signalbox** as the public display name.
- [ ] Confirm TUI-as-hero plus CLI/JSON-as-foundation.
- [ ] Freeze the one-sentence use case and tagline.
- [ ] Record explicit non-goals: not a complete archive, autonomous bot, moderation system, security guarantee, or FLOP Labs product.

**Failure behavior:** Keep strategy and visual files under `docs/plans`; do not rename metadata or public README.

### Gate B — Protocol reconciliation

- [ ] Freeze exact Technocore 0.10.0 read, discovery, long-poll, write, acknowledgement, and readback contracts from authoritative documents.
- [ ] Add endpoint-specific mocked fixtures.
- [ ] Reconcile the current client's older write-response assumptions.
- [ ] Preserve the existing monitor contract byte-for-byte.
- [ ] Permit no live write during discovery or routine tests.
- [ ] If one live write is required for final compatibility proof, require separate authorization for its exact public text and identity.

**Failure behavior:** No Participate-stage implementation and no launch date.

### Gate C — Replacement implementation plan

- [ ] Replace the paused Relay plan with staged Observe, Participate, and Connect tasks.
- [ ] Define exact output schemas per command and format.
- [ ] Define all uncertain public-write outcomes and prohibit blind retries.
- [ ] Define TUI boundaries so it calls shared services rather than duplicating CLI behavior.
- [ ] Receive independent review with zero critical and zero important findings.

**Failure behavior:** No feature implementation.

### Gate D — Product implementation

#### Observe

- [ ] Bounded room discovery.
- [ ] Bounded read and foreground follow.
- [ ] Honest baseline, gap, and coverage reporting.
- [ ] Explicit opt-in bounded local cache.
- [ ] Deterministic local search.
- [ ] Existing content-free `check` remains isolated.

#### Participate

- [ ] Network-free drafts.
- [ ] Exact canonical draft digest.
- [ ] Explicit release authorization.
- [ ] Endpoint-specific write acknowledgement.
- [ ] Independent readback.
- [ ] Durable, content-free operational outcome record.
- [ ] No automatic retry after an uncertain write.

#### Interfaces

- [ ] `technocore-agent` exposes closed CLI/JSON contracts.
- [ ] `technocore-sentinel` remains compatible.
- [ ] The Signalbox TUI uses the same shared services.
- [ ] TUI screenshots can be reproduced from deterministic fixtures.

### Gate E — Verification

- [ ] Full frozen dependency sync.
- [ ] All tests pass normally.
- [ ] All tests pass under `python3 -O`.
- [ ] Compilation passes.
- [ ] Markdown lint passes.
- [ ] SVG XML parsing, static-asset inspection, and rendered visual review pass.
- [ ] `git diff --check` passes.
- [ ] Independent specification review passes.
- [ ] Independent security/quality review passes.
- [ ] Integration review passes.
- [ ] No test performs an unintended live Technocore write.

The README and launch copy must use the actual final count as `[VERIFIED_TEST_COUNT]`; never preserve a stale number.

### Gate F — Package and secret audit

- [ ] Build exact wheel and sdist for the intended version.
- [ ] Audit exact allowlists and forbidden paths.
- [ ] Install the exact wheel in a fresh environment.
- [ ] Smoke-test both executables, TUI entry point, closed contracts, read-only fixtures, draft planning, and failure boundaries.
- [ ] Audit the tracked tree and every reachable Git blob for secret categories without printing candidate values.
- [ ] Confirm identities, keys, nonces, receipts, caches, databases, drafts, events, screenshots with private data, and local paths are absent.
- [ ] Keep `.github/` excluded until its workflow is separately reviewed and authorized.

### Gate G — GitHub release candidate

- [ ] README begins with use case, hero visual, thirty-second demo, and one install path.
- [ ] SECURITY accurately describes current behavior and limitations.
- [ ] License and package metadata agree.
- [ ] CI workflow has least-privilege permissions and pinned trusted actions.
- [ ] GitHub authentication has the effective workflow capability before pushing `.github/workflows/ci.yml`.
- [ ] Decide whether to rename the repository to `technocore-signalbox`; perform that rename only after explicit authorization.
- [ ] Decide whether package/import names remain compatibility identities for the first Signalbox release.

### Gate H — Public readback

After every authorized GitHub write:

- [ ] Compare local, remote branch, and public SHA.
- [ ] Enumerate the public tree.
- [ ] Read back README, license, metadata, representative source, tests, and workflow.
- [ ] Byte-compare every public visual asset with the reviewed local asset.
- [ ] Verify each asset's public media type and rendering.
- [ ] Verify CI reaches a completed successful conclusion.
- [ ] Verify PR and release URLs.
- [ ] Call Awesome Technocore a **submission** until its maintainers merge it.

### Gate I — X publication

- [ ] Use the normal authenticated X website in an operator-controlled browser; do not export, import, or persist its session cookies in the project.
- [ ] Prepare the exact final copy, target URLs, media, and alt text outside X.
- [ ] Let the operator upload media, review the rendered composer, and perform the final publish click manually.
- [ ] In the rendered composer, verify the active account, exact thread order, media placement/crop, alt text, link cards, audience, and reply settings.
- [ ] Re-fetch the exact `@flop_labs` and `@CryptoHayes` profiles/posts on launch day.
- [ ] Confirm final main post, thread replies, contextual reply targets, alt text, and media with the user.
- [ ] Post each externally visible item as its own action.
- [ ] Read back every post URL, exact text, media attachment, account, reply target, and thread linkage before proceeding.
- [ ] Do not DM, repeatedly tag, or cross-post duplicate copy.

### X transport decision — no developer API required

Use **draft automation plus manual browser publication** for the launch. X's April 2026 automation rules explicitly prohibit non-API website scripting and warn that it may result in permanent account suspension.[9] Therefore, do not use XActions, Puppeteer, Playwright, a browser-console script, or an MCP write tool to click X's final Post button on the primary account.

XActions is technically capable of posting without developer API credentials, but it does so by acting through a live X web session. Its own security policy says the stored cookies are a live login and acknowledges enforcement risk.[10] The inspected local MCP posting path also treats a successful button click as success without returning a post URL or independently reading the post back, while its approval record is marked executed only after the external action. That is insufficient for the launch's exact-readback and duplicate-prevention requirements.

The approved no-API workflow is:

1. Generate and checksum the final copy/media packet locally.
2. Open the normal X composer or relevant reply target in the operator's existing browser.
3. Copy the approved text and manually attach the reviewed media and alt text.
4. Compare the rendered composer with the approved packet.
5. The operator performs the final click.
6. Capture the resulting public URL and independently read back exact text, reply target, and media before continuing.

This avoids X developer API setup without transferring reusable account cookies to an automation toolkit. If official API access is configured later, `xurl` may replace the manual transport after a separate approval and verification exercise.

---

## 5. GitHub presentation

### Above the fold

1. Signalbox mark and name.
2. Tagline.
3. One-sentence use case.
4. Short TUI demo.
5. Install/run command.
6. Honest status badge: only verified CI and release status.

### Recommended README sequence

1. **The problem:** fast rooms outrun attention.
2. **The operator loop:** Discover → Observe → Retain → Find → Shape → Approve → Confirm.
3. **Thirty-second demo.**
4. **Why Signalbox is different.**
5. **TUI for people. CLI/JSON for agents.**
6. **Five-minute quickstart.**
7. **Verified bounds and limitations.**
8. **Content-free check path.**
9. **Architecture and state model.**
10. **Hermes/OpenClaw/Codex/Claude Code examples.**
11. **Security and public-write warning.**
12. **Development and verification.**
13. **Independent-project disclaimer.**

### Repository proof block

Use only read-back facts:

```text
✓ [VERIFIED_TEST_COUNT] tests passed normally
✓ [VERIFIED_TEST_COUNT] tests passed under optimized Python
✓ Exact wheel and sdist audited
✓ Fresh-wheel smoke tests passed
✓ GitHub Actions: [CI_URL]
✓ No live writes in routine tests
```

Do not claim “secure,” “production-ready,” “official,” “complete history,” or “FLOP-qualified.”

---

## 6. Launch imagery

The FLOP design system assigns explicit jobs to its palette, including Electric Green for successful product states.[7] Signalbox may harmonize with those conventions, but must remain visibly independent and must not use the FLOP logo as if Signalbox were official.

### Asset 1 — Hero operator loop

**Path:** `docs/assets/signalbox-operator-loop.svg`
**Export:** 1600 × 900 PNG/WebP

Visual sequence:

```text
ROOM NOISE → BOUNDED CONTEXT → LOCAL MESSAGE → APPROVAL GATE → CONFIRMED PUBLIC RESULT
```

Requirements:

- Midnight/navy working surface.
- Cyan for observation and routing.
- Electric green only for confirmed success/readback.
- Amber as Signalbox's distinctive human approval checkpoint.
- Separate dotted content-free operations track.
- Detached `check` sidecar.
- No robot head, shield, firewall, wallet, price chart, or token imagery.

### Asset 2 — TUI hero screenshot

**Path:** `docs/assets/signalbox-tui-hero.png`

Show:

- selected room list;
- bounded coverage indicator;
- retained-context/search pane;
- local draft pane;
- unmistakable approval checkpoint;
- confirmed outcome panel;
- no real private key, local path, sender identity, or raw secret.

Use deterministic fixtures so the screenshot is reproducible and safe.

### Asset 3 — Thirty-second demo

**Paths:**

- `docs/assets/signalbox-demo.mp4`
- `docs/assets/signalbox-demo.webp`

Storyboard:

1. Open Signalbox TUI.
2. Select a room.
3. Show bounded activity and a visible coverage limit.
4. Search retained observations.
5. Prepare a local message.
6. Show exact digest and approval pause.
7. Use a labeled fixture or separately authorized test identity for confirmation.
8. Finish on tagline and GitHub URL.

No fake typing, invented adoption numbers, or unlabeled simulated network result.

### Asset 4 — Human/agent interface diagram

**Path:** `docs/assets/signalbox-interfaces.svg`

Show one shared core feeding:

- operator TUI;
- CLI/JSON;
- isolated content-free check;
- optional content-free events.

### Asset 5 — X launch card

**Path:** `docs/assets/signalbox-launch-card.png`
**Size:** 1600 × 900

Copy:

```text
TECHNOCORE SIGNALBOX
From room noise to an accountable response.
TUI for people · CLI/JSON for agents
```

The launch card supports the main post; the demo video should be the primary media when it is clear and legible.

### Asset 6 — Proof card

**Path:** `docs/assets/signalbox-proof.png`

Include only final read-back facts:

- final test count;
- normal + optimized runs;
- CI success;
- package audit;
- fixed-origin statement;
- routine tests make no live writes.

---

## 7. X campaign structure

### Principle

One strong launch thread plus context-specific replies is better than repeatedly tagging large accounts. The project should be the answer to a real operator problem, not an airdrop solicitation.

### Main post from `@0xAJPanda`

Attach the thirty-second TUI demo.

```text
Agent rooms move faster than operators can follow.

I built Technocore Signalbox: a local-first operator station that turns bounded room activity into searchable context, a reviewable message, and a confirmed public result.

TUI for people. CLI/JSON for agents.

Open source: [FINAL_GITHUB_URL]
```

### Thread reply 1 — The workflow

Attach the operator-loop graphic.

```text
The workflow is simple:

Discover → Observe → Retain → Find → Shape → Approve → Confirm

Nothing becomes public until the exact local message reaches the approval checkpoint.
```

### Thread reply 2 — Why it exists

```text
Signalbox replaces the pile of one-off API calls, cursor files, signing scripts, and readback checks an operator would otherwise have to assemble.

It is built for one recurring job: catch up on a noisy room and send one deliberate response with enough context and control.
```

### Thread reply 3 — Agent integrations

Attach the interface diagram.

```text
The TUI is the human control surface.

The same core is available through closed CLI/JSON commands for Hermes, OpenClaw, Codex, Claude Code, cron, and dashboards.

The content-free check remains isolated for workflows that need a decision, not room text.
```

### Thread reply 4 — Proof and limits

Attach the proof card.

```text
Verified before launch:

• [VERIFIED_TEST_COUNT] tests normally and under optimized Python
• clean wheel/sdist audit
• fresh-install smoke tests
• passing CI: [CI_URL]

Bounded observations are not complete history. Signalbox is independent and is not a FLOP Labs product or endorsement.
```

### Contextual reply to FLOP Labs

Only reply after re-fetching the exact relevant FLOP Labs post and verifying that the visual request remains the correct context. Attach the operator-loop graphic, not the generic launch card.

```text
Built a different kind of Technocore visual: the operator path from room noise to bounded context, a local message, an explicit approval checkpoint, and a confirmed result.

Technocore Signalbox is now fully tested and open source:
[FINAL_GITHUB_URL]
```

Do not say “you asked, so I built it” unless the exact source post proves that wording.

### Contextual reply to Arthur Hayes

Only reply to the exact useful-participation/DID context after re-fetching it. Attach the TUI demo or proof card.

```text
Useful participation was the bar for this build.

Technocore Signalbox helps an operator keep up with fast agent rooms, recover bounded context, prepare an exact local message, and confirm what became public.

Independent, tested, and open source:
[FINAL_GITHUB_URL]
```

Do not ask for an airdrop, imply qualification, or imply Arthur/FLOP reviewed the project.

---

## 8. Launch-day runbook

Each numbered item is a separate operation with readback before the next.

1. Re-run local verification from the exact release candidate.
2. Confirm clean intended diff and exact artifact hashes.
3. Push the authorized branch.
4. Read back branch SHA and public files.
5. Confirm CI completes successfully.
6. Merge PR only with explicit authorization.
7. Read back default branch and visuals.
8. Rename repository only if separately approved; verify redirects and remotes.
9. Create GitHub release only if separately approved; verify tag and assets.
10. Update or supersede the Awesome Technocore submission; verify its public diff.
11. Open the normal X website while signed in as `@0xAJPanda`; do not export the session.
12. Manually attach the reviewed demo media and alt text, then compare the rendered composer with the final approval packet.
13. The operator performs the final publish click; read back URL/text/media.
14. Publish thread replies one at a time; read each back.
15. Publish the FLOP Labs contextual reply; read it back.
16. Publish the Arthur contextual reply; read it back.
17. Pin the main launch post if desired and supported.
18. Save post URLs and launch metrics outside the source package.

No step may be reported complete from a successful command alone; the exact external target must be read back.

---

## 9. Follow-up without spam

### First day

- Answer substantive questions.
- Thank people who test it.
- Convert bug reports into GitHub issues.
- Do not tag FLOP Labs or Arthur again.

### Days two to three

Publish one useful follow-up only if there is new evidence:

- a short technical walkthrough;
- a real external integration;
- a meaningful bug fix;
- an operator workflow example.

### First week

Report honestly:

- repository views/clones/stars;
- successful independent installs;
- issues opened and resolved;
- external integrations;
- protocol incompatibilities discovered;
- next milestone.

Do not manufacture scarcity, adoption, or testimonials.

### If the launch is quiet

Do not repeat the same tagged post. Improve the demo, publish a concrete integration guide, or contribute a useful upstream/awesome-technocore update.

### If a defect appears

Pause promotion. Document the affected versions, fix with a regression test, rerun all gates, publish a factual correction, and resume only after verification.

---

## 10. Success criteria

The launch succeeds when:

1. A new operator can understand the use case in under one minute from GitHub.
2. A technical operator can reproduce the quickstart without private guidance.
3. The TUI demo makes the Observe → Approve → Confirm story obvious without narration.
4. Agent integrators can find closed CLI/JSON examples immediately.
5. Public claims match verified code, artifacts, CI, and protocol behavior.
6. At least one independent person runs the project and provides concrete feedback.
7. Attention from FLOP Labs or Arthur, if it happens, comes from useful evidence rather than repeated tagging.

Stars and impressions are useful metrics, not proof of product value.

---

## 11. Explicitly prohibited launch behavior

- No announcement before GitHub readback and successful CI.
- No claim that Signalbox is official, endorsed, audited, production-safe, or airdrop-qualified.
- No repeated mentions of `@flop_labs` or `@CryptoHayes`.
- No unsolicited DM campaign.
- No fabricated TUI data presented as live.
- No private room data, keys, paths, identities, signatures, or receipts in screenshots.
- No live Technocore write merely to make a better video without separate approval.
- No wallet or token imagery that confuses the operator product with financial promotion.
- No non-API script or automation tool clicking X's final Post button.
- No importing browser cookies into XActions or copying session tokens into project, chat, shell history, or MCP configuration.
- No merge, tag, GitHub release, PyPI publication, or X post without the corresponding explicit authorization.

---

## 12. Final approval packet

Before any launch write, present one compact packet to the user containing:

1. exact release commit SHA;
2. test and artifact results;
3. CI URL and conclusion;
4. final GitHub URL;
5. README hero screenshot;
6. final demo video;
7. all X post/reply text;
8. exact media attached to each post;
9. exact target post URLs for contextual replies;
10. explicit list of remaining limitations.

The user approves or edits that packet. Approval of one item does not authorize unrelated posts or releases.

## Sources

[1] https://github.com/0xAJPanda/technocore-sentinel — Current public Technocore Sentinel repository
[2] https://github.com/0xAJPanda/technocore-sentinel/pull/1 — Open feature PR #1
[3] https://x.com/flop_labs — Flop Labs on X
[4] https://x.com/CryptoHayes — Arthur Hayes on X
[5] https://github.com/UfukNode/Technocore-Live-Workstream — Technocore Live Workstream
[6] https://github.com/zunmax/awesome-technocore — Awesome Technocore
[7] https://flop.finance/brand — FLOP brand guidelines
[8] https://technocore.chat/openapi.json — Technocore Chat OpenAPI 0.10.0
[9] https://help.x.com/en/rules-and-policies/x-automation — X automation rules, updated April 2026
[10] https://github.com/nirholas/XActions/blob/dfce129cad8d2ccc946915c8e8937e798bb8a278/SECURITY.md — XActions security policy at the inspected revision
