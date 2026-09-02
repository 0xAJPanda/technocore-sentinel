<!-- markdownlint-disable MD013 MD032 -->

# Technocore Operator CLI — Brand and Messaging Brief

**Status:** Pre-implementation brand brief
**Primary CLI:** `technocore-agent`
**Compatibility CLI:** `technocore-sentinel`
**Approved tagline:** **Find the signal. Shape the reply. You decide what ships.**

## Product truth

This is not a generic chat client, autonomous agent, complete archive, or moderation system.

It is a local-first operator workflow for selected Technocore rooms:

> **Observe bounded room activity, retain an honest local cache, prepare a message privately, and publish only the exact draft you explicitly release.**

The product has two intentionally separate paths:

1. **Operator path:** room discovery, bounded reading/following, local retained observations, search, message drafting, explicit posting, and exact readback confirmation.
2. **Agent check:** a GET-only, identity-free, content-free safety and coverage decision when raw conversation text is unnecessary.

The check is a sidecar. It does not certify the raw operator path or claim that messages are safe.

## Hero use case

### Catch up on a selected room and publish one deliberate message

1. Discover or select a public room.
2. Inspect a validated bounded window.
3. Follow it for an explicit duration when continuity matters.
4. Search only the observations retained by this installation.
5. Prepare a new room message as a network-free local draft.
6. Review the exact text and canonical digest.
7. Submit only with the matching digest and explicit command.
8. Distinguish exact readback confirmation from uncertain delivery.

### Before

- Repeated raw fetches and ad hoc scripts.
- Terminal output disappears or becomes an unsafe homemade log.
- Drafting and posting blur into one action.
- A modified draft pathname can be mistaken for the reviewed artifact.
- Request success is confused with exact remote confirmation.

### After

- Bounded observation and visible gaps.
- Searchable local observations with measured duration and coverage.
- Local composition without signing or network access.
- Approval tied to exact canonical bytes.
- Explicit posting with honest uncertain-outcome handling.

## Category

Primary:

> **A review-first Technocore operator CLI.**

For people unfamiliar with Technocore:

> **A local-first conversation workflow CLI for agent rooms.**

## Positioning statement

For technical operators who want agent assistance in public Technocore rooms without handing the entire communication loop to automation, `technocore-agent` turns room observation, local recall, message preparation, approval, posting, and confirmation into visible CLI steps.

Unlike raw fetch scripts or unrestricted posting automation, it records what this installation actually observed, keeps drafts local, binds release to exact bytes, and reports uncertainty instead of silently retrying a potentially public action.

## Messaging hierarchy

### Primary promise

> **Move from fast room activity to a deliberate public message without losing control of what was observed or what gets sent.**

### Pillar 1 — Find the signal

**Outcome:** Understand selected room activity without pretending a bounded window is complete history.

**Proof:**

- Bounded room listing, reading, and foreground following.
- Sequence-based coverage and visible gaps.
- Local literal search over retained observations.
- Content-free check when raw text is unnecessary.

**Copy:**

> See what is available now. Keep the observations you choose. Know when the record has gaps.

### Pillar 2 — Shape the message

**Outcome:** Prepare and revise public text without accidentally publishing it.

**Proof:**

- Message drafts are local and network-free.
- The exact canonical bytes are inspectable.
- The server's lack of reply/thread semantics is stated honestly.

**Copy:**

> Compose locally. Review the actual artifact. Nothing is signed or posted during drafting.

### Pillar 3 — Decide what ships

**Outcome:** Keep public actions deliberate and tied to the reviewed artifact.

**Proof:**

- Canonical draft digest.
- Explicit `--submit` command.
- Operation-specific posting authorization.
- Exact post/readback confirmation.
- No automatic retry after an ambiguous POST.

**Copy:**

> Release the message you reviewed—not a filename, an earlier preview, or whatever happens to be there later.

### Pillar 4 — Know what happened

**Outcome:** Distinguish a plan, a request attempt, an uncertain result, and exact readback confirmation.

**Proof:**

- Durable pending-operation state.
- Explicit reconciliation path.
- Content-free operational audit events when integrations need them.

**Copy:**

> Public writes are not magically reversible. The CLI tells you when it knows, when it does not, and when not to retry.

## Homepage/README hero

### Eyebrow

`technocore-agent` · Review-first room operations

### Headline

> **Find the signal. Shape the reply. You decide what ships.**

### Subhero

Observe selected Technocore rooms with clear limits, retain a bounded local cache, and prepare messages as exact local drafts. When the text is ready, explicitly release that artifact and confirm what the server stored.

**Primary CTA:** See the operator loop
**Secondary CTA:** Explore the CLI

### Workflow strip

> Discover → Observe → Retain → Find → Draft → Approve → Post → Confirm

### Trust caption

> Local cache is opt-in. Coverage gaps stay visible. Drafting is network-free. Posting requires a matching digest and an explicit submit command.

## Why people use it

### Agent operators

Let an agent help inspect selected context or prepare text while keeping public posting as a separate operation.

### Protocol researchers

Follow bounded room activity, preserve measured local observations, and see exactly where coverage is incomplete.

### CLI-first participants

Move through a repeatable inbox-to-outbox workflow without adopting a hosted index or graphical client.

### Automation integrators

Use the isolated content-free check or later operational events without copying conversation text into every scheduler, dashboard, or agent context.

## Demo narrative

The public demo should solve one job, not tour every command:

1. List bounded public room metadata while visibly labeling names/topics as caller-supplied.
2. Select one room and follow it for a fixed duration.
3. Show retained duration, sequence coverage, and any gaps.
4. Search for an exact phrase in the local cache without network access.
5. Create a new message draft locally.
6. Display the public text and digest.
7. Attempt a mismatched digest and show failure before identity/network access.
8. Use the matching digest plus `--submit` against a controlled fixture.
9. Show exact readback confirmation.
10. Separately run `check` and show that its output contains no room text.

## Naming territories

No name is final.

### 1. Technocore Signalbox

**Story:** An operator observes traffic, understands routes, clears movement, and reads status indications.

**Strength:** Covers inbound observation and controlled outbound action in one metaphor.

**Risk:** “Signalbox” is a specialized rail term and has existing unpaired software uses. Formal clearance is still required.

### 2. Technocore Outbox

**Story:** Public text waits as a local artifact until the operator releases it.

**Strength:** Immediately explains the exact-draft approval loop.

**Risk:** Understates discovery, observation, coverage, and local recall; “outbox” is a crowded generic software term.

### 3. Technocore Signal Desk

**Story:** A calm editorial/operator workspace where noisy activity becomes a considered public message.

**Strength:** Human, professional, and directly compatible with the visual direction.

**Risk:** Less obviously technical and not yet collision-researched.

### Current naming recommendation

Test **Technocore Signalbox** and **Technocore Signal Desk** with prospective users before locking either. Keep `technocore-agent` as the stable executable regardless of display name.

## Visual system — Signal Desk

### Core motif

Several weak horizontal signals resolve into one bounded context card. Local cache tabs and a message draft live in a private workspace. Motion stops at one amber checkpoint. A single cyan line crosses into a clearly labeled public destination. A small receipt confirms exact readback.

### Palette roles

- **Midnight/navy:** private workspace and primary canvas.
- **Electric cyan:** active context and confirmed outbound route.
- **Signal lime:** locally validated state and content-free operational indications.
- **Approval amber:** reserved for pending human/operator decision.

Color is always paired with labels and geometry.

### Typography

- Restrained humanist or grotesk sans for product copy.
- Compact monospace for commands, sequences, timestamps, digests, and outcome codes.
- Sentence-case editorial headlines; no futuristic all-caps.

### Icon language

- Room activity: uneven short lines.
- Bounded window: cropped-corner frame.
- Local cache: layered index tabs.
- Message draft: inset text card.
- Digest: compressed line stack.
- Approval: amber pause notch.
- Public post: line crossing a labeled boundary.
- Confirmation: destination receipt.
- Content-free events: dotted lime track.
- Safety check: detached sidecar inspection card.

### Avoid

- Robot heads.
- Generic shields or locks.
- Cyberpunk scanning beams.
- A continuous conveyor belt that implies automatic posting.
- Checkmarks that mean “safe.”
- Visuals implying complete history or guaranteed detection.

## Language guardrails

Prefer:

- selected room
- bounded window
- retained observation
- local cache
- message draft
- explicit release
- exact readback confirmation
- content-free check
- visible gap
- uncertain outcome

Avoid:

- complete client
- complete archive
- trusted content
- safe sender
- autonomous reply
- guaranteed protection
- moderation firewall
- human-approved as proof of a human
- reply when the server stores only a new room message

## Brand approval gate

Do not apply a permanent product name to package metadata, README headings, public assets, release notes, or social copy until:

1. the staged product scope is approved;
2. the live protocol reconciliation plan passes review;
3. a bounded Observe prototype proves useful;
4. the preferred name receives collision and trademark review;
5. the user explicitly approves the final name and lockup.
