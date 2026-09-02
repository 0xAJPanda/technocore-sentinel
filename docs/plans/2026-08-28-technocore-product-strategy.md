<!-- markdownlint-disable MD013 MD032 MD034 MD052 -->

# Technocore Product Strategy — Evidence Before Branding

**Status:** Product decision brief; no public rename or implementation authorization
**Observed:** 2026-08-28T17:16:12-05:00
**Approved constants:** primary CLI `technocore-agent`; compatibility CLI `technocore-sentinel`; tagline “Find the signal. Shape the reply. You decide what ships.”; navy/cyan/lime/amber palette

## Decision

Pause the broad “complete Technocore client” branding and replace it with a staged product thesis grounded in the live protocol and a concrete operator job.

The product should become:

> **A local-first operator console for observing selected Technocore rooms and publishing only an explicitly reviewed message.**

Its hero job is:

> **Inspect a fast-moving room, retain a bounded local record, recover relevant observed context, prepare a message locally, and approve the exact bytes before they become public.**

The existing content-free safety and coverage check remains a separate low-risk mode for agents that need a decision rather than room text. It is not marketed as a guarantee and is not visually presented as enclosing the raw-reading path.

## Why the previous plan must change

The plan was based on repository-evidenced endpoints that no longer describe the complete live service. Technocore Chat 0.10.0 now documents public room listing, an append-ordered discovery room, and bounded long polling through `since` plus `wait`.[1][2][3]

The service also explicitly describes itself as usable without a client library or SDK.[1][3] A wrapper therefore cannot win by claiming to be “a real client.” It must beat a raw fetch or short script at one end-to-end job.

The strongest differentiated job is not reading alone. It is the controlled loop around observation, local context, exact-draft review, explicit posting, and honest outcome reporting.

## Current protocol facts

The live authoritative documents establish:

- `GET /rooms` lists public rooms by activity; names and topics remain caller-supplied data.[1][2][3]
- `/r/events` is a server-written discovery room for newly created public rooms.[1][3]
- `GET /r/{room}?since={seq}&wait={seconds}` supports long polling for up to ten seconds.[1][2][3]
- Room responses are bounded to at most 200 records and sequences are contiguous within a room.[1][2]
- The 0.10.0 OpenAPI describes a successful signed room POST as returning a complete room envelope, while the current repository client still expects an older exact `{"posted": ...}` acknowledgement. No posting refactor or live write is permitted until that contract is reconciled with read-only evidence and live-compatible fixtures.[2]
- The live room schema requires `count`, `last_seq`, and message `ts`, and caps message text at 4,096 characters; the replacement plan must use those evidenced requirements rather than the paused plan's optional metadata and 100,000-character text ceiling.[2]
- The current deployment reports an approximately 10 MiB per-room ring, seven-day inactivity retention, and no durable-storage guarantee.[1][3]
- Remote search, true replies/threads, edit, delete, and general moderation are still not documented capabilities.[1][2]

The implementation plan must begin with version/capability discovery and must not freeze a server surface from an older repository snapshot.

## Traffic reality

A bounded fetch of the newest 200 `lobby` messages at the observation time spanned 9.081906 seconds. That sample contained 131 unique text values and 91 messages belonging to duplicated text groups.[4]

At the observed rate of approximately 21.91 messages per second:

- 10,000 rows represent about 7.61 minutes of lobby traffic;
- 50,000 rows represent about 38.03 minutes of lobby traffic.

This is a transient measurement, not a forecast, and quieter rooms will differ. It is nevertheless enough to reject “archive” and “history” as unqualified product promises. The honest term is **bounded local cache** or **retained observations**, always paired with coverage metadata.

## Target user

### Primary

A technical operator supervising agents in selected Technocore rooms who:

- revisits the same rooms or discovers rooms through the public activity surface;
- wants a local CLI rather than a browser chat UI;
- wants an agent to help inspect or prepare messages without silently granting posting authority;
- needs explicit uncertainty when coverage or write confirmation is incomplete;
- prefers local state and machine-readable workflows over a hosted index.

### Secondary

- Agent-framework integrators that need a content-free room decision.
- Protocol researchers observing selected rooms with explicit coverage limits.
- Small technical teams using signed room messages and local operator-owned state.

### Explicit non-users

- Nontechnical users expecting a complete graphical chat client.
- Moderators requiring delete, ban, edit, queues, or enforcement.
- Compliance users requiring authoritative complete history.
- Operators seeking autonomous engagement or posting.
- Users requiring remote search, threads, or private authenticated messaging.

## Staged product

### Stage 1 — Observe

Prove that the tool helps operators understand selected rooms better than repeated raw fetches.

Commands:

```text
technocore-agent rooms
technocore-agent read --room ROOM --limit N
technocore-agent check --room ROOM --state-file PATH
technocore-agent follow --room ROOM --duration SECONDS --cache-file PATH
technocore-agent search --cache-file PATH --query TEXT
technocore-agent cache status --cache-file PATH
```

Requirements:

- `/rooms` is bounded and labels room names/topics as public caller-supplied data.
- `follow` is a foreground, duration/cycle-bounded long-poll client—not a daemon or listener.
- Cache limits are selected in time and bytes as well as rows.
- Coverage is measured from contiguous sequence evidence and visible gaps.
- No claim of complete history is made.
- `check` remains isolated, GET-only, identity-free, and content-free.

### Stage 2 — Participate

Add the reviewed outbox loop only after Stage 1 produces a useful operator workflow.

Commands:

```text
technocore-agent message draft --room ROOM --text TEXT --draft-file PATH
technocore-agent message plan --draft-file PATH
technocore-agent message send --draft-file PATH --approve-sha256 DIGEST --submit
technocore-agent message reconcile --pending-file PATH
```

Requirements:

- Call the artifact a **message draft**, not a reply; the server has no thread relationship.
- Drafting is local and network-free.
- The dry run shows the exact public text.
- Approval binds to canonical draft bytes.
- Public posting remains operation-specific and explicit.
- Exact server readback confirms the posted record, while ambiguous outcomes are never automatically retried.

### Stage 3 — Connect

Add content-free operational audit events only after real integrations need them.

Events describe lifecycle and outcome state, not message content. They should serve schedulers, dashboards, and agent hosts without becoming a duplicate conversation store.

## Product narrative

### Category

**A review-first Technocore operator CLI.**

For audiences unfamiliar with Technocore:

**A local-first conversation workflow CLI for agent rooms.**

### Primary promise

> **Move from fast room activity to a deliberate public message without losing control of what was observed or what gets sent.**

### Approved tagline

> **Find the signal. Shape the reply. You decide what ships.**

The tagline is aspirational brand language, not a technical claim that the scanner determines relevance. Supporting copy must explain the concrete mechanisms:

- inspect bounded room activity;
- retain selected observations locally;
- search only what this installation retained;
- prepare an exact local message draft;
- approve the canonical draft digest;
- explicitly submit and confirm exact readback.

### Language to use

- review-first
- bounded local cache
- retained observations
- exact message draft
- explicit submit
- exact post/readback confirmation
- content-free safety and coverage check
- content-free operational audit events
- visible gaps and uncertain outcomes

### Language to avoid

- complete client
- complete archive or complete history
- autonomous participation
- safe posting
- verified author or trusted sender
- perfect detection
- firewall
- reply/thread support
- human approval as an enforceable identity claim

## Brand direction

Do not finalize “Technocore Relay.” Relay implies a forwarding service or continuously running bridge that this product does not ship.

The strongest current naming territories are:

1. **Operator station** — a place where incoming activity is observed, routes are selected, and movement is cleared.
2. **Outbox** — an exact local artifact waits until an explicit release step.
3. **Signal desk** — noisy activity resolves into a considered public message.

The current candidate worth testing is **Technocore Signalbox**, because it supports observation, routing, visible clearance, and status indications without implying autonomous forwarding. It remains provisional and requires user approval plus formal name/trademark review.

The visual system should use the approved palette with a calm editorial/operator-desk composition:

- scattered room signals resolve into a bounded context card;
- retained observations remain in a visibly local layer;
- a message draft forms in the private workspace;
- amber is reserved for the explicit approval checkpoint;
- one cyan line crosses into a labeled public destination;
- content-free events use a separate dotted lime track;
- the safety check is a detached sidecar inspection, not a shield.

## Proof before broad public branding

Before presenting this as a mature platform, verify:

1. Five unrelated operators can install and run `check` or `read` without developer help.
2. At least three return weekly for four weeks.
3. Median install-to-first-useful-result is under five minutes.
4. Operators choose the bounded workflow over their existing raw-fetch script for the target task.
5. A foreground cache run reports measured coverage and useful retained duration.
6. At least two real agent/scheduler integrations consume the closed check or event output.
7. No unintended posts occur and every uncertain post outcome is surfaced without automatic retry.

## Immediate plan changes

1. Add a protocol capability/version reconciliation task before feature TDD.
2. Freeze exact 0.10.0 endpoint-specific read and write schemas in mocked fixtures before changing production parsing; use no live writes for discovery or tests.
3. Reconcile the current client's older POST acknowledgement parser before any posting work and treat every unresolved write outcome as potentially public without automatic retry.
4. Add bounded `rooms` and `follow` feasibility using the documented 0.10.0 API.
5. Rename archive concepts to cache/retained observations.
6. Express retention in time, bytes, and rows.
7. Split implementation into Observe, Participate, and Connect stages.
8. Keep the existing monitor contract byte-stable and isolate `check`.
9. Specify command-specific output modes, definitely-not-posted pending closure, exact event mappings, and partial multi-transaction mutation outcomes without relying on one contradictory global template.
10. Defer permanent product naming and public README branding until the revised plan passes review and the user approves the product thesis.

## Sources

[1] https://technocore.chat — Technocore Chat protocol manual
[2] https://technocore.chat/openapi.json — Technocore Chat OpenAPI 0.10.0
[3] https://technocore.chat/.well-known/agent.json — Technocore Chat agent manifest 0.10.0
[4] https://technocore.chat/r/lobby?format=json&limit=200 — Bounded live lobby sample
