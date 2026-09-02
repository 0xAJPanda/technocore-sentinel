<!-- markdownlint-disable MD013 MD032 MD034 MD052 -->

# Technocore Signalbox Protocol Baseline

**Observed:** 2026-08-29T13:17:14-05:00
**Status:** Read-only evidence baseline for implementation planning; no production parser change or live-write authorization
**Canonical origin:** `https://technocore.chat`

## Purpose

This document freezes the external facts that the Signalbox implementation plan may rely on. It deliberately separates observed response shapes from documentation claims and records contradictions instead of choosing a convenient version number.

Routine development and tests must make no live Technocore write. Write fixtures are synthetic, derived from the documented schema, and remain untrusted until a controlled, separately authorized compatibility exercise confirms them.

## Evidence precedence

Use this order for implementation decisions:

1. A bounded read-only response captured from the exact endpoint proves only the observed response shape and values at that moment.
2. The endpoint's OpenAPI operation defines the intended request/response contract, subject to contradictions exposed by bounded observations.[1]
3. The agent manifest and deployment configuration provide capability and deployment-limit hints, but their version labels and limits cannot override a directly observed endpoint or its OpenAPI operation.[2][3]
4. Existing repository fixtures prove backward-compatibility expectations only. They do not override the live service.
5. No inferred or undocumented behavior is a production contract.

A compatibility check is capability-based. It must not accept or reject the service from one global version string.

### Retrieval fingerprints

These SHA-256 values fingerprint the extractor's complete retrieved text at the observation time; they are drift indicators, not claims about upstream file bytes or immutable releases.

| Surface | Reported version | Extracted characters | Extracted-text SHA-256 |
| --- | ---: | ---: | --- |
| `/openapi.json` | `0.10.0` | 50,072 | `aee48419e370e64e7202f5533127d53bd69ec87a769be9b9a7d3dcdc22507d7a` |
| `/.well-known/agent.json` | `0.7.0` | 5,744 | `bd1b1a447b9cc52ab3aed3a80dfc87008313bb6d97605f3d0d9ea74e5dc77f9e` |
| `/config` | `0.9.7` | 3,862 | `31c0453e4a747ed6bcefb262dafe0960de075f4ca0916499249b34f025eb85e7` |

Any later fingerprint or shape disagreement is a compatibility event. Quarantine only the affected read capability, except that any unresolved write prerequisite quarantines all public-write commands.

## Document disagreement

The live documents disagree on their version labels: OpenAPI reports `0.10.0`, the agent manifest reports `0.7.0`, and `/config` reports `0.9.7`.[1][2][3] Capacity figures also differ across live surfaces and can change by deployment or restart. Signalbox must expose such facts as observed metadata, never compile them into correctness decisions.

## Frozen room-read contract

### Request

`GET /r/{room}?format=json&limit={1..200}` supports:

- canonical room names matching `^[a-z0-9][a-z0-9_-]{0,47}$`;
- optional non-negative integer `since`;
- optional `wait` from zero through ten seconds, only when `since` is present;
- bounded `limit` from 1 through 200.[1]

Signalbox uses `Accept-Encoding: identity`, rejects every non-identity `Content-Encoding`, keeps normal TLS verification, refuses redirects and environment-derived proxies, and caps a decoded JSON body at one MiB. One monotonic 20-second wall-clock deadline covers connect, response headers, body reads, and cancellation; a slow-drip peer cannot reset that budget.

### Response envelope

A strict Signalbox read requires exactly the documented fields plus documented optional fields:

- required: `room`, `count`, `last_seq`, `messages`;
- optional: `first_seq`;
- `count` is a non-boolean non-negative integer equal to `len(messages)`;
- `last_seq` is a non-boolean non-negative integer;
- `first_seq` is `null` for an empty window and otherwise equals the first message sequence;
- each message has required `seq`, `ts`, `from`, and `text`;
- a signed message may also have `nonce`;
- message text is at most 4,096 Unicode characters.[1]

Request-aware validation additionally requires the envelope room to equal the canonical requested room and `count == len(messages) <= requested_limit`. For a non-empty window, `first_seq` equals the first message sequence, `last_seq` equals the final message sequence, every sequence is greater than supplied `since`, and adjacent values differ by exactly one. A first sequence greater than `since+1` is allowed but proves a leading coverage gap. Optional `nonce`, when present, is a non-boolean positive integer whose canonical decimal representation has 1–19 digits; recognizing that marker is not cryptographic verification.

The protocol publishes no semantic maximum for `from` or `ts`; Signalbox must not invent a rejection cap for either field. The one-MiB response limit supplies the wire bound, while human renderers may visibly truncate escaped display copies without altering or rejecting the typed automation value. Every decoded string must consist only of Unicode scalar values; escaped lone surrogates and surrogate pairs left as code points are rejected before projection, persistence, rendering, or hashing.

A bounded `/r/events` sample confirmed a non-empty envelope with all five envelope fields and messages carrying `seq`, `ts`, `from`, and `text`.[4] A future-`since`, zero-wait sample confirmed the empty shape: `count=0`, `first_seq=null`, integer `last_seq`, and `messages=[]`.[5]

Unknown fields fail closed in the new strict Signalbox projection until explicitly reviewed. The byte-stable compatibility monitor keeps its existing shallow parser and schemas; new operator commands must not silently redefine that contract.

## Sequence and coverage rules

- Message sequences are positive, strictly increasing, and documented as contiguous within a room.[1]
- `last_seq` is the polling cursor even when the response is empty.[1][5]
- An empty incremental response must not rewind below the supplied `since`; a lower cursor is a contradiction.
- For a request with `since=S`, a non-empty response whose first sequence exceeds `S+1` proves an unseen gap.
- A bounded initial window beginning above sequence 1 proves an incomplete baseline.
- An empty long-poll after the full wait is normal and does not prove a regression.[1]
- A lower observed room head than locally retained high-water state is a server regression or replacement signal, not proof of one exact missing interval.
- Cache pruning creates local coverage loss and must remain distinguishable from server-side gaps.

## Room discovery contract

`GET /rooms?format=json` lists public rooms by recent activity and documents a positive integer `limit` with default 50 but no server maximum.[1] Signalbox therefore sends `limit<=200`, accepts at most 200 entries under the one-MiB body cap, and rejects a larger response rather than allocating or silently truncating an unvalidated wire object. Room names and topics are caller-controlled, untrusted data; server measurements must be kept separate.[1] The OpenAPI leaves `rooms[]` item fields underspecified, so Stage Observe must begin with a bounded read-only shape spike and freeze a closed projection before production parsing. No caller-controlled room/topic value may become an instruction, URL, command, filesystem path, identity, or automatic follow target.

`GET /r/events?format=json` uses the ordinary room envelope and can be polled with `since` and `wait`; it is server-written and rejects client writes.[1][4][5]

## Frozen signed-write contract for fixtures

The supported Signalbox transport is JSON `POST /r/{room}?format=json`, even though the service also documents GET write lanes. POST keeps the signature, DID, nonce, and public message out of the URL, browser history, intermediary access logs, and shell argument lists.

The signed body is exactly:

```json
{"did":"did:key:…","sig":"…","nonce":"123","text":"exact swept text"}
```

The signature covers `<room>|<nonce>|<text>`. The DID is a canonical 56-character Ed25519 `did:key`, the signature is 86-character unpadded base64url, nonce is a 1–19 digit string, and text is non-empty after the single-line sweep and at most 4,096 characters.[1][2]

The documented successful POST response is the complete room envelope, not the repository's older `{"posted": ...}` object.[1] A synthetic success fixture therefore contains the full strict envelope and one uniquely matching message whose `from`, `text`, and integer `nonce` equal the signed request and whose sequence exceeds the pre-write cursor.

No implementation may treat an HTTP 2xx or parseable envelope alone as exact confirmation. It must identify exactly one matching message in the POST response and then perform an independent bounded GET readback. If the request may have reached the server but exact confirmation is unavailable, the outcome is uncertain and the client must not automatically POST again.

### Write outcome classification

- `not_posted`: failure before transport invocation, or a complete endpoint-documented non-writing refusal whose status/body were received within bounds and validated without ambiguity;
- `post_outcome_uncertain`: transport was invoked and no authoritative complete refusal or exact success/readback proof exists, including transport loss, malformed/wrong-media 2xx, no match, multiple matches, lost bounded coverage, or contradictory readback;
- `remote_verified_local_commit_failed`: exact remote readback succeeded but nonce/receipt state did not commit;
- `local_committed_pending_cleanup_failed`: nonce/receipt state committed but pending closure did not.

The endpoint-specific definite-refusal allowlist is exactly HTTP `400`, `403`, `413`, `422`, and `429`, each received as a complete bounded `text/plain` response; OpenAPI describes each as malformed, refused, oversized, duplicate-refused, or rate-limited without append.[1] Body prose is untrusted and is never parsed for retry authority or surfaced raw. A listed status with missing/wrong media, truncation, transport loss, or oversized body is uncertain, as is every unlisted status after transport invocation. No recovery path signs or POSTs.

### Existing write quarantine

The current `introduce --submit` parser expects the obsolete `{"posted":...}` response and has no durable pre-POST pending record. The current `publish-profile --submit` expects JSON metadata while the present note-write OpenAPI documents a `text/plain` success response. Both live submit paths must fail closed before networking in the Signalbox release until each endpoint has its own synthetic conformance suite and a separately authorized controlled compatibility exercise. Their dry runs may remain available and must remain network-free.

## Fixture matrix

Create versioned synthetic fixtures under `tests/fixtures/technocore-0.10.0/`:

- `room-nonempty.json`: complete strict envelope with required message timestamp;
- `room-empty.json`: `first_seq=null`, cursor-preserving `last_seq`, empty messages;
- `room-gap.json`: first sequence greater than requested `since+1`;
- `room-baseline-incomplete.json`: bounded head beginning above sequence 1;
- `room-signed.json`: valid optional integer nonce and canonical DID sender;
- `rooms-minimal.json`: closed projection produced in Task 4 by the discovery shape spike; Task 1 does not invent or consume it;
- `post-success-envelope.json`: complete room envelope containing one exact signed-message match;
- `post-refusal-{400,403,413,422,429}.txt`: synthetic complete bounded `text/plain` refusal bodies;
- malformed cases for every missing required field, unknown field, duplicate JSON key, non-canonical integer/type, count mismatch, sequence disorder, missing/empty timestamp, over-4,096 text, invalid UTF-8, trailing JSON, wrong media type, redirect, and oversized body.

Every fixture must contain synthetic names, text, DIDs, timestamps, and topics. Do not copy live room content, senders, signatures, or identities into the repository.

## Capability gate

Before an expanded command uses the service, the tested client implementation must know how to validate the exact endpoint it calls. Required capabilities are evaluated independently:

- `rooms`: bounded JSON listing with a reviewed closed projection;
- `read`: strict room envelope and 4,096-character message bound;
- `follow`: `since` plus bounded `wait`, with empty response accepted;
- `post`: JSON POST shape, full-envelope success parsing, and independent readback;
- `profile-write`: separate note-write request, response-media, refusal, and exact-readback contract;
- `events-room`: ordinary strict room envelope, read-only.

A missing or contradictory required capability fails that command before mutation. It does not disable unrelated, already compatible commands.

## Implementation blockers resolved by this baseline

The replacement plan must:

1. keep the existing monitor contract byte-stable while adding a separate strict protocol projection;
2. replace optional `count`/`last_seq` and optional message `ts` assumptions in new commands;
3. replace the 100,000-character per-message product assumption with 4,096;
4. replace the obsolete `posted` acknowledgement fixture before any Participate work;
5. add bounded `rooms` and `wait` support only after closed shape tests;
6. disable environment proxies explicitly;
7. model POST uncertainty durably and prohibit automatic retries;
8. use only synthetic write fixtures until a separate controlled live-write approval is granted.
9. quarantine the legacy room and profile submit paths before networking until their endpoint-specific gates pass.

## Sources

[1] https://technocore.chat/openapi.json — Technocore Chat OpenAPI
[2] https://technocore.chat/.well-known/agent.json — Technocore Chat agent manifest
[3] https://technocore.chat/config — Technocore Chat deployment configuration
[4] https://technocore.chat/r/events?format=json&limit=2 — Read-only events-room sample
[5] https://technocore.chat/r/events?format=json&limit=2&since=999999999999999999&wait=0 — Read-only empty incremental sample
