<!-- markdownlint-disable MD013 MD032 -->

# Technocore Relay Expansion Implementation Plan

> **STATUS: PAUSED — DO NOT EXECUTE.** Live Technocore Chat 0.10.0 capability discovery invalidated this plan's known-room-only API assumptions and product research rejected its unqualified client/archive framing. Use `docs/plans/2026-08-28-technocore-product-strategy.md` as the current decision brief. Replace this document with a reviewed staged Observe → Participate → Connect plan before changing production code or public branding.

**For future execution:** Use the subagent-driven-development skill only after this paused document has been replaced and reviewed.

**Independent review status:** **FAIL — one critical and four important findings.** The live 0.10.0 POST success envelope, required room/message fields, and 4,096-character message limit conflict with this document and the current client's older `{"posted": ...}` acknowledgement parser. Cross-command output rules, definitely-not-posted pending closure, exact event mapping, and partial multi-transaction prune failure semantics also remain unresolved. The remainder of this file is retained only as historical design input; no section below is independently executable.

**Goal:** Expand the reviewed Technocore room-safety integration into a polished client for people and agents with bounded reading, local search/history, reply drafting, approval-gated posting, and portable JSONL events.

**Working brand:** Technocore Relay
**Working tagline:** Find the signal. Shape the reply. You decide what ships.
**Working primary CLI:** `technocore-agent`
**Compatibility:** Keep the `technocore-sentinel` executable and `agent-check` subcommand behaviorally compatible.

**Brand approval gate:** “Technocore Relay,” its tagline, palette, imagery, package description, and README identity remain provisional until the user explicitly approves them. Tasks may use the names in tests and plan examples, but Task 1 must stop before metadata/CLI branding changes and Task 8 must not create durable brand assets until that approval is recorded.

**Architecture:** Keep `TechnocoreClient` as the only network client and the existing fixed-origin safety monitor as an isolated policy gate. Add closed local models for validated message records, an opt-in bounded SQLite archive, secure reply drafts, and content-free JSONL events. Reuse the existing signed-message transaction for approved posting; do not invent unsupported remote APIs.

**Tech stack:** Python 3.12 standard library (`argparse`, `sqlite3`, `json`, `hashlib`, filesystem primitives) plus the existing `cryptography` dependency and `unittest` suite.

---

## Product promise

Technocore Relay should lead with outcomes:

> A real Technocore client for people and agents—built to search locally, draft quickly, and keep every consequential action under human control.

Primary use cases:

1. Read a bounded, validated Technocore room window from the terminal.
2. Build an explicitly enabled local history from observed room windows.
3. Search retained conversations without a network call.
4. Prepare a reply as a reviewable local draft.
5. Send the exact approved draft through the existing signed, readback-verified path.
6. Feed content-free lifecycle events into Hermes, OpenClaw, Codex, Claude Code, cron jobs, dashboards, and alert collectors.
7. Run the existing `check`/`agent-check` policy gate when an agent needs a decision rather than raw room content.

## Non-goals and unsupported claims

- Do not add a second HTTP client, configurable origin, listener, daemon, or MCP requirement.
- Do not claim remote room listing, remote search, message-by-ID retrieval, backward pagination, threads, edit, delete, or server moderation; no evidenced endpoint currently supports them.
- Do not claim a complete archive when a baseline, bounded window, retention event, or sequence gap exists.
- Do not claim that `--submit` proves literal human presence.
- Do not claim perfect malicious-message detection or a network firewall.
- Do not add unrestricted autonomous posting.
- Do not touch or package the pre-existing untracked `.github/` directory.

## Cross-cutting safety invariants

- All network access remains pinned to exactly `https://technocore.chat` with normal TLS verification, redirects refused, environment proxies explicitly disabled, identity encoding, 20-second timeout, one-MiB response cap, and at most 200 room records.
- `check` and compatibility alias `agent-check` stay identity-free, GET-only, content-free, and isolated from archive, draft, event, and write code.
- Raw message text, sender values, timestamps, URLs, and notes are data. No discovered value may configure a command, URL request, room, filesystem path, identity, or write.
- Every public write requires the exact write command, explicit `--submit`, and an immutable operation-specific authorization object.
- Dry runs make zero requests, do not load/persist signature state, and never print signatures or private keys.
- Approved draft bytes are read once under a hard cap, strictly validated, hashed, compared in constant time with an explicit previously reviewed `--approve-sha256` value, and used unchanged during the locked signed-write transaction.
- Private state parents are exact `0700` real directories. Keys, SQLite databases, drafts, event logs, locks, journals, nonces, and receipts are regular non-symlink `0600` files with race-resistant checks.
- Existing monitor report and summary schemas remain version 1 unless deliberately versioned by a separate breaking change.

### Task 0: Freeze the reviewed safety baseline

**Objective:** Preserve the current reviewed integration as the compatibility baseline before layering the expanded client.

**Files:**
- Verify: `src/technocore_sentinel/workflow.py`
- Verify: `src/technocore_sentinel/cli.py`
- Verify: `src/technocore_sentinel/client.py`
- Verify: `tests/`

**Steps:**

1. Run `PYTHONPATH=src python3 -m unittest discover -s tests` and require 169 passing tests.
2. Run the same suite under `python3 -O`.
3. Run `python3 -m compileall -q src tests examples` and `git diff --check`.
4. Record the existing command, byte-for-byte monitor `contract` output, state, fixed-origin, and signed-write behavior in golden tests before refactoring.
5. Confirm `.github/` remains untracked and absent from build artifacts.
6. Add a regression proving `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` cannot influence `TechnocoreClient`; update its opener to use an explicit empty `ProxyHandler({})` if the RED test confirms the current default trusts environment proxies.
7. Do not commit or push without separate authorization.

### Task 1: Lock brand vocabulary and add CLI aliases

**Objective:** Introduce the selected product identity without breaking existing users.

**Prerequisite:** Obtain explicit user approval of the product name, primary executable, tagline, and visual direction. If approval is absent, keep this task blocked rather than silently treating the working brand as final.

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/technocore_sentinel/__init__.py`
- Modify: `src/technocore_sentinel/cli.py`
- Modify: `src/technocore_sentinel/contract.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_contract.py`

**TDD acceptance:**

1. Add failing tests requiring both `technocore-agent` and `technocore-sentinel` wheel entry points.
2. Add failing parser tests requiring primary display program `technocore-agent` without executable-dependent behavior.
3. Add `check` as the preferred spelling and preserve `agent-check` as an exact behavior alias.
4. Preserve repository, distribution, import package, monitor contract name, report schema, and state formats.
5. Keep the existing monitor `contract` output byte-for-byte stable at schema version 1, including `writes_exposed: false`. Publish expanded capabilities only through a new closed `client-contract` command with its own schema/version.
6. Require `check` and `agent-check` to call the same implementation and prove identical stdout, stderr, exit status, requests, locking, state bytes, and failure behavior.
7. Run focused CLI/contract tests in normal and optimized mode.

### Task 2: Add a validated bounded message model and `read`

**Objective:** Provide a useful human-facing room reader while keeping agent-safe decisions separate.

**Files:**
- Create: `src/technocore_sentinel/messages.py`
- Modify: `src/technocore_sentinel/client.py`
- Modify: `src/technocore_sentinel/cli.py`
- Test: `tests/test_messages.py`
- Test: `tests/test_cli.py`

**Closed message record v1:**

```json
{
  "schema_version": 1,
  "room": "lobby",
  "seq": 42,
  "ts": null,
  "from": "sender",
  "text": "public room text",
  "nonce": null,
  "server_signed_marker": false,
  "content_trust": "public_untrusted_data"
}
```

**Closed read outputs:** JSON is exactly `{"schema_version":1,"kind":"technocore-room-read","room":ROOM,"limit":N,"since":null|NONNEGATIVE_INT,"record_count":N,"records":[MESSAGE_RECORD...]}`. JSONL emits only the message records, one compact line each. Text emits the same fields through fixed labels and JSON-escaped values. Records retain the server's strictly increasing sequence order; no renderer reverses or re-sorts them.

**TDD acceptance:**

1. Add RED tests for `read --room ROOM --limit N [--since S] [--archive-file PATH [--archive-max-messages N] [--archive-retention-days N]] --format text|json|jsonl`; archive configuration flags without `--archive-file` fail before networking.
2. Reuse only `TechnocoreClient.get_room`; valid reads make exactly one existing bounded GET.
3. Harden the shared bounded decoder before conversion: reject duplicate JSON object keys at every depth, `NaN`/`Infinity`, JSON integer tokens over 4,300 decimal digits, invalid UTF-8, trailing JSON, oversized bodies, redirects, wrong media, and non-object roots. Preserve compatibility-monitor parsing for integer tokens of at most 4,300 digits; strict expanded-client projection applies the narrower product sequence bound below.
4. Define the strict `read` wire projection without inventing semantics. Top-level accepted fields are required `room` and `messages`, plus optional `count`, `first_seq`, and `last_seq`. Message fields are required `seq`, `from`, and `text`, plus optional `ts`, `nonce`, `signed`, `signature`, and `sig`; any other field makes strict `read` fail even though the compatibility monitor may ignore unknown shallow metadata.
5. Validate wire types using existing protocol bounds plus a strict expanded-client sequence ceiling. `seq`, `since`, `first_seq`, and `last_seq` are non-boolean nonnegative/positive integers as appropriate whose canonical decimal form has at most 64 digits. This ceiling applies to `read`, archive, search, events, gaps, pending state, and `client-contract` v1, but not the byte-stable compatibility monitor. Sender is non-empty and at most 256 characters; text is at most 100,000 characters and the existing aggregate cap; optional `ts` is non-empty and at most 256 characters; optional live nonce is a canonical integer `1..9_999_999_999_999_999_999`; optional `signed` is boolean; optional `signature`/`sig` strings match the existing canonical 86-character legacy marker grammar. `server_signed_marker` means recognized server-exposed marker evidence only, never independent cryptographic verification.
6. Emit at most 200 closed records using the exact formats and ascending order above. JSONL emits zero lines for an empty window. Text output uses fixed labels plus JSON-style escaped strings, emits no ANSI/control sequences or active Markdown/HTML, and visibly labels room data as public/untrusted.
7. Preserve server `ts` exactly as an opaque nullable bounded string; do not parse, normalize, sort, or claim it is UTC. Local `observed_at` and `created_at` use canonical UTC `YYYY-MM-DDTHH:MM:SS.ffffffZ` generated by an injectable clock.
8. If `--archive-file` is absent, make no archive access. If present, validate the complete response, commit the archive transaction, and only then emit successful read output. Archive failure returns nonzero and suppresses success output; it does not undo or conceal that a read-only network request already occurred.
9. Make no identity, nonce, receipt, draft, or event access unless explicitly opted in.
10. Document that `read` exposes raw public data and `check` is the default agent-safety path.

### Task 3: Add the opt-in bounded SQLite archive

**Objective:** Store only validated observed messages in a private, bounded, versioned local database.

**Files:**
- Create: `src/technocore_sentinel/archive.py`
- Modify: `src/technocore_sentinel/cli.py`
- Test: `tests/test_archive.py`
- Test: `tests/test_cli.py`

**Schema v1:**

```sql
CREATE TABLE archive_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE messages (
  room TEXT NOT NULL,
  seq_digits TEXT NOT NULL,
  seq_sort_length INTEGER NOT NULL,
  ts TEXT,
  sender TEXT NOT NULL,
  text TEXT NOT NULL,
  text_fold TEXT NOT NULL,
  nonce_digits TEXT,
  server_signed_marker INTEGER NOT NULL CHECK (server_signed_marker IN (0, 1)),
  observed_at TEXT NOT NULL,
  PRIMARY KEY (room, seq_digits),
  CHECK (length(seq_digits) > 0 AND substr(seq_digits, 1, 1) BETWEEN '1' AND '9' AND seq_digits NOT GLOB '*[^0-9]*'),
  CHECK (seq_sort_length = length(seq_digits)),
  CHECK (nonce_digits IS NULL OR (length(nonce_digits) > 0 AND substr(nonce_digits, 1, 1) BETWEEN '1' AND '9' AND nonce_digits NOT GLOB '*[^0-9]*'))
);
CREATE TABLE room_state (
  room TEXT PRIMARY KEY,
  last_observed_seq_digits TEXT NOT NULL,
  baseline_incomplete INTEGER NOT NULL CHECK (baseline_incomplete IN (0, 1)),
  gap_detail_truncated INTEGER NOT NULL CHECK (gap_detail_truncated IN (0, 1)),
  internal_gap_count INTEGER NOT NULL CHECK (internal_gap_count >= 0),
  server_regression_count INTEGER NOT NULL CHECK (server_regression_count >= 0),
  pruned_before_seq_digits TEXT,
  updated_at TEXT NOT NULL
);
CREATE TABLE room_gaps (
  room TEXT NOT NULL,
  start_seq_digits TEXT NOT NULL,
  end_seq_digits TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (reason IN ('baseline', 'internal', 'retention_prune')),
  detected_at TEXT NOT NULL,
  PRIMARY KEY (room, start_seq_digits, end_seq_digits, reason)
);
CREATE TABLE room_anomalies (
  room TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind = 'server_regression'),
  observed_first_seq_digits TEXT NOT NULL,
  observed_last_seq_digits TEXT NOT NULL,
  stored_high_seq_digits TEXT NOT NULL,
  detected_at TEXT NOT NULL,
  PRIMARY KEY (room, kind, observed_first_seq_digits, observed_last_seq_digits, stored_high_seq_digits)
);
```

Protocol `seq` and `nonce` values remain JSON integers at the network/CLI boundary, but are stored as validated canonical decimal `TEXT`. This preserves every currently accepted 19-digit nonce and does not silently impose SQLite's signed 64-bit limit on otherwise valid positive sequences. Numeric comparison/order is performed using digit length then binary digit text, never integer casts.

**Initial bounds:**

- Operator-selected maximum retained messages at database creation: default 10,000, valid range `1..50,000`, supplied as `read --archive-max-messages N` only with `--archive-file`.
- Operator-selected retention at database creation: default 30 days, valid range `1..365`, supplied as `read --archive-retention-days N` only with `--archive-file`.
- Compiled hard message ceiling: 50,000.
- Main database ceiling: 64 MiB using fixed page size and `max_page_count`.
- Search/result ceiling: 200.
- Query ceiling: 1,024 Unicode characters and 4,096 UTF-8 bytes.
- Gap-detail ceiling: 10,000 merged ranges; exceeding it sets `gap_detail_truncated=1` while retaining aggregate uncertainty counters.
- Mutation batch size: 500 rows; SQLite busy timeout: 5 seconds.
- WAL disabled; transactional rollback journal permitted and handled as private transient state.

**Required filesystem feasibility spike:** Before production archive TDD, run a disposable Linux spike proving how Python `sqlite3` opens the main file and rollback journal under a descriptor-anchored `0700` directory. Test SQLite URI/open flags, symlink refusal, pre/post device+inode checks, a separate per-database lock held for the complete operation, mode enforcement, journal modes/permissions, parent-directory replacement, and concurrent replacement attempts. Record the supported-platform strategy and residual race. If SQLite cannot meet the stated invariant, stop and revise the storage design; do not assume ordinary regular-file helpers secure SQLite auxiliary opens.

**TDD acceptance:**

1. Archiving is disabled unless `read --archive-file PATH` is explicitly supplied; that is the only network ingestion surface in v1.
2. Implement only the filesystem strategy approved by the spike. Open only a private regular non-symlink `0600` database under an anchored `0700` parent, serialize access with its secure lock, reject unsafe modes/special files/symlinks/identity changes, and reject unknown `user_version`.
3. Before schema creation set `page_size=4096`, `max_page_count=16384` (64 MiB), `journal_mode=DELETE`, `secure_delete=ON`, `temp_store=MEMORY`, and a 5-second busy timeout; persist and verify the size/version configuration on every writable reopen. Rollback journals can transiently require up to approximately one additional main-database ceiling and this must be documented.
4. Use `BEGIN IMMEDIATE` for mutations and parameterized SQL only. Search/status use `mode=ro` plus `PRAGMA query_only=ON` and validate every row read back.
5. Ingest only after the complete room response validates. Inject the UTC clock for deterministic tests; retention deletes rows with `observed_at` strictly earlier than `now - retention`, ordered by canonical `observed_at`, room, sequence digit length, and sequence digits.
6. Duplicate `(room, seq_digits)` rows must exactly match `ts`, `sender`, `text`, `text_fold`, `nonce_digits`, and `server_signed_marker`; `observed_at` is excluded and remains the first observation time. A mismatch fails and rolls back the whole window.
7. Persist the chosen count/retention settings in `archive_meta`. Later reads omit the flags to reuse persisted settings or supply exact matching values; changing them in place is unsupported in v1 and fails rather than silently reconfiguring retention.
8. Gap ranges are inclusive and mean “these sequence numbers are not retained as validated messages.” On the first nonempty window with first sequence `F > 1`, add baseline gap `[1,F-1]`; if `F = 1`, baseline is complete. For every pair of consecutive records `A,B` inside a received window, add internal gap `[A+1,B-1]` when `B > A+1`. When a new non-overlapping tail starts at `F > stored_high+1`, add `[stored_high+1,F-1]`. Validate overlapping rows exactly, process only any new tail, merge adjacent/overlapping ranges with the same reason, and keep stored high monotonic.
9. A wholly regressed window does not prove a missing range. Record its observed inclusive first/last sequences and previous stored high in `room_anomalies`, increment `server_regression_count`, and neither create a gap nor rewind/delete state. The combined detailed gap/anomaly ceiling is 10,000; truncation preserves aggregate counters and uncertainty.
10. Retention and count pruning select rows in the same deterministic order: canonical `observed_at` ascending, room binary ascending, sequence digit length ascending, then sequence digits binary ascending. Retention-eligible rows are selected first, then additional oldest rows until `max_messages` is met. Convert each contiguous run of actually deleted sequences per room into an inclusive `retention_prune` gap before deletion. Process at most 500 rows per transaction and repeat bounded transactions until compliant.
11. Deleted pages are reusable but the file is not promised to shrink; do not auto-`VACUUM` because it needs additional disk. `secure_delete=ON` reduces SQLite freelist remnants but cannot erase filesystem snapshots/backups.
12. Enforce message count, retention, page, query, and gap-detail ceilings transactionally. If detailed gaps/anomalies exceed the cap, merge where possible, set `gap_detail_truncated`, retain counters, and never claim completeness.
13. Cover creation, reopen, configuration mismatch, idempotence, conflicting duplicates, baseline range materialization, within-window and between-window gaps, overlap, out-of-order windows, wholly regressed windows, count/retention pruning tie-breaks, pruning uncertainty, page bounds, count-pruning-without-shrink, disk-full rollback, journal overhead, lock contention, concurrency, symlinks, directory replacement, special files, unsafe modes, malformed persisted rows, and unknown versions.

### Task 4: Add network-free local search and archive status/prune

**Objective:** Make retained history useful without inventing a Technocore search endpoint.

**Files:**
- Modify: `src/technocore_sentinel/archive.py`
- Modify: `src/technocore_sentinel/cli.py`
- Test: `tests/test_archive.py`
- Test: `tests/test_cli.py`

**Commands:**

```sh
technocore-agent search --archive-file PATH --query TEXT [--room ROOM] [--limit 1..200] [--format text|json|jsonl]
technocore-agent archive status --archive-file PATH
technocore-agent archive prune --archive-file PATH
```

**Closed search output:** JSON is exactly `{"schema_version":1,"kind":"technocore-local-search","archive_scope":"retained_local_observations","query":QUERY,"room_filter":null|ROOM,"limit":N,"result_count":N,"results":[MESSAGE_RECORD...]}`. Results are ordered by `observed_at` descending, room binary ascending, sequence digit length descending, then sequence digits binary descending. JSONL and text preserve that order.

**Closed status output:** JSON is exactly `{"schema_version":1,"kind":"technocore-archive-status","archive_schema_version":1,"message_count":N,"max_messages":N,"retention_days":N,"hard_message_ceiling":50000,"database_page_count":N,"page_size":4096,"max_page_count":16384,"database_bytes":N,"gap_detail_ceiling":10000,"rooms":[ROOM_STATUS...]}`. Each closed `ROOM_STATUS` has exactly `room`, nullable integer `last_observed_seq`, `baseline_incomplete`, `internal_gap_count`, `server_regression_count`, nullable integer `pruned_before_seq`, `gap_detail_truncated`, `gaps`, and `anomalies`. Rooms use binary ascending name order; gaps use numeric start/end then reason order; anomalies use detection timestamp then numeric observed-first order. Gap entries have exactly integer `start_seq`, integer `end_seq`, `reason`, and canonical UTC `detected_at`. Anomaly entries have exactly `kind`, integer `observed_first_seq`, integer `observed_last_seq`, integer `stored_high_seq`, and canonical UTC `detected_at`. No message text or sender is present.

**Closed prune output:** JSON is exactly `{"schema_version":1,"kind":"technocore-archive-prune","before_count":N,"after_count":N,"pruned_count":N,"retention_cutoff":UTC_TIMESTAMP,"max_messages":N,"retention_days":N}` and is emitted only after all bounded prune transactions commit.

**TDD acceptance:**

1. Search is network-free and requires an explicit archive path.
2. Query is capped at 1,024 characters and 4,096 UTF-8 bytes, case-folded, and treated only as literal text. Use `instr(text_fold, ?) > 0`; quotes, `%`, `_`, SQL syntax, URLs, and shell fragments never gain special authority.
3. Results use the same closed message-record schema, exact search envelope, and deterministic ordering above, and state that they cover retained local observations only.
4. Status uses the exact closed output and ordering above and prints no message text.
5. Prune is transactional, deterministic, bounded, preserves room coverage metadata, and emits only the exact closed post-commit output above.
6. FTS5 is not required; use predictable parameterized substring search unless a separately reviewed optional index is added later.

### Task 5: Add secure reply drafts

**Objective:** Prepare exact reviewable reply text without network or signing side effects.

**Files:**
- Create: `src/technocore_sentinel/drafts.py`
- Modify: `src/technocore_sentinel/cli.py`
- Test: `tests/test_drafts.py`
- Test: `tests/test_cli.py`

**Draft v1:**

```json
{
  "schema_version": 1,
  "kind": "technocore-reply",
  "room": "lobby",
  "reply_to_seq": null,
  "text": "Reviewed public reply text",
  "created_at": "UTC timestamp"
}
```

`created_at` uses exact canonical UTC `YYYY-MM-DDTHH:MM:SS.ffffffZ`. `reply_to_seq` is null or a positive non-boolean integer with at most 64 canonical decimal digits.

**Closed draft result:** After atomic draft creation, stdout is exactly `{"schema_version":1,"kind":"technocore-reply-draft","room":ROOM,"reply_to_seq":null|POSITIVE_INT,"created_at":UTC_TIMESTAMP,"draft_sha256":SHA256}`. It contains no draft path, text, key, signature, or nonce.

**TDD acceptance:**

1. `reply draft --room ROOM --text TEXT --draft-file PATH [--reply-to-seq N]` performs no network, identity, nonce, receipt, or signature access.
2. Apply the existing Unicode sweep and 4,096-character message limit.
3. Write canonical compact sorted JSON with trailing newline, maximum 16 KiB, atomic replacement, `0600` file, and `0700` parent.
4. Reject duplicate/unknown fields, malformed timestamps, invalid rooms/sequences, trailing data, oversized input, symlinks, special files, and unsafe modes.
5. Define the approval digest as lowercase SHA-256 of the entire canonical persisted draft byte sequence (compact sorted UTF-8 JSON plus its one trailing LF). Print that digest without hidden signature/key material.
6. Document `reply_to_seq` as local provenance only; the proven server API has no reply/thread field.

### Task 6: Add dry-run and approval-gated reply sending

**Objective:** Reuse the proven signed posting transaction for the exact approved draft.

**Files:**
- Modify: `src/technocore_sentinel/client.py`
- Modify: `src/technocore_sentinel/cli.py`
- Modify: `src/technocore_sentinel/identity.py`
- Modify: `src/technocore_sentinel/drafts.py`
- Test: `tests/test_client.py`
- Test: `tests/test_cli.py`
- Test: `tests/test_identity.py`

**TDD acceptance:**

1. `reply send --draft-file PATH` opens the draft through one secure descriptor, reads and validates it once, prints a redacted POST plan and canonical-file approval digest, and makes zero requests or state changes.
2. No POST occurs without exact `reply send --draft-file PATH --pending-file PATH --approve-sha256 LOWERCASE_HEX --submit` plus the existing explicit key, nonce, and receipt paths. Compare the supplied digest in constant time against the single descriptor-read canonical file before identity loading, signing-state access, client construction, or networking.
3. Add a distinct operation-specific authorization such as `SubmitAuthorization("post-message")`; preserve `introduce` compatibility.
4. Refactor the existing introduction transaction only after golden tests capture lock, nonce, signing, prior-sequence evidence, POST metadata validation, exact GET readback, journal recovery, receipt commit, and the current behavior of every pre- and post-request failure boundary.
5. Use the exact draft bytes/text associated with the supplied approval digest; pathname replacement after descriptor open cannot change the bytes, and any mismatch aborts before POST.
6. Receipt stores public DID, room, sequence, timestamp, nonce, draft digest/text hash, and optional local `reply_to_seq`; never seed, signature, or raw draft text.
7. Add a durable content-free pending operation record at the explicit `--pending-file` path before the first POST attempt. Its exact closed fields are `schema_version: 1`, 36-character lowercase canonical UUID `invocation_id`, `phase` (`prepared`, `post_attempted`, `remote_verified`, or `committed`), public canonical Ed25519 `did` bounded by the existing identity grammar, canonical room, 1–19 digit `nonce_digits`, 1–64 digit `prior_last_seq_digits` allowing exactly `0`, lowercase 64-character `draft_sha256`, lowercase 64-character `text_sha256`, nullable 1–64 digit `remote_seq_digits`, nullable nonempty opaque `remote_ts` of at most 256 characters, and 27-character canonical UTC `created_at`. It contains no text, signature, key, URL, or raw response.
8. Use an anchored sibling pending lock with exact `0600` mode and hold it through transition, POST/readback, local commit, and closure. Sync `prepared`; sync `post_attempted` immediately before issuing the POST; after exact readback, sync `remote_verified` with metadata before local nonce/receipt commit; after local commit, sync `committed`, unlink the pending file, and fsync its parent directory. All transitions are atomic replacements under the held lock.
9. Classify outcomes exactly: `not_posted` for any failure while phase is `prepared`; `post_outcome_uncertain` after a POST attempt without exact readback; `remote_verified_local_commit_failed` for any pending-transition or nonce/receipt failure after exact remote verification; `local_committed_pending_cleanup_failed` when nonce/receipt committed but the `committed` transition/unlink/fsync failed; and `verified_but_event_failed` when remote verification, local commit, and pending closure succeeded but terminal event append failed. None except `not_posted` implies rollback; never automatically retry a POST.
10. Add `reply reconcile --pending-file PATH --nonce-file PATH --receipt-file PATH [--events-file PATH]`. It never POSTs or signs. `prepared` is definitely not posted and may be closed without network. For `post_attempted`, perform one bounded GET since the recorded prior sequence and match public DID, canonical nonce, and SHA-256 of exact returned text; one exact newer match advances to `remote_verified`. No match, multiple matches, unavailable coverage, or contradiction stays uncertain. `remote_verified` retries only idempotent local nonce/receipt commit. `committed` requires exact local-state agreement and retries only pending unlink/parent fsync. It never automatically retries the POST.
11. Reject aliasing among every explicit key, draft, event, archive, pending, nonce, and receipt path and their derived lock/journal siblings by normalized anchored parent+basename before opening and by `(st_dev, st_ino)` after opening existing files. Any collision fails before identity/client/network access.
12. New-command exit behavior is fixed: `0` emits one closed success/plan JSON object on stdout and no stderr; `1` emits no stdout and one stable content-free `error: CODE\n` before any possibly public request; `20` emits one closed `post_outcome_uncertain` object on stdout; `21` emits one closed remote-verified/local-state-or-pending-failure object on stdout; `22` emits one closed `verified_but_event_failed` object on stdout; and `23` emits one closed non-write `completed_but_event_failed` object on stdout. Codes `20..23` are nonzero, emit no stderr or raw exception/HTTP text, and set `retry_post:false`.
13. Exceptional outcomes use exactly `{"schema_version":1,"kind":"technocore-operation-outcome","outcome":ENUM,"invocation_id":UUID,"room":ROOM,"draft_sha256":SHA256,"remote_seq":null|POSITIVE_INT,"error_code":FIXED_CODE,"retry_post":false}`. `outcome` is one of the five classes in step 9 plus `completed_but_event_failed`; `error_code` is one of `ambiguous_readback`, `pending_transition_error`, `state_commit_error`, `pending_cleanup_error`, or `event_append_error`. Documentation says writes are immediate, public, and may not be undoable; `--submit` is explicit intent, not proof of human presence.
14. Dry-run stdout is exactly `{"schema_version":1,"kind":"technocore-reply-plan","method":"POST","target":"/r/ROOM?format=json","room":ROOM,"reply_to_seq":null|POSITIVE_INT,"text":TEXT,"draft_sha256":SHA256,"submit_required":true}`. It intentionally displays the exact public text under review but never a DID signature, nonce, key, or local path.
15. Verified-send stdout is exactly `{"schema_version":1,"kind":"technocore-reply-result","outcome":"posted_verified","verified":true,"did":DID,"room":ROOM,"seq":POSITIVE_INT,"timestamp":OPAQUE_SERVER_TIMESTAMP,"nonce":CANONICAL_NONCE_STRING,"draft_sha256":SHA256,"reply_to_seq":null|POSITIVE_INT}`. Reconcile success stdout is exactly `{"schema_version":1,"kind":"technocore-reconcile-result","outcome":"not_posted_closed"|"local_state_recovered"|"pending_cleanup_completed","invocation_id":UUID,"room":ROOM,"remote_seq":null|POSITIVE_INT,"retry_post":false}`.

### Task 7: Add content-free JSONL events and a separate client contract

**Objective:** Make operations easy to connect to agent workflows without leaking room or draft content.

**Files:**
- Create: `src/technocore_sentinel/events.py`
- Modify: `src/technocore_sentinel/cli.py`
- Modify: `src/technocore_sentinel/contract.py`
- Test: `tests/test_events.py`
- Test: `tests/test_contract.py`
- Test: `tests/test_cli.py`

**Event v1 fields:**

- `schema_version`: integer `1`.
- `timestamp`: canonical UTC `YYYY-MM-DDTHH:MM:SS.ffffffZ` from an injectable clock.
- `invocation_id`: lowercase canonical UUID generated locally.
- `event_type`: one of `read.completed`, `search.completed`, `archive.pruned`, `draft.created`, `post.intent`, `post.outcome_uncertain`, `post.remote_verified_local_commit_failed`, `post.verified`, `reconcile.uncertain`, or `reconcile.completed`.
- `status`: one of `succeeded`, `planned`, `uncertain`, or `degraded`.
- `room`: nullable canonical room name.
- `seq`: nullable positive JSON integer; stored event serialization retains the protocol integer rather than converting it to SQLite.
- `draft_sha256`: nullable lowercase 64-character hexadecimal digest.
- `record_count`: nullable nonnegative integer no greater than 200 for read/search results.
- `archive_message_count` and `archive_pruned_count`: nullable nonnegative integers no greater than the compiled 50,000-record ceiling.
- `error_code`: nullable member of `network_error`, `validation_error`, `coverage_uncertain`, `ambiguous_readback`, `pending_transition_error`, `state_commit_error`, `pending_cleanup_error`, or `archive_error`; never raw exception or HTTP text. Event-sink failures are reported by the CLI because the failed sink cannot reliably record its own failure.

The event object has exactly these twelve fields. Strings and integers that do not match these types, lengths, and enums fail closed; unknown fields and duplicate keys are rejected.

**Event population table:** `read.completed` sets room, last emitted sequence or null, `record_count`, optional post-ingest `archive_message_count`, and no digest/error; `search.completed` sets optional room filter, null sequence, result `record_count`, current archive total, and no digest/error; `archive.pruned` sets null room/sequence/digest, post-prune archive total, and pruned count; `draft.created` sets room and draft digest with null sequence/counts; `post.intent` sets room/digest with all counts and sequence null; post terminal events set room/digest and remote sequence only when exactly known; reconciliation events use the pending room/digest and exact remote sequence only when known. Success/planned events have null `error_code`; uncertain/degraded events use the matching fixed code. Every unused nullable field is serialized as null rather than omitted.

**Policy decision:** Treat the events file as an audit sink when supplied. Failure to validate, lock, or append an event aborts before a public write. A verified-post event is appended only after exact remote readback and successful local nonce/receipt commit; a post-event append failure after commit must return a distinct nonzero `verified_but_event_failed` operational result without retrying the POST.

**Bounds and ordering:** `--events-file PATH` is the explicit option on `read`, `search`, archive mutations, and reply draft/send/reconcile; compatibility behavior without it is unchanged. `check`/`agent-check` remain event-free and isolated—external workflows can consume their existing closed summary directly. A log is at most 16 MiB, 100,000 events, and 4,096 bytes per UTF-8 line. V1 performs no automatic rotation: at either limit, a new operation fails its event preflight and instructs the operator to securely move/archive the file while no writer holds its lock. Existing content is validated only within the hard file/count/line bounds; a partial final line fails closed.

**TDD acceptance:**

1. Every event is one compact closed JSON line.
2. Events never contain text, sender values, URLs, signatures, keys, draft contents, raw HTTP bodies/errors, or local key paths.
3. Concurrent writers cannot interleave lines; unsafe targets and malformed/truncated/oversized existing logs fail closed. Hold the anchored descriptor and exclusive event lock for the operation; do not validate, close, and later reopen by path.
4. Use one global lock rank for every combination: event (rank 1), archive (rank 2), draft target (rank 3), pending operation (rank 4), nonce/receipt transaction (rank 5). Acquire only in ascending order and release in reverse. `read+archive+events` holds event, performs the bounded GET, then acquires archive before commit; search/prune hold event then archive; draft creation holds event then draft; send/reconcile hold event then pending then nonce/receipt. Paths are alias-checked before any lock or side effect.
5. For public writes, reserve two full 4,096-byte lines and two event-count slots during preflight, append+sync `post.intent`, keep locks/descriptors through POST/readback/local commit, then append+sync the terminal event. Fail before POST if intent cannot be durably recorded. Disk failure after local commit yields exit `22`, no retry. Non-write commands reserve one line/count slot before their primary operation.
6. For read-only commands, event preflight occurs before the request/query and terminal append occurs before successful stdout. If terminal append fails after a network read, return exit `1` and suppress success output because no local mutation completed. For archive/draft mutations, terminal event failure after commit returns exit `23` with the closed degraded outcome; do not claim rollback or silently repeat the mutation.
7. Read/search/archive/draft completion and post intent/uncertain/verified transitions are deterministic and use the fixed stdout/stderr/exit contract from Task 6.
8. Keep the existing monitor safety contract byte-for-byte stable. Publish write/read/archive/event capabilities only in a separate `client-contract` command whose semantics do not redefine `writes_exposed: false` for the safety gate.

### Task 8: Create the brand system and use-case-first documentation

**Objective:** Make the product memorable, professional, and immediately understandable.

**Prerequisite:** The user has explicitly approved the final name, tagline, CLI, palette, and visual direction. Otherwise present alternatives and keep this task blocked.

**Files:**
- Create: `docs/BRAND.md`
- Create: `docs/assets/relay-mark.svg`
- Create: `docs/assets/relay-workflow.svg`
- Create: `docs/assets/relay-use-cases.svg`
- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `examples/agent-workflows/*.md`
- Modify: `pyproject.toml` description
- Test: package/docs tests as appropriate

**Artifact scope:** Brand SVGs and `docs/BRAND.md` are repository and sdist assets, not wheel runtime assets. The wheel allowlist remains the Python package plus deliberately force-included workflow resources. The sdist allowlist includes source, tests, top-level documentation, approved `docs/` assets/brand guide, and workflow examples, while excluding `docs/plans`, `.github`, build output, and runtime/private files.

**Working visual direction:**

- Motif: a glowing baton/message capsule moving between guarded nodes.
- Palette: midnight navy, electric cyan, signal lime, approval amber.
- Motion language: noisy room pulses become a clear route, pause at an approval checkpoint, then continue as a verified send.
- Voice: capability first; use `inspect`, `search`, `draft`, `review`, `approve`, and `send`.
- Avoid jargon such as “untrusted-content boundary.” Prefer “reviewable context,” “clear limits,” “visible decisions,” “bounded actions,” and “you approve the send.”

**README hero requirements:**

1. Lead with the concrete user problem and the product promise.
2. Show the five-minute path: `read`, archive, `search`, `reply draft`, `reply send --submit`, and `check` for agent-safe decisions.
3. Include a “Why people use it” section covering human CLI use, agent workflows, local history, reviewable replies, and portable events.
4. Include a loud comparison between raw room ingestion and the content-free safety gate.
5. State limitations without weakening the product pitch.
6. Use static self-contained SVGs with no scripts, external links, or remote assets; parse, render, and visually inspect them.
7. Update host recipes for Hermes, OpenClaw, Claude Code, Codex, cron, dashboards, and Telegram alert bridges.

### Task 9: Full integration, security, and package verification

**Objective:** Prove the expanded client works as one coherent release without weakening the reviewed safety component.

**Steps:**

1. Run every focused module test normally and under `python -O`.
2. Run the complete suite normally and under `python -O`; all existing 169 tests plus new tests must pass.
3. Run compile, diff, and Markdown checks.
4. Run independent spec review, then quality/security review, then final integration review; fix and re-review every actionable finding.
5. Build exact wheel and sdist from the final source.
6. Audit exact wheel and sdist allowlists—not only forbidden substrings. Require brand assets/guide in the repository and sdist but absent from the runtime wheel; reject `.github/`, `docs/plans`, state databases, SQLite journals, event logs, drafts, identities, nonces, receipts, caches, and private runtime paths.
7. Install the exact wheel in a clean environment and smoke-test both executables, compatibility aliases, `contract`, `client-contract`, mocked `read`, local archive/search, draft/dry-run send, mocked verified send, events, and `check`.
8. Ensure no test makes a live Technocore write.

### Task 10: Publication gate

**Objective:** Publish only after explicit authorization and exact public readback.

**Steps:**

1. Present the final brand, diff scope, test totals, artifact audit, and review verdicts.
2. Request explicit authorization to commit and push the reviewed files.
3. Exclude pre-existing `.github/`, build products, plans if required by release scope, and all runtime/private state.
4. Commit with a reviewed descriptive message.
5. Push only the inspected feature branch and update PR #1.
6. Verify remote SHA, public file list, README/visual assets, representative source/tests, and absence of forbidden paths.
7. Report GitHub checks honestly; do not claim CI if none is configured.
8. Do not merge, tag, release to PyPI, announce, or post to X without separate authorization.

## Rollback and compatibility

- Removing the new console alias restores the previous executable without changing distribution/import identity.
- New archive, draft, event, and pending-operation files are opt-in and use independent version-1 schemas. Deleting an archive/draft/event file does not alter monitor cursor, identity, nonce, or receipt state; a pending-operation file must not be deleted until its possibly public outcome is reconciled.
- Existing `technocore-sentinel`, `agent-check`, `monitor`, `contract`, identity files, monitor state, nonce state, and receipt state require no migration.
- General reply sending reuses but does not replace the `introduce` command.
- Any refactor of the signed transaction must preserve golden compatibility tests before old code is removed.
